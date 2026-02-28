"""Client MMS minimal orienté "reports" sans dépendance GPL.

Architecture:
  - TCP / socket standard
  - TPKT: voir tpkt.send_tpkt / tpkt.recv_tpkt
  - COTP: voir cotp.cotp_connect / cotp_send_data / cotp_recv_data
  - ACSE / MMS: à encoder via asn1_codec (ou, pour un MVP, via des payloads bruts).

Ce module fournit une façade orientée reports qui reste indépendante
de l'implémentation concrète ASN.1/BER.
"""

from __future__ import annotations

import socket
from typing import Callable, Optional

from cotp import cotp_connect, cotp_send_data, cotp_recv_data, COTPError
from tpkt import TPKTError
from asn1_codec import (
    encode_mms_initiate,
    encode_mms_get_rcb,
    encode_mms_set_rcb,
    decode_mms_pdu,
    MMSReport,
    reset_invoke_id,
)


class MMSConnectionError(RuntimeError):
    """Erreur de connexion ou d'initialisation MMS."""


ReportCallback = Callable[[MMSReport], None]


def _hex_debug(data: bytes, max_bytes: int = 128) -> str:
    """Format hex pour debug (tronqué si long)."""
    if len(data) <= max_bytes:
        return data.hex(" ")
    return data[:max_bytes].hex(" ") + f" ... (+{len(data) - max_bytes} octets)"


class MMSReportsClient:
    """Client minimal pour s'abonner à des reports MMS sur un IED IEC 61850.

    Cette implémentation ne gère que:
      - l'établissement de la connexion TPKT/COTP,
      - l'envoi d'un InitiateRequest MMS,
      - l'activation des reports sur un RCB donné (SetRCBValues),
      - la boucle de réception de Reports.
    """

    def __init__(
        self,
        host: str,
        port: int = 102,
        timeout: float = 5.0,
        debug: bool = False,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._debug = debug

    def connect(self) -> None:
        """Ouvre la connexion TCP, établit COTP et envoie MMS Initiate."""
        if self._sock is not None:
            return

        try:
            sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        except OSError as e:
            raise MMSConnectionError(f"Échec connexion TCP vers {self._host}:{self._port}: {e}") from e

        self._sock = sock

        try:
            if self._debug:
                print("[DEBUG] >>> COTP Connection Request (CR)")
            cotp_connect(sock, timeout=self._timeout)
            if self._debug:
                print("[DEBUG] <<< COTP Connection Confirm (CC)")
        except (COTPError, TPKTError, OSError) as e:
            self.close()
            raise MMSConnectionError(f"Échec handshake COTP: {e}") from e

        # MMS Initiate
        try:
            initiate_pdu = encode_mms_initiate()
        except NotImplementedError as e:
            self.close()
            raise MMSConnectionError(
                "encode_mms_initiate n'est pas implémenté. "
                "Branchez asn1_codec sur une implémentation ASN.1 réelle."
            ) from e

        if self._debug:
            print(f"[DEBUG] >>> MMS InitiateRequest ({len(initiate_pdu)} octets)")
            print(f"[DEBUG]     {_hex_debug(initiate_pdu)}")
        cotp_send_data(sock, initiate_pdu)

        # On attend la réponse à l'initiate (optionnellement on pourrait la décoder)
        resp = cotp_recv_data(sock, timeout=self._timeout)
        if resp is None:
            self.close()
            raise MMSConnectionError("Connexion fermée pendant le MMS InitiateResponse.")
        if self._debug:
            print(f"[DEBUG] <<< MMS InitiateResponse ({len(resp)} octets)")
            print(f"[DEBUG]     {_hex_debug(resp)}")

        reset_invoke_id()

    def close(self) -> None:
        """Ferme proprement le socket TCP."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            finally:
                self._sock = None

    def enable_reporting(
        self,
        domain_id: str,
        item_id: str,
        *,
        rpt_ena: bool = True,
        intg_pd_ms: int = 2000,
        do_get_first: bool = True,
    ) -> None:
        """Active les reports sur un RCB donné.

        Envoie GetRCBValues puis la séquence complète de SetRCBValues
        (ResvTms, IntgPd, TrgOps, OptFlds, PurgeBuf, EntryID, RptEna, GI).
        """
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")

        if do_get_first:
            get_pdu = encode_mms_get_rcb(domain_id, item_id)
            if self._debug:
                print(f"[DEBUG] >>> GetRCBValues {domain_id}/{item_id} ({len(get_pdu)} octets)")
                print(f"[DEBUG]     {_hex_debug(get_pdu)}")
            cotp_send_data(self._sock, get_pdu)
            resp = cotp_recv_data(self._sock, timeout=self._timeout)
            if self._debug:
                if resp is not None:
                    print(f"[DEBUG] <<< GetRCBValuesResponse ({len(resp)} octets)")
                    print(f"[DEBUG]     {_hex_debug(resp)}")
                else:
                    print("[DEBUG] <<< (aucune réponse GetRCBValues)")

        set_attrs = (
            "ResvTms", "IntgPd", "TrgOps", "OptFlds",
            "PurgeBuf", "EntryID", "RptEna", "GI",
        )
        set_pdus = encode_mms_set_rcb(
            domain_id,
            item_id,
            rpt_ena=rpt_ena,
            intg_pd_ms=intg_pd_ms,
        )
        for attr, pdu in zip(set_attrs, set_pdus):
            if self._debug:
                print(f"[DEBUG] >>> SetRCBValues ${attr} ({len(pdu)} octets)")
                print(f"[DEBUG]     {_hex_debug(pdu)}")
            cotp_send_data(self._sock, pdu)
            resp = cotp_recv_data(self._sock, timeout=self._timeout)
            if self._debug:
                if resp is not None:
                    print(f"[DEBUG] <<< SetRCBValuesResponse ${attr} ({len(resp)} octets)")
                    print(f"[DEBUG]     {_hex_debug(resp)}")
                else:
                    print(f"[DEBUG] <<< (aucune réponse SetRCBValues ${attr})")

    def loop_reports(self, callback: ReportCallback) -> None:
        """Boucle de réception bloquante qui invoque callback pour chaque Report."""
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")

        # En phase "subscriber", on attend indéfiniment des reports.
        # On désactive donc le timeout réseau du socket.
        try:
            self._sock.settimeout(None)
        except OSError:
            pass

        while True:
            pdu = cotp_recv_data(self._sock)
            if pdu is None:
                if self._debug:
                    print("[DEBUG] <<< connexion fermée (fin de flux)")
                break
            if self._debug:
                print(f"[DEBUG] <<< PDU reçu ({len(pdu)} octets)")
                print(f"[DEBUG]     {_hex_debug(pdu)}")
            try:
                decoded = decode_mms_pdu(pdu)
            except NotImplementedError as e:
                raise MMSConnectionError(
                    "decode_mms_pdu n'est pas implémenté. "
                    "Branchez asn1_codec sur une implémentation ASN.1 réelle."
                ) from e

            if isinstance(decoded, MMSReport):
                decoded.raw_pdu = pdu
                callback(decoded)
            # Pour d'autres types de PDUs, on pourrait ajouter un dispatch ici.

