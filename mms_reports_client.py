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


class MMSReportsClient:
    """Client minimal pour s'abonner à des reports MMS sur un IED IEC 61850.

    Cette implémentation ne gère que:
      - l'établissement de la connexion TPKT/COTP,
      - l'envoi d'un InitiateRequest MMS,
      - l'activation des reports sur un RCB donné (SetRCBValues),
      - la boucle de réception de Reports.
    """

    def __init__(self, host: str, port: int = 102, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None

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
            cotp_connect(sock, timeout=self._timeout)
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

        cotp_send_data(sock, initiate_pdu)

        # On attend la réponse à l'initiate (optionnellement on pourrait la décoder)
        resp = cotp_recv_data(sock, timeout=self._timeout)
        if resp is None:
            self.close()
            raise MMSConnectionError("Connexion fermée pendant le MMS InitiateResponse.")

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
            cotp_send_data(self._sock, get_pdu)
            _ = cotp_recv_data(self._sock, timeout=self._timeout)

        set_pdus = encode_mms_set_rcb(
            domain_id,
            item_id,
            rpt_ena=rpt_ena,
            intg_pd_ms=intg_pd_ms,
        )
        for pdu in set_pdus:
            cotp_send_data(self._sock, pdu)
            _ = cotp_recv_data(self._sock, timeout=self._timeout)

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
                break
            try:
                decoded = decode_mms_pdu(pdu)
            except NotImplementedError as e:
                raise MMSConnectionError(
                    "decode_mms_pdu n'est pas implémenté. "
                    "Branchez asn1_codec sur une implémentation ASN.1 réelle."
                ) from e

            if isinstance(decoded, MMSReport):
                callback(decoded)
            # Pour d'autres types de PDUs, on pourrait ajouter un dispatch ici.

