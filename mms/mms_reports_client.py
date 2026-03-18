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
import time
from typing import Callable, Optional

HEARTBEAT_INTERVAL = 60.0  # secondes entre deux messages "en attente"

from .cotp import cotp_connect, cotp_send_data, cotp_recv_data, COTPError
from .tpkt import TPKTError
from .asn1_codec import (
    encode_mms_initiate,
    encode_mms_get_rcb,
    encode_mms_get_name_list,
    encode_mms_set_rcb,
    decode_mms_pdu,
    decode_mms_get_name_list_response,
    is_read_response_success,
    MMSReport,
    reset_invoke_id,
)


class MMSConnectionError(RuntimeError):
    """Erreur de connexion ou d'initialisation MMS."""


ReportCallback = Callable[[MMSReport], None]


def _is_information_report(report: MMSReport) -> bool:
    """True si le PDU est un vrai informationReport (pas le fallback raw_hex)."""
    if not report.entries or len(report.entries) != 1:
        return True
    e = report.entries[0]
    return not (isinstance(e, dict) and "raw_hex" in e)


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

    def _recv_until_response(self, report_callback: Optional[ReportCallback] = None) -> Optional[bytes]:
        """Reçoit un PDU ; si c'est un Report, appelle le callback et réessaie jusqu'à avoir la réponse Get/Set.
        Retourne le PDU brut de la réponse confirmée, ou None si connexion fermée."""
        while True:
            resp = cotp_recv_data(self._sock, timeout=self._timeout)
            if resp is None:
                return None
            try:
                decoded = decode_mms_pdu(resp)
            except NotImplementedError:
                return resp
            if isinstance(decoded, MMSReport) and _is_information_report(decoded) and report_callback:
                decoded.raw_pdu = resp
                report_callback(decoded)
                continue
            if self._debug:
                print(f"[DEBUG] <<< réponse ({len(resp)} octets)")
            return resp

    def get_name_list(
        self,
        object_class: int,
        scope_vmd: bool = True,
        domain_id: Optional[str] = None,
    ) -> Optional[tuple[list[str], bool]]:
        """Envoie GetNameList et retourne (liste_de_noms, more_follows) ou None en cas d'échec."""
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")
        pdu = encode_mms_get_name_list(object_class, scope_vmd=scope_vmd, domain_id=domain_id)
        if self._debug:
            print(f"[DEBUG] >>> GetNameList objectClass={object_class} scope_vmd={scope_vmd} domain={domain_id!r}")
            print(f"[DEBUG]     {_hex_debug(pdu)}")
        cotp_send_data(self._sock, pdu)
        resp = self._recv_until_response()
        if resp is None:
            return None
        if self._debug:
            print(f"[DEBUG] <<< GetNameList response ({len(resp)} octets)")
            print(f"[DEBUG]     {_hex_debug(resp)}")
        result = decode_mms_get_name_list_response(resp)
        if self._debug and result:
            print(f"[DEBUG]     → {len(result[0])} noms, moreFollows={result[1]}")
        return result

    def probe_rcb(self, domain_id: str, item_id: str) -> bool:
        """Envoie GetRCBValues et retourne True si le RCB existe (Read-Response), False sinon."""
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")
        pdu = encode_mms_get_rcb(domain_id, item_id)
        cotp_send_data(self._sock, pdu)
        resp = self._recv_until_response()
        if resp is None:
            return False
        return is_read_response_success(resp)

    def enable_reporting(
        self,
        domain_id: str,
        item_id: str,
        *,
        rpt_ena: bool = True,
        intg_pd_ms: int = 2000,
        do_get_first: bool = True,
        report_callback: Optional[ReportCallback] = None,
    ) -> None:
        """Active les reports sur un RCB donné.

        Envoie GetRCBValues puis la séquence complète de SetRCBValues
        (ResvTms, IntgPd, TrgOps, OptFlds, PurgeBuf, EntryID, RptEna, GI).
        Tout Report reçu pendant la phase est transmis à report_callback.
        """
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")

        if do_get_first:
            get_pdu = encode_mms_get_rcb(domain_id, item_id)
            if self._debug:
                print(f"[DEBUG] >>> GetRCBValues {domain_id}/{item_id} ({len(get_pdu)} octets)")
                print(f"[DEBUG]     {_hex_debug(get_pdu)}")
            cotp_send_data(self._sock, get_pdu)
            self._recv_until_response(report_callback)

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
            self._recv_until_response(report_callback)

    def loop_reports(self, callback: ReportCallback, *, quiet_heartbeat: bool = False) -> None:
        """Boucle de réception bloquante qui invoque callback pour chaque Report.

        quiet_heartbeat=True désactive l'affichage périodique
        "  (en attente de reports...)" lorsqu'aucun PDU n'est reçu.
        """
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")

        # Timeout pour éventuellement afficher un message "en attente" périodiquement (heartbeat).
        try:
            self._sock.settimeout(HEARTBEAT_INTERVAL)
        except OSError:
            pass

        while True:
            try:
                pdu = cotp_recv_data(self._sock, timeout=HEARTBEAT_INTERVAL)
            except socket.timeout:
                if not quiet_heartbeat:
                    print("  (en attente de reports...)")
                continue
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

    def send_confirmed_pdu_and_wait(self, pdu: bytes) -> bytes:
        """
        Envoie un MMS confirmed-RequestPDU et attend la première réponse reçue.

        Utilisé pour un MVP : Write/Operate sans décoder le response en détail.
        """
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")
        cotp_send_data(self._sock, pdu)
        resp = self._recv_until_response(report_callback=None)
        if resp is None:
            raise MMSConnectionError("Connexion fermée pendant l'attente de la réponse MMS.")
        return resp

    def send_confirmed_pdu(self, pdu: bytes) -> None:
        """Envoie un confirmed-RequestPDU sans attendre de réponse."""
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")
        cotp_send_data(self._sock, pdu)

    def recv_next_tpdu(self, *, timeout: float = 1.0) -> Optional[bytes]:
        """Lit la prochaine TPDU DT et retourne le payload user_data (MMS)."""
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")
        try:
            return cotp_recv_data(self._sock, timeout=timeout)
        except socket.timeout:
            # Pas de donnée dans le délai : on signale "rien reçu"
            return None

    def recv_until_contains(
        self,
        *,
        substrings: tuple[bytes, ...],
        timeout_total: float = 3.0,
        per_read_timeout: float = 0.5,
        stop_on_first: bool = True,
    ) -> bytes:
        """
        Lit plusieurs réponses jusqu'à ce que :
          - un des `substrings` apparaisse dans un payload brut,
          - ou que `timeout_total` expire.
        Retourne la dernière réponse lue (ou lève si aucune).
        """
        end_ts = time.time() + timeout_total
        last_resp: Optional[bytes] = None
        last_match_resp: Optional[bytes] = None
        while time.time() < end_ts:
            try:
                resp = self.recv_next_tpdu(timeout=per_read_timeout)
            except socket.timeout:
                # Pas de nouvelle TPDU pour l'instant : on retente jusqu'au
                # timeout_total global.
                continue
            if resp is None:
                break
            last_resp = resp
            if any(s in resp for s in substrings):
                if stop_on_first:
                    return resp
                # Sinon on continue jusqu'au timeout_total : on conserve la
                # dernière réponse qui *match* le critère (ex: LastApplError),
                # pour éviter de perdre l'erreur si un ACK court arrive ensuite.
                last_match_resp = resp
        if last_resp is None:
            raise MMSConnectionError("Connexion fermée pendant l'attente de la réponse MMS.")
        return last_match_resp if last_match_resp is not None else last_resp

    def send_confirmed_pdu_and_wait_for_control_response(
        self,
        pdu: bytes,
        *,
        expected_substrings: tuple[bytes, ...] = (),
        timeout_total: float = 3.0,
    ) -> bytes:
        """
        Envoie un confirmed-RequestPDU et attend une réponse "utile".

        Dans certains cas, un IED peut envoyer une réponse de confirmation courte
        avant l'éventuel contenu applicatif (ex: controlLastApplError).
        Cette méthode lit plusieurs PDUs successives jusqu'à ce que :
          - au moins un des `expected_substrings` soit présent dans le payload brut,
          - ou que `timeout_total` soit dépassé.
        """
        if self._sock is None:
            raise MMSConnectionError("Connexion MMS non établie.")

        cotp_send_data(self._sock, pdu)

        end_ts = time.time() + timeout_total
        last_resp: Optional[bytes] = None
        # On attend au moins une réponse
        while time.time() < end_ts:
            # timeout par lecture, pour éviter de bloquer trop longtemps
            resp = cotp_recv_data(self._sock, timeout=min(self._timeout, 1.0))
            if resp is None:
                break
            last_resp = resp
            raw = resp
            if b"LastApplError" in raw:
                return resp
            if expected_substrings and any(s in raw for s in expected_substrings):
                return resp
            # sinon on continue jusqu'au timeout_total
        if last_resp is None:
            raise MMSConnectionError("Connexion fermée pendant l'attente de la réponse MMS.")
        return last_resp

