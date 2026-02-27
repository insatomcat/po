from mms_reports_client import MMSReportsClient
from asn1_codec import MMSReport  # juste pour le type

IED_IP = "10.132.159.191"
IED_PORT = 102
DOMAIN_ID = "VMC7_1LD0"
ITEM_ID = "LLN0$BR$CB_LDPHAS1_CYPO02"  # RCB de la trace qui marche

def on_report(report: MMSReport) -> None:
    print("REPORT reçu :")
    print(f"  RCB    : {report.rcb_reference}")
    print(f"  RptId  : {report.rpt_id}")
    print(f"  DataSet: {report.data_set_name}")
    print(f"  SeqNum : {report.seq_num}")
    if report.entries:
        for i, e in enumerate(report.entries):
            print(f"    [{i}] {e}")

def main() -> None:
    client = MMSReportsClient(IED_IP, IED_PORT)
    client.connect()
    client.enable_reporting(DOMAIN_ID, ITEM_ID)
    print("En attente de reports...")
    client.loop_reports(on_report)

if __name__ == "__main__":
    main()