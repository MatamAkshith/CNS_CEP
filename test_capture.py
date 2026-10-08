from detection_engine import DetectionEngine
from alert_manager import AlertManager
from statistics_manager import StatisticsManager
from storage_manager import StorageManager
from scapy.all import sniff
from packet_parser import parse_packet


detection_engine = DetectionEngine()
alert_manager = AlertManager()
statistics_manager = StatisticsManager()
storage_manager = StorageManager()


def packet_callback(packet):

    parsed_packet = parse_packet(packet)

    alerts = detection_engine.analyze(parsed_packet)

    for alert in alerts:

        processed_alert = alert_manager.process(alert)

        if processed_alert:

            statistics_manager.process(processed_alert)

            storage_manager.save_alert(processed_alert)

            print(alert_manager.format_alert(processed_alert))

    print("\n==============================")
    print(f"Timestamp: {parsed_packet['timestamp']}")
    print(f"IP Version: {parsed_packet['ip_version']}")
    print(f"Source: {parsed_packet['source_ip']}")
    print(f"Destination: {parsed_packet['destination_ip']}")
    print(f"Protocol: {parsed_packet['protocol']}")
    print(f"Source Port: {parsed_packet['source_port']}")
    print(f"Destination Port: {parsed_packet['destination_port']}")
    print(f"Length: {parsed_packet['length']}")
    print(f"TCP Flags: {parsed_packet['tcp_flags']}")


if __name__ == "__main__":
    print("Starting live packet capture...")
    print("Press Ctrl+C to stop.")

    try:
        sniff(prn=packet_callback)
    except KeyboardInterrupt:
        print("\nPacket capture stopped cleanly.")