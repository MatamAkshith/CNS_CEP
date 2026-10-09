import threading
from detection_engine import DetectionEngine
from alert_manager import AlertManager
from statistics_manager import StatisticsManager
from storage_manager import StorageManager
from capture_state import capture_state_manager
from scapy.all import sniff
from packet_parser import parse_packet


# Initialize application components
storage_manager = StorageManager()
detection_engine = DetectionEngine()
alert_manager = AlertManager(storage_manager.load_alerts())
statistics_manager = StatisticsManager()


def packet_callback(packet):
    parsed_packet = parse_packet(packet)

    capture_state_manager.record_packet(parsed_packet)

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


def _heartbeat_loop(stop_event):
    while not stop_event.is_set():
        capture_state_manager.touch_heartbeat()
        stop_event.wait(1.5)


def main():
    print("Starting live packet capture...")
    print("Press Ctrl+C to stop.")

    capture_state_manager.start_capture()
    stop_event = threading.Event()
    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(stop_event,),
        daemon=True
    )
    heartbeat_thread.start()

    try:
        sniff(prn=packet_callback)
    except KeyboardInterrupt:
        print("\nPacket capture stopped cleanly.")
        capture_state_manager.stop_capture()
    except Exception as e:
        print(f"\nPacket capture error: {e}")
        capture_state_manager.fail_capture(str(e))
        raise
    finally:
        stop_event.set()
        capture_state_manager.stop_capture()


if __name__ == "__main__":
    main()