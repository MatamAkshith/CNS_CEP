class AlertManager:

    def __init__(self):
        self.alerts = []

    def process(self, alert):

        if alert is None:
            return None

        for existing_alert in self.alerts:
            if (
                existing_alert.get("type") == alert.get("type")
                and existing_alert.get("source_ip") == alert.get("source_ip")
            ):
                return None

        self.alerts.append(alert)

        return alert

    def get_alerts(self):
        return self.alerts

    def format_alert(self, alert):

        if alert is None:
            return None

        alert_type = alert.get("type")
        source_ip = alert.get("source_ip")

        message = (
            "🚨 SECURITY ALERT\n"
            f"Type: {alert_type}\n"
            f"Source IP: {source_ip}"
        )

        if "destination_ip" in alert:
            message += f"\nDestination IP: {alert.get('destination_ip')}"

        if "ports_scanned" in alert:
            message += f"\nPorts Scanned: {alert.get('ports_scanned')}"

        if "syn_count" in alert:
            message += f"\nSYN Count: {alert.get('syn_count')}"

        if "window" in alert:
            message += f"\nTime Window: {alert.get('window')} seconds"

        return message