class StatisticsManager:

    def __init__(self):
        self.alerts = []

    def process(self, alert):

        if alert is None:
            return

        self.alerts.append(alert)

    def get_total_alerts(self):

        return len(self.alerts)

    def get_alerts_by_type(self):

        statistics = {}

        for alert in self.alerts:

            alert_type = alert.get("type")

            if alert_type not in statistics:
                statistics[alert_type] = 0

            statistics[alert_type] += 1

        return statistics

    def get_alerts_by_source(self):

        statistics = {}

        for alert in self.alerts:

            source_ip = alert.get("source_ip")

            if source_ip not in statistics:
                statistics[source_ip] = 0

            statistics[source_ip] += 1

        return statistics

    def get_top_source(self):

        if not self.alerts:
            return None

        statistics = self.get_alerts_by_source()

        top_source = max(
            statistics,
            key=statistics.get
        )

        return {
            "source_ip": top_source,
            "count": statistics[top_source]
        }

    def get_top_alert_type(self):

        if not self.alerts:
            return None

        statistics = self.get_alerts_by_type()

        top_type = max(
            statistics,
            key=statistics.get
        )

        return {
            "type": top_type,
            "count": statistics[top_type]
        }

    def get_summary(self):

        return {
            "total_alerts": self.get_total_alerts(),
            "alerts_by_type": self.get_alerts_by_type(),
            "alerts_by_source": self.get_alerts_by_source(),
            "top_source": self.get_top_source(),
            "top_alert_type": self.get_top_alert_type()
        }