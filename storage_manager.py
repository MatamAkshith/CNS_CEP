import json
import os


class StorageManager:

    def __init__(self, file_path="alerts.json"):
        self.file_path = file_path

        self._initialize_storage()

    def _initialize_storage(self):

        if not os.path.exists(self.file_path):

            with open(self.file_path, "w") as file:
                json.dump([], file)

    def load_alerts(self):

        with open(self.file_path, "r") as file:
            return json.load(file)

    def save_alerts(self, alerts):

        with open(self.file_path, "w") as file:
            json.dump(alerts, file, indent=4)

    def save_alert(self, alert):

        alerts = self.load_alerts()

        alerts.append(alert)

        self.save_alerts(alerts)