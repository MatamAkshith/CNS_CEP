from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.parse import urlparse, parse_qs

from storage_manager import StorageManager
from statistics_manager import StatisticsManager


storage_manager = StorageManager()


class RequestHandler(BaseHTTPRequestHandler):

    def send_json_response(self, status_code, data):
        response = json.dumps(data).encode("utf-8")

        self.send_response(status_code)
        self.send_header(
            "Content-Type",
            "application/json"
        )
        self.send_header(
            "Content-Length",
            str(len(response))
        )
        self.end_headers()

        self.wfile.write(response)

    def send_html_response(self, status_code, html):
        response = html.encode("utf-8")

        self.send_response(status_code)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.send_header(
            "Content-Length",
            str(len(response))
        )
        self.end_headers()

        self.wfile.write(response)

    def generate_dashboard(self):
        alerts = storage_manager.load_alerts()

        statistics_manager = StatisticsManager()

        for alert in alerts:
            statistics_manager.process(alert)

        summary = statistics_manager.get_summary()

        total_alerts = summary["total_alerts"]
        alerts_by_type = summary["alerts_by_type"]
        top_source = summary["top_source"]
        top_alert_type = summary["top_alert_type"]

        if top_source:
            top_source_text = (
                f"{top_source['source_ip']} "
                f"({top_source['count']} alerts)"
            )
        else:
            top_source_text = "None"

        if top_alert_type:
            top_alert_text = (
                f"{top_alert_type['type']} "
                f"({top_alert_type['count']} alerts)"
            )
        else:
            top_alert_text = "None"

        alert_type_rows = ""

        for alert_type, count in alerts_by_type.items():
            alert_type_rows += f"""
                <tr>
                    <td>{alert_type}</td>
                    <td>{count}</td>
                </tr>
            """

        recent_alerts = alerts[-10:]
        recent_alerts.reverse()

        recent_alert_rows = ""

        for alert in recent_alerts:
            recent_alert_rows += f"""
                <tr>
                    <td>{alert.get('type', 'Unknown')}</td>
                    <td>{alert.get('source_ip', 'Unknown')}</td>
                    <td>{alert.get('destination_ip', 'N/A')}</td>
                </tr>
            """

        if not alert_type_rows:
            alert_type_rows = """
                <tr>
                    <td colspan="2">No alerts recorded</td>
                </tr>
            """

        if not recent_alert_rows:
            recent_alert_rows = """
                <tr>
                    <td colspan="3">No alerts recorded</td>
                </tr>
            """

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Network Security Monitor</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 30px;
            background: #f4f6f8;
        }}

        h1 {{
            margin-bottom: 30px;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }}

        .card h3 {{
            margin-top: 0;
            color: #555;
        }}

        .value {{
            font-size: 24px;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-bottom: 30px;
        }}

        th,
        td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}

        th {{
            background: #eeeeee;
        }}

        .section {{
            margin-bottom: 30px;
        }}
    </style>
</head>

<body>

    <h1>Network Security Monitor</h1>

    <div class="cards">

        <div class="card">
            <h3>Total Alerts</h3>
            <div class="value">
                {total_alerts}
            </div>
        </div>

        <div class="card">
            <h3>Top Source</h3>
            <div class="value">
                {top_source_text}
            </div>
        </div>

        <div class="card">
            <h3>Top Alert Type</h3>
            <div class="value">
                {top_alert_text}
            </div>
        </div>

    </div>


    <div class="section">

        <h2>Alerts by Type</h2>

        <table>

            <tr>
                <th>Alert Type</th>
                <th>Count</th>
            </tr>

            {alert_type_rows}

        </table>

    </div>


    <div class="section">

        <h2>Recent Alerts</h2>

        <table>

            <tr>
                <th>Alert Type</th>
                <th>Source IP</th>
                <th>Destination IP</th>
            </tr>

            {recent_alert_rows}

        </table>

    </div>

</body>
</html>
"""

        return html

    def do_GET(self):

        try:

            parsed_url = urlparse(self.path)

            path = parsed_url.path
            query = parse_qs(parsed_url.query)

            if path == "/":

                if query:
                    self.send_json_response(
                        400,
                        {
                            "error": "Query parameters are not supported for /"
                        }
                    )
                    return

                html = self.generate_dashboard()

                self.send_html_response(
                    200,
                    html
                )

            elif path == "/alerts":

                allowed_parameters = {
                    "type",
                    "source_ip"
                }

                unsupported_parameters = set(query) - allowed_parameters

                if unsupported_parameters:

                    self.send_json_response(
                        400,
                        {
                            "error": "Unsupported query parameter",
                            "parameters": sorted(
                                unsupported_parameters
                            )
                        }
                    )

                    return

                alerts = storage_manager.load_alerts()

                if "type" in query:

                    alert_type = query["type"][0]

                    alerts = [
                        alert
                        for alert in alerts
                        if alert.get("type") == alert_type
                    ]

                if "source_ip" in query:

                    source_ip = query["source_ip"][0]

                    alerts = [
                        alert
                        for alert in alerts
                        if alert.get("source_ip") == source_ip
                    ]

                self.send_json_response(
                    200,
                    alerts
                )

            elif path == "/statistics":

                if query:

                    self.send_json_response(
                        400,
                        {
                            "error":
                            "Query parameters are not supported for /statistics"
                        }
                    )

                    return

                alerts = storage_manager.load_alerts()

                statistics_manager = StatisticsManager()

                for alert in alerts:
                    statistics_manager.process(alert)

                summary = statistics_manager.get_summary()

                self.send_json_response(
                    200,
                    summary
                )

            else:

                self.send_json_response(
                    404,
                    {
                        "error": "Endpoint not found"
                    }
                )

        except Exception:

            self.send_json_response(
                500,
                {
                    "error": "Internal server error"
                }
            )


if __name__ == "__main__":

    server_address = (
        "localhost",
        8000
    )

    server = HTTPServer(
        server_address,
        RequestHandler
    )

    print(
        "HTTP server running on "
        "http://localhost:8000"
    )

    print("Press Ctrl+C to stop.")

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("\nHTTP server stopped.")

        server.server_close()