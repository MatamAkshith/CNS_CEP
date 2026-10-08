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

    def do_GET(self):

        try:

            parsed_url = urlparse(self.path)

            path = parsed_url.path
            query = parse_qs(parsed_url.query)

            if path == "/alerts":

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
                            "error": "Query parameters are not supported for /statistics"
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

    server_address = ("localhost", 8000)

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