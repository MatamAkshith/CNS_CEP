import json
import os
import threading
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer

import http_server


class TestHTTPServer(unittest.TestCase):

    test_file = "test_http_alerts.json"
    server = None
    thread = None

    @classmethod
    def setUpClass(cls):

        test_alerts = [
            {
                "type": "Possible TCP SYN Port Scan",
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.10",
                "ports_scanned": [22, 23, 80, 443, 8080],
                "window": 10
            },
            {
                "type": "Possible TCP SYN Flood",
                "source_ip": "192.168.1.60",
                "syn_count": 20,
                "window": 5
            },
            {
                "type": "Possible TCP SYN Flood",
                "source_ip": "192.168.1.50",
                "syn_count": 20,
                "window": 5
            }
        ]

        with open(cls.test_file, "w") as file:
            json.dump(test_alerts, file, indent=4)

        http_server.storage_manager = (
            http_server.StorageManager(cls.test_file)
        )

        cls.server = HTTPServer(
            ("localhost", 8001),
            http_server.RequestHandler
        )

        cls.thread = threading.Thread(
            target=cls.server.serve_forever
        )

        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):

        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

        if os.path.exists(cls.test_file):
            os.remove(cls.test_file)

    def get(self, path):

        connection = HTTPConnection(
            "localhost",
            8001
        )

        connection.request(
            "GET",
            path
        )

        response = connection.getresponse()

        body = response.read().decode("utf-8")

        connection.close()

        return response.status, json.loads(body)

    def test_get_all_alerts(self):

        status, data = self.get("/alerts")

        self.assertEqual(status, 200)
        self.assertEqual(len(data), 3)

    def test_filter_by_type(self):

        status, data = self.get(
            "/alerts?type=Possible%20TCP%20SYN%20Flood"
        )

        self.assertEqual(status, 200)
        self.assertEqual(len(data), 2)

    def test_filter_by_source_ip(self):

        status, data = self.get(
            "/alerts?source_ip=192.168.1.50"
        )

        self.assertEqual(status, 200)
        self.assertEqual(len(data), 2)

    def test_combined_filter(self):

        status, data = self.get(
            "/alerts?"
            "type=Possible%20TCP%20SYN%20Flood"
            "&source_ip=192.168.1.50"
        )

        self.assertEqual(status, 200)
        self.assertEqual(len(data), 1)

    def test_statistics(self):

        status, data = self.get("/statistics")

        self.assertEqual(status, 200)
        self.assertEqual(data["total_alerts"], 3)
        self.assertEqual(
            data["alerts_by_type"]["Possible TCP SYN Flood"],
            2
        )
        self.assertEqual(
            data["alerts_by_source"]["192.168.1.50"],
            2
        )

    def test_unknown_endpoint(self):

        status, data = self.get("/unknown")

        self.assertEqual(status, 404)
        self.assertEqual(
            data["error"],
            "Endpoint not found"
        )

    def test_unsupported_query_parameter(self):

        status, data = self.get(
            "/alerts?foo=bar"
        )

        self.assertEqual(status, 400)
        self.assertEqual(
            data["error"],
            "Unsupported query parameter"
        )

    def test_statistics_query_parameter(self):

        status, data = self.get(
            "/statistics?foo=bar"
        )

        self.assertEqual(status, 400)
        self.assertEqual(
            data["error"],
            "Query parameters are not supported for /statistics"
        )


if __name__ == "__main__":
    unittest.main()