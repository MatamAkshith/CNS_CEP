import json
import os
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer

import http_server


class TestHTTPServer(unittest.TestCase):

    temp_dir = None
    test_file = None
    server = None
    thread = None

    @classmethod
    def setUpClass(cls):

        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_file = os.path.join(
            cls.temp_dir.name,
            "test_http_alerts.json"
        )

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
        if cls.temp_dir:
            cls.temp_dir.cleanup()
        http_server.storage_manager = http_server.StorageManager()


    def get_raw(self, path):

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
        headers = dict(response.getheaders())

        connection.close()

        return response.status, body, headers

    def get(self, path):

        status, body, _ = self.get_raw(path)

        return status, json.loads(body)

    def test_root_dashboard(self):

        status, body, headers = self.get_raw("/")

        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("<!DOCTYPE html>", body)
        self.assertIn("Network Security Monitor", body)

    def test_root_query_parameter(self):

        status, data = self.get("/?foo=bar")

        self.assertEqual(status, 400)
        self.assertEqual(
            data["error"],
            "Query parameters are not supported for /"
        )

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

    def test_capture_status_endpoint(self):

        status, data = self.get("/capture_status")

        self.assertEqual(status, 200)
        self.assertIn("status", data)
        self.assertIn("is_active", data)
        self.assertIn("total_packets", data)
        self.assertIn("recent_packets", data)

    def test_packets_endpoint(self):

        status, data = self.get("/packets")

        self.assertEqual(status, 200)
        self.assertIsInstance(data, list)

    def test_capture_status_query_parameter(self):

        status, data = self.get("/capture_status?foo=bar")

        self.assertEqual(status, 400)
        self.assertEqual(
            data["error"],
            "Query parameters are not supported for /capture_status"
        )

    def test_packets_query_parameter(self):

        status, data = self.get("/packets?foo=bar")

        self.assertEqual(status, 400)
        self.assertEqual(
            data["error"],
            "Query parameters are not supported for /packets"
        )

    def test_dashboard_root_endpoint(self):

        connection = HTTPConnection("localhost", 8001)
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        connection.close()

        self.assertEqual(response.status, 200)
        self.assertIn("<!DOCTYPE html>", body)
        self.assertIn("Network Security Monitor", body)


if __name__ == "__main__":
    unittest.main()