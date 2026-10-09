from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import traceback
import time
from urllib.parse import urlparse, parse_qs
from html import escape

from storage_manager import StorageManager
from statistics_manager import StatisticsManager
from capture_state import capture_state_manager


storage_manager = StorageManager()


class RequestHandler(BaseHTTPRequestHandler):

    def send_json_response(self, status_code, data):
        response = json.dumps(data).encode("utf-8")

        self.send_response(status_code)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
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

        initial_capture_state = capture_state_manager.get_state()
        initial_status = initial_capture_state["status"]
        initial_status_upper = initial_status.upper()
        initial_total_packets = initial_capture_state["total_packets"]
        initial_last_packet = initial_capture_state["last_packet_time"] or "None"
        initial_duration = initial_capture_state["duration_seconds"]

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
            pct = (count / total_alerts * 100) if total_alerts > 0 else 0
            pct_str = f"{pct:.1f}%"
            alert_type_rows += f"""
                <tr>
                    <td><span class="alert-badge">{escape(str(alert_type))}</span></td>
                    <td class="mono-val">{count}</td>
                    <td>
                        <div class="dist-bar-wrapper">
                            <div class="dist-bar-track">
                                <div class="dist-bar-fill" style="width: {pct_str};"></div>
                            </div>
                            <span class="dist-percent">{pct_str}</span>
                        </div>
                    </td>
                </tr>
            """

        recent_alert_rows = ""
        recent_alerts = list(reversed(alerts))[:10]

        for alert in recent_alerts:
            raw_ts = alert.get("timestamp")
            if raw_ts is not None:
                try:
                    val = float(raw_ts)
                    timestamp = escape(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(val)))
                except (ValueError, TypeError):
                    timestamp = escape(str(raw_ts))
            else:
                timestamp = "N/A"

            alert_type = escape(str(alert.get("type", "Unknown")))
            source_ip = escape(str(alert.get("source_ip", "Unknown")))
            destination_ip = escape(str(alert.get("destination_ip", "N/A")))
            
            # Format detail summary based on alert type
            if "ports_scanned" in alert:
                detail = f"Ports: {alert['ports_scanned']}"
            elif "syn_count" in alert:
                detail = f"SYN count: {alert['syn_count']}"
            elif "target_hosts" in alert:
                detail = f"Hosts: {len(alert['target_hosts'])}"
            else:
                detail = "-"
            detail = escape(detail)

            recent_alert_rows += f"""
                <tr>
                    <td class="mono-val">{timestamp}</td>
                    <td><span class="alert-badge">{alert_type}</span></td>
                    <td class="mono-val">{source_ip}</td>
                    <td class="mono-val">{destination_ip}</td>
                    <td class="mono-val">{detail}</td>
                </tr>
            """


        if not alert_type_rows:
            alert_type_rows = """
                <tr>
                    <td colspan="3" class="empty-state">No alerts recorded</td>
                </tr>
            """

        if not recent_alert_rows:
            recent_alert_rows = """
                <tr>
                    <td colspan="5" class="empty-state">No security alerts recorded</td>
                </tr>
            """

        initial_dot_class = "stopped"
        if initial_status == "active":
            initial_dot_class = "active"
        elif initial_status in ("starting", "waiting"):
            initial_dot_class = "offline"
        elif initial_status == "error":
            initial_dot_class = "error"

        html = f"""<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Network Security Monitor</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Orbitron:wght@600;700;800&display=swap" rel="stylesheet">

    <style>
        :root {{
            --bg-dark: #090d16;
            --bg-card: #111827;
            --bg-input: #1e293b;
            --border-color: #1e293b;
            --border-muted: rgba(255, 255, 255, 0.06);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-subtle: #64748b;
            --cyan-accent: #06b6d4;
            --cyan-subtle: rgba(6, 182, 212, 0.12);
            --teal-accent: #14b8a6;
            --status-green: #10b981;
            --status-red: #f43f5e;
            --status-amber: #f59e0b;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            background-color: var(--bg-dark);
            color: var(--text-main);
            min-height: 100vh;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px 24px;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border-color);
        }}

        .header-title-group {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        h1 {{
            font-family: 'Orbitron', sans-serif;
            font-size: 24px;
            font-weight: 700;
            letter-spacing: 0.04em;
            color: var(--text-main);
            margin: 0;
            text-transform: uppercase;
        }}

        .header-subtitle {{
            font-size: 13px;
            color: var(--text-subtle);
            font-weight: 500;
        }}

        .badge-group {{
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }}

        .status-badge {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 500;
        }}

        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--text-subtle);
            transition: all 0.2s ease;
        }}

        .status-dot.active {{
            background-color: var(--status-green);
            box-shadow: 0 0 8px var(--status-green);
        }}

        .status-dot.stopped {{
            background-color: var(--text-subtle);
            box-shadow: none;
        }}

        .status-dot.error {{
            background-color: var(--status-red);
            box-shadow: 0 0 8px var(--status-red);
        }}

        .status-dot.offline {{
            background-color: var(--status-amber);
            box-shadow: 0 0 8px var(--status-amber);
        }}

        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}

        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--cyan-accent);
            border-radius: 10px;
            padding: 18px 20px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }}

        .card h3 {{
            font-family: 'Inter', sans-serif;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            margin: 0 0 8px 0;
        }}

        .card .value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 20px;
            font-weight: 700;
            color: var(--text-main);
            overflow-wrap: anywhere;
        }}

        .card .value-small {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-main);
            overflow-wrap: anywhere;
        }}

        .card-meta {{
            font-size: 11px;
            color: var(--text-subtle);
            margin-top: 6px;
            font-family: 'JetBrains Mono', monospace;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .section-panel {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 32px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }}

        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        h2 {{
            font-family: 'Orbitron', sans-serif;
            font-size: 15px;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: var(--text-muted);
            margin: 0;
        }}

        .meta-tag {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-subtle);
        }}

        .filter-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            margin-bottom: 20px;
            padding: 12px 16px;
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }}

        .filter-group {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .filter-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-subtle);
        }}

        .filter-input,
        .filter-select {{
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            font-size: 13px;
            padding: 6px 12px;
            border-radius: 6px;
            outline: none;
            transition: border-color 0.15s;
        }}

        .filter-input {{
            font-family: 'JetBrains Mono', monospace;
            width: 180px;
        }}

        .filter-input:focus,
        .filter-select:focus {{
            border-color: var(--cyan-accent);
        }}

        .filter-reset {{
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            font-family: 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 500;
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.15s;
            margin-left: auto;
        }}

        .filter-reset:hover {{
            background: var(--bg-input);
            color: var(--text-main);
        }}

        .table-scroll {{
            width: 100%;
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th {{
            font-family: 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            background: var(--bg-dark);
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
        }}

        td {{
            font-size: 13px;
            color: var(--text-main);
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            overflow-wrap: anywhere;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tbody tr {{
            transition: background 0.15s;
        }}

        tbody tr:hover {{
            background: rgba(255, 255, 255, 0.02);
        }}

        .alert-badge {{
            display: inline-block;
            background: var(--cyan-subtle);
            color: var(--cyan-accent);
            border: 1px solid rgba(6, 182, 212, 0.25);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.02em;
        }}

        .proto-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 600;
        }}

        .proto-tcp {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
        .proto-udp {{ background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }}
        .proto-icmp {{ background: rgba(234, 179, 8, 0.15); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.3); }}
        .proto-other {{ background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.3); }}

        .mono-val {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #e2e8f0;
        }}

        .dist-bar-wrapper {{
            display: flex;
            align-items: center;
            gap: 12px;
            width: 100%;
        }}

        .dist-bar-track {{
            flex: 1;
            height: 8px;
            background: var(--bg-input);
            border-radius: 4px;
            overflow: hidden;
        }}

        .dist-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--teal-accent), var(--cyan-accent));
            border-radius: 4px;
            transition: width 0.3s ease;
        }}

        .dist-percent {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-muted);
            min-width: 45px;
            text-align: right;
        }}

        .empty-state {{
            color: var(--text-subtle);
            font-style: italic;
            text-align: center;
            padding: 24px;
        }}

        .load-more-btn {{
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            font-size: 13px;
            font-weight: 500;
            padding: 8px 20px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.15s;
            margin: 16px auto 0 auto;
            display: block;
        }}

        .load-more-btn:hover {{
            border-color: var(--cyan-accent);
            background: #283548;
        }}

        @media (max-width: 900px) {{
            .cards-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        @media (max-width: 600px) {{
            .container {{
                padding: 16px 12px;
            }}

            header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 16px;
            }}

            .cards-grid {{
                grid-template-columns: 1fr;
            }}

            .filter-bar {{
                flex-direction: column;
                align-items: stretch;
            }}

            .filter-reset {{
                margin-left: 0;
            }}

            table {{
                font-size: 12px;
            }}

            th, td {{
                padding: 8px 10px;
            }}
        }}
    </style>
</head>

<body>

    <div class="container">

        <header>
            <div class="header-title-group">
                <h1>Network Security Monitor</h1>
                <div class="header-subtitle">CNS CEP Security Operations Center</div>
            </div>

            <div class="badge-group">
                <div class="status-badge">
                    <div class="status-dot {initial_dot_class}" id="capture-status-dot"></div>
                    <span id="capture-status-text">Capture {initial_status_upper}</span>
                </div>
                <div class="status-badge">
                    <div class="status-dot" id="status-dot"></div>
                    <span id="dashboard-status">Connecting...</span>
                </div>
            </div>
        </header>

        <div class="cards-grid">

            <div class="card">
                <h3>Capture Status</h3>
                <div class="value" id="capture-status-val">{initial_status_upper}</div>
                <div class="card-meta" id="capture-duration-meta">Duration: {initial_duration}s | Last: {initial_last_packet}</div>
            </div>

            <div class="card">
                <h3>Packets Captured</h3>
                <div class="value" id="total-packets-val">{initial_total_packets}</div>
                <div class="card-meta">Parsed live Scapy packets</div>
            </div>

            <div class="card">
                <h3>Total Alerts</h3>
                <div class="value" id="total-alerts">{total_alerts}</div>
                <div class="card-meta">Deduplicated security events</div>
            </div>

            <div class="card">
                <h3>Top Threat Vector</h3>
                <div class="value-small" id="top-source">{escape(top_source_text)}</div>
                <div class="card-meta" id="top-alert-type">{escape(top_alert_text)}</div>
            </div>

        </div>

        <div class="section-panel">
            <div class="section-header">
                <h2>Live Packet Activity</h2>
                <span class="meta-tag" id="recent-packet-count">0 packets buffered</span>
            </div>

            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Protocol</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Port / Detail</th>
                            <th>Length</th>
                        </tr>
                    </thead>

                    <tbody id="recent-packets-body">
                        <tr>
                            <td colspan="6" class="empty-state">No live packets captured yet</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section-panel">
            <div class="section-header">
                <h2>Alerts by Category</h2>
            </div>

            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th>Alert Type</th>
                            <th>Count</th>
                            <th>Distribution</th>
                        </tr>
                    </thead>

                    <tbody id="alerts-by-type">
                        {alert_type_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section-panel">
            <div class="section-header">
                <h2>Security Incident Log</h2>
                <span class="meta-tag" id="matching-alerts-count">Showing 0 matching alerts</span>
            </div>

            <div class="filter-bar">
                <div class="filter-group">
                    <span class="filter-label">Type:</span>
                    <select id="filter-alert-type" class="filter-select">
                        <option value="">All Types</option>
                    </select>
                </div>

                <div class="filter-group">
                    <span class="filter-label">Source IP:</span>
                    <input type="text" id="filter-source-ip" class="filter-input" placeholder="Filter IP...">
                </div>

                <button id="filter-clear" class="filter-reset">Clear Filters</button>
            </div>

            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Alert Type</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Details</th>
                        </tr>
                    </thead>

                    <tbody id="recent-alerts">
                        {recent_alert_rows}
                    </tbody>
                </table>
            </div>

            <button id="load-more-alerts" class="load-more-btn" style="display: none;">Load More Alerts</button>
        </div>

    </div>

    <script>
        let cachedAlerts = [];
        let cachedStatistics = null;
        let cachedCaptureState = null;
        let cachedPackets = [];
        let displayedAlertLimit = 10;

        function formatTimestamp(ts) {{
            if (ts === null || ts === undefined || ts === "" || ts === "N/A" || ts === "None") {{
                return "N/A";
            }}
            const num = Number(ts);
            if (!isNaN(num) && num > 0) {{
                const ms = num < 10000000000 ? num * 1000 : num;
                const d = new Date(ms);
                if (!isNaN(d.getTime())) {{
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    const hours = String(d.getHours()).padStart(2, '0');
                    const mins = String(d.getMinutes()).padStart(2, '0');
                    const secs = String(d.getSeconds()).padStart(2, '0');
                    return `${{year}}-${{month}}-${{day}} ${{hours}}:${{mins}}:${{secs}}`;
                }}
            }}
            return String(ts);
        }}

        function formatDuration(seconds) {{
            if (!seconds || seconds <= 0) return "0s";
            const hrs = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            if (hrs > 0) return `${{hrs}}h ${{mins}}m ${{secs}}s`;
            if (mins > 0) return `${{mins}}m ${{secs}}s`;
            return `${{secs}}s`;
        }}

        function updateRecentPacketsTable(packets) {{
            const packetsBody = document.getElementById("recent-packets-body");
            const packetCountTag = document.getElementById("recent-packet-count");
            packetsBody.replaceChildren();

            packetCountTag.textContent = `${{packets.length}} packets buffered`;

            if (!packets || packets.length === 0) {{
                const row = document.createElement("tr");
                const cell = document.createElement("td");
                cell.colSpan = 6;
                cell.className = "empty-state";
                cell.textContent = "No live packets captured yet";
                row.appendChild(cell);
                packetsBody.appendChild(row);
                return;
            }}

            const displayPackets = packets.slice().reverse();

            for (const packet of displayPackets) {{
                const row = document.createElement("tr");

                const timeCell = document.createElement("td");
                timeCell.className = "mono-val";
                timeCell.textContent = formatTimestamp(packet.timestamp);

                const protoCell = document.createElement("td");
                const protoBadge = document.createElement("span");
                const proto = (packet.protocol || "Unknown").toUpperCase();
                let protoClass = "proto-other";
                if (proto === "TCP") protoClass = "proto-tcp";
                else if (proto === "UDP") protoClass = "proto-udp";
                else if (proto === "ICMP") protoClass = "proto-icmp";
                protoBadge.className = `proto-badge ${{protoClass}}`;
                protoBadge.textContent = proto;
                protoCell.appendChild(protoBadge);

                const srcCell = document.createElement("td");
                srcCell.className = "mono-val";
                srcCell.textContent = packet.source_ip || "N/A";

                const dstCell = document.createElement("td");
                dstCell.className = "mono-val";
                dstCell.textContent = packet.destination_ip || "N/A";

                const portCell = document.createElement("td");
                portCell.className = "mono-val";
                let portDetail = "-";
                if (packet.source_port !== null && packet.source_port !== undefined && packet.destination_port !== null && packet.destination_port !== undefined) {{
                    portDetail = `${{packet.source_port}} → ${{packet.destination_port}}`;
                }} else if (packet.destination_port !== null && packet.destination_port !== undefined) {{
                    portDetail = `→ ${{packet.destination_port}}`;
                }}
                if (packet.tcp_flags) {{
                    portDetail += ` [${{packet.tcp_flags}}]`;
                }}
                portCell.textContent = portDetail;

                const lenCell = document.createElement("td");
                lenCell.className = "mono-val";
                lenCell.textContent = packet.length !== null && packet.length !== undefined ? `${{packet.length}} B` : "-";

                row.appendChild(timeCell);
                row.appendChild(protoCell);
                row.appendChild(srcCell);
                row.appendChild(dstCell);
                row.appendChild(portCell);
                row.appendChild(lenCell);

                packetsBody.appendChild(row);
            }}
        }}

        function updateRecentAlertsTable() {{
            const recentAlertsBody = document.getElementById("recent-alerts");
            const filterType = document.getElementById("filter-alert-type").value;
            const filterSource = document.getElementById("filter-source-ip").value.trim().toLowerCase();
            const matchingCountTag = document.getElementById("matching-alerts-count");
            const loadMoreBtn = document.getElementById("load-more-alerts");

            recentAlertsBody.replaceChildren();

            let filteredAlerts = cachedAlerts;

            if (filterType) {{
                filteredAlerts = filteredAlerts.filter(a => a.type === filterType);
            }}

            if (filterSource) {{
                filteredAlerts = filteredAlerts.filter(a => (a.source_ip || "").toLowerCase().includes(filterSource));
            }}

            const totalMatching = filteredAlerts.length;
            const sortedAlerts = filteredAlerts.slice().reverse();
            const visibleAlerts = sortedAlerts.slice(0, displayedAlertLimit);

            matchingCountTag.textContent = `Showing ${{visibleAlerts.length}} of ${{totalMatching}} matching alerts`;

            if (totalMatching > displayedAlertLimit) {{
                loadMoreBtn.style.display = "block";
            }} else {{
                loadMoreBtn.style.display = "none";
            }}

            if (visibleAlerts.length === 0) {{
                const row = document.createElement("tr");
                const cell = document.createElement("td");

                cell.colSpan = 5;
                cell.className = "empty-state";
                cell.textContent = "No security alerts recorded";

                row.appendChild(cell);
                recentAlertsBody.appendChild(row);
            }} else {{
                for (const alert of visibleAlerts) {{
                    const row = document.createElement("tr");

                    const timeCell = document.createElement("td");
                    timeCell.className = "mono-val";
                    timeCell.textContent = formatTimestamp(alert.timestamp);

                    const typeCell = document.createElement("td");
                    const badge = document.createElement("span");
                    badge.className = "alert-badge";
                    badge.textContent = alert.type || "Unknown";
                    typeCell.appendChild(badge);

                    const sourceCell = document.createElement("td");
                    sourceCell.className = "mono-val";
                    sourceCell.textContent = alert.source_ip || "Unknown";

                    const destinationCell = document.createElement("td");
                    destinationCell.className = "mono-val";
                    destinationCell.textContent = alert.destination_ip || "N/A";

                    const detailCell = document.createElement("td");
                    detailCell.className = "mono-val";
                    let detailText = "-";
                    if (alert.ports_scanned) {{
                        detailText = `Ports: ${{alert.ports_scanned.join(', ')}}`;
                    }} else if (alert.syn_count) {{
                        detailText = `SYN count: ${{alert.syn_count}}`;
                    }} else if (alert.target_hosts) {{
                        detailText = `Hosts: ${{alert.target_hosts.length}}`;
                    }}
                    detailCell.textContent = detailText;

                    row.appendChild(timeCell);
                    row.appendChild(typeCell);
                    row.appendChild(sourceCell);
                    row.appendChild(destinationCell);
                    row.appendChild(detailCell);

                    recentAlertsBody.appendChild(row);
                }}
            }}
        }}

        function updateFilterTypeOptions(statistics) {{
            const select = document.getElementById("filter-alert-type");
            const currentValue = select.value;
            const alertTypes = Object.keys(statistics.alerts_by_type || {{}});

            select.replaceChildren();

            const defaultOption = document.createElement("option");
            defaultOption.value = "";
            defaultOption.textContent = "All Types";
            select.appendChild(defaultOption);

            for (const type of alertTypes) {{
                const option = document.createElement("option");
                option.value = type;
                option.textContent = type;

                if (type === currentValue) {{
                    option.selected = true;
                }}

                select.appendChild(option);
            }}
        }}

        function updateCaptureUI(captureState) {{
            const captureDot = document.getElementById("capture-status-dot");
            const captureText = document.getElementById("capture-status-text");
            const captureVal = document.getElementById("capture-status-val");
            const captureMeta = document.getElementById("capture-duration-meta");

            captureDot.className = "status-dot";

            let statusStr = (captureState.status || "stopped").toUpperCase();
            if (captureState.status === "active") {{
                captureDot.classList.add("active");
                captureText.textContent = "Capture Active";
            }} else if (captureState.status === "starting") {{
                captureDot.classList.add("offline");
                captureText.textContent = "Capture Starting...";
                statusStr = "STARTING";
            }} else if (captureState.status === "waiting") {{
                captureDot.classList.add("offline");
                captureText.textContent = "Waiting for Traffic";
                statusStr = "WAITING";
            }} else if (captureState.status === "error") {{
                captureDot.classList.add("error");
                captureText.textContent = "Capture Error";
                if (captureState.error) {{
                    statusStr = "ERROR";
                }}
            }} else if (captureState.status === "inactive") {{
                captureDot.classList.add("stopped");
                captureText.textContent = "Capture Inactive";
                statusStr = "INACTIVE";
            }} else {{
                captureDot.classList.add("stopped");
                captureText.textContent = "Capture Stopped";
                statusStr = "STOPPED";
            }}

            captureVal.textContent = statusStr;

            const durationStr = formatDuration(captureState.duration_seconds);
            const lastTimeStr = captureState.last_packet_time ? formatTimestamp(captureState.last_packet_time) : "None";
            captureMeta.textContent = `Duration: ${{durationStr}} | Last: ${{lastTimeStr}}`;

            document.getElementById("total-packets-val").textContent = (captureState.total_packets || 0).toLocaleString();
        }}


        async function refreshDashboard() {{
            const statusElement = document.getElementById("dashboard-status");
            const statusDot = document.getElementById("status-dot");

            try {{
                const responses = await Promise.all([
                    fetch("/statistics", {{ cache: "no-store" }}),
                    fetch("/alerts", {{ cache: "no-store" }}),
                    fetch("/capture_status", {{ cache: "no-store" }}),
                    fetch("/packets", {{ cache: "no-store" }})
                ]);

                if (!responses.every(response => response.ok)) {{
                    throw new Error("Unable to retrieve dashboard data");
                }}

                cachedStatistics = await responses[0].json();
                cachedAlerts = await responses[1].json();
                cachedCaptureState = await responses[2].json();
                cachedPackets = await responses[3].json();

                updateCaptureUI(cachedCaptureState);
                updateRecentPacketsTable(cachedPackets);

                document.getElementById("total-alerts").textContent = cachedStatistics.total_alerts;

                const topSource = cachedStatistics.top_source;
                document.getElementById("top-source").textContent = topSource
                    ? `${{topSource.source_ip}} (${{topSource.count}} alerts)`
                    : "None";

                const topAlertType = cachedStatistics.top_alert_type;
                document.getElementById("top-alert-type").textContent = topAlertType
                    ? `${{topAlertType.type}} (${{topAlertType.count}} alerts)`
                    : "None";

                const alertTypeBody = document.getElementById("alerts-by-type");
                alertTypeBody.replaceChildren();

                const alertTypes = Object.entries(cachedStatistics.alerts_by_type || {{}});
                const totalAlerts = cachedStatistics.total_alerts || 0;

                if (alertTypes.length === 0) {{
                    const row = document.createElement("tr");
                    const cell = document.createElement("td");

                    cell.colSpan = 3;
                    cell.className = "empty-state";
                    cell.textContent = "No alerts recorded";

                    row.appendChild(cell);
                    alertTypeBody.appendChild(row);
                }} else {{
                    for (const [type, count] of alertTypes) {{
                        const row = document.createElement("tr");

                        const typeCell = document.createElement("td");
                        const badge = document.createElement("span");
                        badge.className = "alert-badge";
                        badge.textContent = type;
                        typeCell.appendChild(badge);

                        const countCell = document.createElement("td");
                        countCell.className = "mono-val";
                        countCell.textContent = count;

                        const distCell = document.createElement("td");
                        const pct = totalAlerts > 0 ? ((count / totalAlerts) * 100).toFixed(1) : "0.0";
                        
                        const wrapper = document.createElement("div");
                        wrapper.className = "dist-bar-wrapper";

                        const track = document.createElement("div");
                        track.className = "dist-bar-track";

                        const fill = document.createElement("div");
                        fill.className = "dist-bar-fill";
                        fill.style.width = `${{pct}}%`;

                        const pctLabel = document.createElement("span");
                        pctLabel.className = "dist-percent";
                        pctLabel.textContent = `${{pct}}%`;

                        track.appendChild(fill);
                        wrapper.appendChild(track);
                        wrapper.appendChild(pctLabel);
                        distCell.appendChild(wrapper);

                        row.appendChild(typeCell);
                        row.appendChild(countCell);
                        row.appendChild(distCell);

                        alertTypeBody.appendChild(row);
                    }}
                }}

                updateFilterTypeOptions(cachedStatistics);
                updateRecentAlertsTable();

                if (statusDot) statusDot.className = "status-dot active";
                statusElement.textContent = "System Connected";

            }} catch (error) {{
                if (statusDot) statusDot.className = "status-dot offline";
                statusElement.textContent = "Connection Error";
                console.error("Dashboard refresh failed:", error);
            }}
        }}

        document.getElementById("filter-alert-type").addEventListener("change", () => {{
            displayedAlertLimit = 10;
            updateRecentAlertsTable();
        }});
        document.getElementById("filter-source-ip").addEventListener("input", () => {{
            displayedAlertLimit = 10;
            updateRecentAlertsTable();
        }});
        document.getElementById("filter-clear").addEventListener("click", () => {{
            document.getElementById("filter-alert-type").value = "";
            document.getElementById("filter-source-ip").value = "";
            displayedAlertLimit = 10;
            updateRecentAlertsTable();
        }});
        document.getElementById("load-more-alerts").addEventListener("click", () => {{
            displayedAlertLimit += 10;
            updateRecentAlertsTable();
        }});

        refreshDashboard();
        setInterval(refreshDashboard, 3000);
    </script>
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

            elif path == "/capture_status":

                if query:
                    self.send_json_response(
                        400,
                        {
                            "error": "Query parameters are not supported for /capture_status"
                        }
                    )
                    return

                capture_state = capture_state_manager.get_state()
                self.send_json_response(
                    200,
                    capture_state
                )

            elif path == "/packets":

                if query:
                    self.send_json_response(
                        400,
                        {
                            "error": "Query parameters are not supported for /packets"
                        }
                    )
                    return

                recent_packets = capture_state_manager.get_state()["recent_packets"]
                self.send_json_response(
                    200,
                    recent_packets
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

                # Augment statistics with real-time capture metrics
                capture_state = capture_state_manager.get_state()
                summary["total_packets"] = capture_state["total_packets"]
                summary["capture_status"] = capture_state["status"]
                summary["is_capture_active"] = capture_state["is_active"]
                summary["duration_seconds"] = capture_state["duration_seconds"]
                summary["last_packet_time"] = capture_state["last_packet_time"]

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

        except Exception as e:
            traceback.print_exc()
            self.send_json_response(
                500,
                {
                    "error": "Internal server error",
                    "details": str(e)
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