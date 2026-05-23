"""
logger.py — Packet logging module for Smart Packet Inspector.
Saves captured packet records to CSV and plain-text log files.
"""

import csv
import os
from datetime import datetime
from pathlib import Path


# Default output directory for logs
LOG_DIR = Path("logs")

# CSV column headers (must match keys in packet_data dicts)
CSV_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "protocol",
    "size", "src_port", "dst_port", "http_info"
]


class PacketLogger:
    """
    Dual-format packet logger: writes both a structured CSV file and a
    human-readable TXT log for every capture session.
    """

    def __init__(self, session_name: str = None, log_dir: Path = LOG_DIR):
        """
        Initialize the logger. Creates the log directory if it doesn't exist.

        Args:
            session_name (str|None): Custom name for this session's log files.
                                     Defaults to a timestamp-based name.
            log_dir (Path): Directory where log files are written.
        """
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

        if session_name is None:
            session_name = datetime.now().strftime("session_%Y%m%d_%H%M%S")

        self.session_name = session_name
        self.csv_path = self.log_dir / f"{session_name}.csv"
        self.txt_path = self.log_dir / f"{session_name}.txt"

        self._packet_count = 0
        self._csv_file = None
        self._csv_writer = None
        self._txt_file = None
        self._initialized = False

    def open(self):
        """
        Open both log files and write their headers/banners.
        Must be called before any log() calls.
        """
        # Open CSV log
        self._csv_file = open(self.csv_path, "w", newline="", encoding="utf-8")
        self._csv_writer = csv.DictWriter(
            self._csv_file, fieldnames=CSV_FIELDS, extrasaction="ignore"
        )
        self._csv_writer.writeheader()

        # Open TXT log
        self._txt_file = open(self.txt_path, "w", encoding="utf-8")
        self._write_txt_banner()

        self._initialized = True

    def _write_txt_banner(self):
        """Write a header banner to the TXT log file."""
        banner = (
            "=" * 70 + "\n"
            f"  SMART PACKET INSPECTOR — Capture Session Log\n"
            f"  Session : {self.session_name}\n"
            f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            "=" * 70 + "\n\n"
        )
        self._txt_file.write(banner)
        self._txt_file.flush()

    def log(self, packet_data: dict):
        """
        Write a single packet record to both CSV and TXT files.

        Args:
            packet_data (dict): Packet metadata dict from sniffer.py
        """
        if not self._initialized:
            raise RuntimeError("PacketLogger.open() must be called before log()")

        self._packet_count += 1

        # Write to CSV
        self._csv_writer.writerow(packet_data)
        self._csv_file.flush()

        # Write to TXT (human-readable single-line format)
        ports = ""
        if packet_data.get("src_port") and packet_data.get("dst_port"):
            ports = f"  Ports: {packet_data['src_port']} → {packet_data['dst_port']}"

        http_note = ""
        if packet_data.get("http_info"):
            snippet = packet_data["http_info"][:80].replace("\r\n", " ")
            http_note = f"\n    HTTP: {snippet}"

        line = (
            f"[{packet_data.get('timestamp', 'N/A')}] "
            f"#{self._packet_count:<5} "
            f"{packet_data.get('protocol', '???'):6} "
            f"{packet_data.get('src_ip', '?'):>15} → {packet_data.get('dst_ip', '?'):<15} "
            f"({packet_data.get('size', 0)} bytes){ports}{http_note}\n"
        )
        self._txt_file.write(line)
        self._txt_file.flush()

    def log_alert(self, alert: dict):
        """
        Append an anomaly alert to the TXT log.

        Args:
            alert (dict): Alert dict from analyzer.py
        """
        if not self._initialized:
            return
        line = (
            f"\n⚠  ALERT [{alert.get('severity','?')}] {alert.get('type','?')} — "
            f"{alert.get('message','')}\n\n"
        )
        self._txt_file.write(line)
        self._txt_file.flush()

    def write_summary(self, stats: dict, alerts: list):
        """
        Append a session summary block at the end of the TXT log.

        Args:
            stats (dict): Statistics snapshot from TrafficAnalyzer.get_stats()
            alerts (list): Full alert list from TrafficAnalyzer.get_alerts()
        """
        if not self._initialized:
            return

        lines = [
            "\n" + "=" * 70 + "\n",
            "  SESSION SUMMARY\n",
            "=" * 70 + "\n",
            f"  Total Packets    : {stats.get('total_packets', 0)}\n",
            f"  Total Bytes      : {stats.get('total_bytes', 0):,}\n",
            f"  Session Duration : {stats.get('session_duration_sec', 0)}s\n",
            f"  Avg Pkt/sec      : {stats.get('packets_per_second', 0)}\n",
            f"  Alerts Fired     : {stats.get('alert_count', 0)}\n",
            "\n  Protocol Breakdown:\n",
        ]

        for proto, count in stats.get("protocol_counts", {}).items():
            lines.append(f"    {proto:<8} : {count}\n")

        lines.append("\n  Top Source IPs:\n")
        for ip, count in stats.get("top_source_ips", []):
            lines.append(f"    {ip:<18} : {count} packets\n")

        if alerts:
            lines.append("\n  Anomaly Alerts:\n")
            for a in alerts:
                lines.append(
                    f"    [{a.get('severity','?')}] {a.get('type','?')} "
                    f"from {a.get('src_ip','?')} — {a.get('message','')}\n"
                )

        lines.append("=" * 70 + "\n")

        self._txt_file.writelines(lines)
        self._txt_file.flush()

    def close(self):
        """
        Flush and close both log files.
        """
        if self._csv_file:
            self._csv_file.close()
        if self._txt_file:
            self._txt_file.close()
        self._initialized = False

    @property
    def packet_count(self) -> int:
        """Return the number of packets logged in this session."""
        return self._packet_count

    def __repr__(self):
        return (
            f"PacketLogger(session='{self.session_name}', "
            f"csv='{self.csv_path}', txt='{self.txt_path}', "
            f"packets={self._packet_count})"
        )
