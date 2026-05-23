"""
analyzer.py — Real-time traffic analytics and anomaly detection engine.
Tracks statistics, detects suspicious patterns, and provides summary reports.
"""

from collections import defaultdict, deque
from datetime import datetime
import threading
import time


# --- Thresholds for anomaly detection ---
ICMP_FLOOD_THRESHOLD = 15        # ICMP packets from same IP within window
IP_FLOOD_THRESHOLD = 80          # Total packets from same IP within window
ANOMALY_WINDOW_SECONDS = 10      # Rolling time window for flood detection


class TrafficAnalyzer:
    """
    Stateful traffic analyzer that consumes parsed packet dictionaries
    and produces statistics and anomaly alerts.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # --- Core counters ---
        self.total_packets = 0
        self.protocol_counts = defaultdict(int)   # {'TCP': 42, 'UDP': 10, ...}
        self.source_ip_counts = defaultdict(int)  # {'192.168.1.1': 33, ...}
        self.total_bytes = 0

        # --- Per-IP timestamps for flood detection (rolling window) ---
        # Maps IP → deque of float timestamps
        self._icmp_timestamps: dict[str, deque] = defaultdict(lambda: deque())
        self._ip_timestamps: dict[str, deque] = defaultdict(lambda: deque())

        # --- Alert log ---
        self.alerts: list[dict] = []

        # --- Session start time ---
        self.session_start = datetime.now()

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def ingest(self, packet_data: dict):
        """
        Ingest one parsed packet dictionary produced by PacketSniffer.
        Updates all counters and runs anomaly detection.

        Args:
            packet_data (dict): Packet metadata dict from sniffer.py
        """
        with self._lock:
            self.total_packets += 1
            self.total_bytes += packet_data.get("size", 0)
            proto = packet_data.get("protocol", "OTHER")
            src = packet_data.get("src_ip", "unknown")

            self.protocol_counts[proto] += 1
            self.source_ip_counts[src] += 1

            # Anomaly detection
            now = time.time()
            self._check_icmp_flood(src, proto, now)
            self._check_ip_flood(src, now)

    def get_stats(self) -> dict:
        """
        Return a snapshot of current traffic statistics.

        Returns:
            dict: Statistics snapshot (safe copy, thread-consistent).
        """
        with self._lock:
            elapsed = (datetime.now() - self.session_start).total_seconds()
            pps = self.total_packets / elapsed if elapsed > 0 else 0

            top_ips = sorted(
                self.source_ip_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]

            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "protocol_counts": dict(self.protocol_counts),
                "top_source_ips": top_ips,
                "packets_per_second": round(pps, 2),
                "session_duration_sec": round(elapsed, 1),
                "alert_count": len(self.alerts),
            }

    def get_alerts(self) -> list:
        """
        Return a copy of all fired anomaly alerts.
        """
        with self._lock:
            return list(self.alerts)

    def reset(self):
        """
        Reset all counters and alert history (new capture session).
        """
        with self._lock:
            self.total_packets = 0
            self.protocol_counts.clear()
            self.source_ip_counts.clear()
            self.total_bytes = 0
            self._icmp_timestamps.clear()
            self._ip_timestamps.clear()
            self.alerts.clear()
            self.session_start = datetime.now()

    # ------------------------------------------------------------------ #
    #  Internal anomaly detection helpers                                  #
    # ------------------------------------------------------------------ #

    def _prune_old_timestamps(self, ts_deque: deque, now: float, window: float):
        """
        Remove timestamps older than `window` seconds from the deque.
        Modifies the deque in-place.
        """
        cutoff = now - window
        while ts_deque and ts_deque[0] < cutoff:
            ts_deque.popleft()

    def _check_icmp_flood(self, src_ip: str, proto: str, now: float):
        """
        Detect ICMP flood from a single source IP.
        Fires an alert if ICMP count from `src_ip` exceeds threshold within window.
        """
        if proto != "ICMP":
            return

        dq = self._icmp_timestamps[src_ip]
        dq.append(now)
        self._prune_old_timestamps(dq, now, ANOMALY_WINDOW_SECONDS)

        if len(dq) >= ICMP_FLOOD_THRESHOLD:
            alert = {
                "type": "ICMP_FLOOD",
                "severity": "HIGH",
                "src_ip": src_ip,
                "count": len(dq),
                "window_sec": ANOMALY_WINDOW_SECONDS,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": (
                    f"ICMP flood detected! {len(dq)} ICMP packets from "
                    f"{src_ip} in {ANOMALY_WINDOW_SECONDS}s"
                ),
            }
            # Deduplicate: don't re-fire the same alert within the same window
            if not self._alert_exists("ICMP_FLOOD", src_ip):
                self.alerts.append(alert)

    def _check_ip_flood(self, src_ip: str, now: float):
        """
        Detect general traffic flood from a single IP.
        Fires an alert if total packet rate from `src_ip` exceeds threshold.
        """
        dq = self._ip_timestamps[src_ip]
        dq.append(now)
        self._prune_old_timestamps(dq, now, ANOMALY_WINDOW_SECONDS)

        if len(dq) >= IP_FLOOD_THRESHOLD:
            alert = {
                "type": "IP_FLOOD",
                "severity": "MEDIUM",
                "src_ip": src_ip,
                "count": len(dq),
                "window_sec": ANOMALY_WINDOW_SECONDS,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": (
                    f"Traffic flood detected! {len(dq)} packets from "
                    f"{src_ip} in {ANOMALY_WINDOW_SECONDS}s"
                ),
            }
            if not self._alert_exists("IP_FLOOD", src_ip):
                self.alerts.append(alert)

    def _alert_exists(self, alert_type: str, src_ip: str) -> bool:
        """
        Check if a recent alert of the given type+IP already exists.
        Prevents duplicate alerts from flooding the log.
        """
        return any(
            a["type"] == alert_type and a["src_ip"] == src_ip
            for a in self.alerts[-20:]  # Check only the last 20 alerts
        )
