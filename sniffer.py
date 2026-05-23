"""
sniffer.py — Core packet capture engine for Smart Packet Inspector.
Uses Scapy to sniff network packets and push them to the analyzer pipeline.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime
import threading


class PacketSniffer:
    """
    Handles real-time packet capture using Scapy's sniff() engine.
    Supports filters by protocol and IP address.
    """

    def __init__(self, packet_callback, protocol_filter=None, ip_filter=None, interface=None):
        """
        Initialize the sniffer with callback and optional filters.

        Args:
            packet_callback (callable): Function to call for each captured packet.
            protocol_filter (str|None): Protocol to filter ('TCP', 'UDP', 'ICMP', 'HTTP').
            ip_filter (str|None): IP address to filter (source or destination).
            interface (str|None): Network interface to sniff on (None = default).
        """
        self.packet_callback = packet_callback
        self.protocol_filter = protocol_filter.upper() if protocol_filter else None
        self.ip_filter = ip_filter
        self.interface = interface
        self._stop_event = threading.Event()
        self._thread = None

    def _matches_filter(self, packet) -> bool:
        """
        Apply protocol and IP filters to a captured packet.

        Returns:
            bool: True if the packet passes all active filters.
        """
        # Protocol filtering
        if self.protocol_filter:
            proto = self._detect_protocol(packet)
            if proto != self.protocol_filter:
                return False

        # IP filtering
        if self.ip_filter and IP in packet:
            if packet[IP].src != self.ip_filter and packet[IP].dst != self.ip_filter:
                return False

        return True

    def _detect_protocol(self, packet) -> str:
        """
        Detect the primary application-level protocol of a packet.

        Returns:
            str: 'HTTP', 'TCP', 'UDP', 'ICMP', or 'OTHER'
        """
        if IP not in packet:
            return "OTHER"

        if TCP in packet:
            # Attempt HTTP detection by checking known ports and payload
            if packet[TCP].dport in (80, 8080) or packet[TCP].sport in (80, 8080):
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode("utf-8", errors="ignore")
                        if payload.startswith(("GET ", "POST ", "PUT ", "HTTP/", "DELETE ")):
                            return "HTTP"
                    except Exception:
                        pass
            return "TCP"

        elif UDP in packet:
            return "UDP"

        elif ICMP in packet:
            return "ICMP"

        return "OTHER"

    def _process_packet(self, packet):
        """
        Internal handler called by Scapy for each captured packet.
        Builds a structured packet dictionary and passes it to the callback.
        """
        if IP not in packet:
            return  # Skip non-IP frames (ARP, etc.)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        protocol = self._detect_protocol(packet)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)

        # Extract TCP/UDP port info if available
        src_port = dst_port = None
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # HTTP payload preview (first 200 chars)
        http_info = None
        if protocol == "HTTP" and Raw in packet:
            try:
                http_info = packet[Raw].load.decode("utf-8", errors="ignore")[:200]
            except Exception:
                pass

        packet_data = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "size": size,
            "src_port": src_port,
            "dst_port": dst_port,
            "http_info": http_info,
        }

        # Apply filters before forwarding
        if self._matches_filter_dict(packet_data, packet):
            self.packet_callback(packet_data)

    def _matches_filter_dict(self, packet_data: dict, raw_packet) -> bool:
        """
        Apply filters using the already-parsed packet_data dict.
        """
        if self.protocol_filter and packet_data["protocol"] != self.protocol_filter:
            return False
        if self.ip_filter:
            if packet_data["src_ip"] != self.ip_filter and packet_data["dst_ip"] != self.ip_filter:
                return False
        return True

    def start(self):
        """
        Start packet sniffing in a background daemon thread.
        Non-blocking — returns immediately.
        """
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def _sniff_loop(self):
        """
        The actual blocking sniff call running in a background thread.
        Uses stop_filter to allow graceful shutdown via stop().
        """
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda p: self._stop_event.is_set(),
        )

    def stop(self):
        """
        Signal the sniffer to stop capturing. Waits for thread to finish.
        """
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
