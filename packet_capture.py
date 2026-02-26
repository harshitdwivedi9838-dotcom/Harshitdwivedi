"""
Packet Capture Module
Captures live network packets using Scapy.
Supports both live capture and offline PCAP file reading.
"""

import threading
import time
from datetime import datetime
from typing import Callable, Optional, Dict
import logging

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, get_if_list
    from scapy.layers.inet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")


class PacketCapture:
    """
    Handles packet capture from network interfaces or PCAP files.
    Extracts relevant information and passes to callback function.
    """
    
    def __init__(self, interface: str = None, callback: Callable = None):
        """
        Initialize packet capture.
        
        Args:
            interface: Network interface to capture from (None for default)
            callback: Function to call for each captured packet
        """
        self.interface = interface
        self.callback = callback
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.start_time = None
        
        # Logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'total_bytes': 0
        }
    
    @staticmethod
    def get_available_interfaces() -> list:
        """Get list of available network interfaces."""
        if not SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except Exception as e:
            logging.error(f"Error getting interfaces: {e}")
            return []
    
    def parse_packet(self, packet) -> Optional[Dict]:
        """
        Parse a packet and extract relevant information.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet information or None if invalid
        """
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            # Base packet info
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': self._get_protocol_name(packet),
                'packet_size': len(packet),
                'src_port': None,
                'dst_port': None,
                'flags': None
            }
            
            # Extract transport layer info
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = self._get_tcp_flags(tcp_layer)
                self.stats['tcp_packets'] += 1
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
                self.stats['udp_packets'] += 1
                
            elif packet.haslayer(ICMP):
                self.stats['icmp_packets'] += 1
            else:
                self.stats['other_packets'] += 1
            
            # Update statistics
            self.stats['total_packets'] += 1
            self.stats['total_bytes'] += packet_info['packet_size']
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")
            return None
    
    def _get_protocol_name(self, packet) -> str:
        """Determine the protocol name from packet."""
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        else:
            return 'OTHER'
    
    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string."""
        flags = []
        if tcp_layer.flags.S:
            flags.append('SYN')
        if tcp_layer.flags.A:
            flags.append('ACK')
        if tcp_layer.flags.F:
            flags.append('FIN')
        if tcp_layer.flags.R:
            flags.append('RST')
        if tcp_layer.flags.P:
            flags.append('PSH')
        if tcp_layer.flags.U:
            flags.append('URG')
        
        return '|'.join(flags) if flags else 'NONE'
    
    def _packet_handler(self, packet):
        """Internal packet handler callback."""
        try:
            packet_info = self.parse_packet(packet)
            
            if packet_info and self.callback:
                self.callback(packet_info)
            
            self.packet_count += 1
            
            # Log progress every 100 packets
            if self.packet_count % 100 == 0:
                elapsed = time.time() - self.start_time
                rate = self.packet_count / elapsed if elapsed > 0 else 0
                self.logger.info(f"Captured {self.packet_count} packets ({rate:.1f} pkt/s)")
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
    
    def start_capture(self, packet_count: int = 0, timeout: int = None):
        """
        Start capturing packets in a separate thread.
        
        Args:
            packet_count: Number of packets to capture (0 for unlimited)
            timeout: Timeout in seconds (None for unlimited)
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is not available. Cannot capture packets.")
            return
        
        if self.is_capturing:
            self.logger.warning("Capture already in progress")
            return
        
        self.is_capturing = True
        self.packet_count = 0
        self.start_time = time.time()
        
        def capture_worker():
            try:
                self.logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
                
                # Start sniffing
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    count=packet_count if packet_count > 0 else 0,
                    timeout=timeout,
                    store=False,  # Don't store packets in memory
                    stop_filter=lambda x: not self.is_capturing
                )
                
            except PermissionError:
                self.logger.error("Permission denied. Run with sudo/administrator privileges.")
            except Exception as e:
                self.logger.error(f"Capture error: {e}")
            finally:
                self.is_capturing = False
                self.logger.info(f"Capture stopped. Total packets: {self.packet_count}")
        
        self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop the packet capture."""
        if self.is_capturing:
            self.logger.info("Stopping packet capture...")
            self.is_capturing = False
            
            # Wait for thread to finish
            if self.capture_thread:
                self.capture_thread.join(timeout=5)
    
    def capture_from_file(self, pcap_file: str, callback: Callable = None):
        """
        Read packets from a PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            callback: Optional callback (uses self.callback if None)
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is not available.")
            return
        
        try:
            self.logger.info(f"Reading packets from {pcap_file}")
            packets = rdpcap(pcap_file)
            
            callback_func = callback or self.callback
            self.packet_count = 0
            self.start_time = time.time()
            
            for packet in packets:
                packet_info = self.parse_packet(packet)
                
                if packet_info and callback_func:
                    callback_func(packet_info)
                
                self.packet_count += 1
            
            self.logger.info(f"Processed {self.packet_count} packets from file")
            
        except FileNotFoundError:
            self.logger.error(f"PCAP file not found: {pcap_file}")
        except Exception as e:
            self.logger.error(f"Error reading PCAP file: {e}")
    
    def get_statistics(self) -> Dict:
        """Get current capture statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        return {
            'total_packets': self.stats['total_packets'],
            'tcp_packets': self.stats['tcp_packets'],
            'udp_packets': self.stats['udp_packets'],
            'icmp_packets': self.stats['icmp_packets'],
            'other_packets': self.stats['other_packets'],
            'total_bytes': self.stats['total_bytes'],
            'elapsed_time': elapsed,
            'packets_per_second': self.stats['total_packets'] / elapsed if elapsed > 0 else 0,
            'is_capturing': self.is_capturing
        }
    
    def reset_statistics(self):
        """Reset all statistics."""
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'total_bytes': 0
        }
        self.packet_count = 0


# Example usage
if __name__ == "__main__":
    def packet_callback(packet_info):
        print(f"Packet: {packet_info['src_ip']}:{packet_info['src_port']} -> "
              f"{packet_info['dst_ip']}:{packet_info['dst_port']} "
              f"[{packet_info['protocol']}] {packet_info['packet_size']} bytes")
    
    # List available interfaces
    interfaces = PacketCapture.get_available_interfaces()
    print(f"Available interfaces: {interfaces}")
    
    # Create capture instance
    capture = PacketCapture(callback=packet_callback)
    
    # Start capturing for 10 seconds
    print("Starting capture for 10 seconds...")
    capture.start_capture(timeout=10)
    
    # Wait for capture to complete
    time.sleep(12)
    
    # Print statistics
    stats = capture.get_statistics()
    print(f"\nCapture Statistics:")
    print(f"Total packets: {stats['total_packets']}")
    print(f"TCP: {stats['tcp_packets']}, UDP: {stats['udp_packets']}, ICMP: {stats['icmp_packets']}")
    print(f"Rate: {stats['packets_per_second']:.2f} pkt/s")
