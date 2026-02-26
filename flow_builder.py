"""
Flow Builder Module
Aggregates individual packets into bidirectional network flows.
A flow is identified by 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
"""

import time
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict
import threading


class FlowBuilder:
    """
    Builds and manages network flows from individual packets.
    Tracks flow statistics and maintains flow state.
    """
    
    def __init__(self, flow_timeout: int = 120, cleanup_interval: int = 60):
        """
        Initialize flow builder.
        
        Args:
            flow_timeout: Seconds before inactive flow expires
            cleanup_interval: Seconds between cleanup operations
        """
        self.flow_timeout = flow_timeout
        self.cleanup_interval = cleanup_interval
        
        # Flow storage: {flow_key: flow_data}
        self.flows = {}
        self.flow_lock = threading.Lock()
        
        # Cleanup thread
        self.cleanup_thread = None
        self.running = False
        
        # Statistics
        self.total_flows = 0
        self.active_flows = 0
    
    def _generate_flow_key(self, packet_info: Dict) -> str:
        """
        Generate a unique flow key from packet information.
        Uses bidirectional flow (normalizes source/dest).
        
        Args:
            packet_info: Parsed packet information
            
        Returns:
            Flow key string
        """
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        src_port = packet_info.get('src_port', 0) or 0
        dst_port = packet_info.get('dst_port', 0) or 0
        protocol = packet_info['protocol']
        
        # Normalize flow direction (smaller IP first)
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        elif src_ip > dst_ip:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        else:
            # Same IP, use smaller port first
            if src_port <= dst_port:
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def process_packet(self, packet_info: Dict) -> Dict:
        """
        Process a packet and update corresponding flow.
        
        Args:
            packet_info: Parsed packet information
            
        Returns:
            Updated flow data
        """
        flow_key = self._generate_flow_key(packet_info)
        
        with self.flow_lock:
            if flow_key not in self.flows:
                # Create new flow
                self.flows[flow_key] = self._create_new_flow(packet_info, flow_key)
                self.total_flows += 1
                self.active_flows += 1
            else:
                # Update existing flow
                self._update_flow(self.flows[flow_key], packet_info)
            
            return self.flows[flow_key].copy()
    
    def _create_new_flow(self, packet_info: Dict, flow_key: str) -> Dict:
        """Create a new flow from first packet."""
        return {
            'flow_key': flow_key,
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'protocol': packet_info['protocol'],
            'first_seen': packet_info['timestamp'],
            'last_seen': packet_info['timestamp'],
            'packet_count': 1,
            'byte_count': packet_info['packet_size'],
            'duration': 0.0,
            'packets': [packet_info],  # Store recent packets for analysis
            'flags': [packet_info.get('flags')],
            'syn_count': 1 if packet_info.get('flags') and 'SYN' in packet_info.get('flags', '') else 0,
            'fin_count': 0,
            'rst_count': 0
        }
    
    def _update_flow(self, flow: Dict, packet_info: Dict):
        """Update an existing flow with new packet."""
        flow['last_seen'] = packet_info['timestamp']
        flow['packet_count'] += 1
        flow['byte_count'] += packet_info['packet_size']
        
        # Calculate duration
        time_diff = (flow['last_seen'] - flow['first_seen']).total_seconds()
        flow['duration'] = time_diff
        
        # Store recent packets (keep last 10)
        flow['packets'].append(packet_info)
        if len(flow['packets']) > 10:
            flow['packets'].pop(0)
        
        # Track TCP flags
        flags = packet_info.get('flags', '')
        if flags:
            flow['flags'].append(flags)
            if 'SYN' in flags:
                flow['syn_count'] += 1
            if 'FIN' in flags:
                flow['fin_count'] += 1
            if 'RST' in flags:
                flow['rst_count'] += 1
    
    def get_flow_features(self, flow_key: str) -> Optional[Dict]:
        """
        Calculate statistical features for a flow.
        
        Args:
            flow_key: Flow identifier
            
        Returns:
            Dictionary of flow features for ML
        """
        with self.flow_lock:
            if flow_key not in self.flows:
                return None
            
            flow = self.flows[flow_key]
            
            # Calculate features
            duration = flow['duration'] if flow['duration'] > 0 else 0.001
            
            features = {
                'flow_key': flow_key,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'] or 0,
                'dst_port': flow['dst_port'] or 0,
                'protocol': flow['protocol'],
                
                # Basic statistics
                'packet_count': flow['packet_count'],
                'byte_count': flow['byte_count'],
                'duration': duration,
                
                # Derived features
                'avg_packet_size': flow['byte_count'] / flow['packet_count'],
                'packets_per_second': flow['packet_count'] / duration,
                'bytes_per_second': flow['byte_count'] / duration,
                
                # TCP-specific features
                'syn_count': flow.get('syn_count', 0),
                'fin_count': flow.get('fin_count', 0),
                'rst_count': flow.get('rst_count', 0),
                
                # Port analysis
                'is_well_known_port': 1 if (flow['dst_port'] and flow['dst_port'] < 1024) else 0,
                
                # Timestamps
                'first_seen': flow['first_seen'],
                'last_seen': flow['last_seen']
            }
            
            return features
    
    def get_all_active_flows(self) -> List[Dict]:
        """Get all currently active flows with features."""
        with self.flow_lock:
            flows = []
            for flow_key in list(self.flows.keys()):
                features = self.get_flow_features(flow_key)
                if features:
                    flows.append(features)
            return flows
    
    def get_flow(self, flow_key: str) -> Optional[Dict]:
        """Get specific flow by key."""
        with self.flow_lock:
            return self.flows.get(flow_key, {}).copy()
    
    def cleanup_expired_flows(self) -> int:
        """
        Remove flows that haven't seen activity recently.
        
        Returns:
            Number of flows removed
        """
        current_time = datetime.now()
        removed_count = 0
        
        with self.flow_lock:
            expired_keys = []
            
            for flow_key, flow in self.flows.items():
                time_since_last = (current_time - flow['last_seen']).total_seconds()
                
                if time_since_last > self.flow_timeout:
                    expired_keys.append(flow_key)
            
            # Remove expired flows
            for key in expired_keys:
                del self.flows[key]
                removed_count += 1
                self.active_flows -= 1
        
        return removed_count
    
    def start_cleanup_thread(self):
        """Start background thread for automatic cleanup."""
        if self.running:
            return
        
        self.running = True
        
        def cleanup_worker():
            while self.running:
                time.sleep(self.cleanup_interval)
                removed = self.cleanup_expired_flows()
                if removed > 0:
                    print(f"Cleaned up {removed} expired flows")
        
        self.cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def stop_cleanup_thread(self):
        """Stop the cleanup thread."""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
    
    def get_statistics(self) -> Dict:
        """Get flow builder statistics."""
        with self.flow_lock:
            return {
                'total_flows_created': self.total_flows,
                'active_flows': len(self.flows),
                'flow_timeout': self.flow_timeout
            }
    
    def reset(self):
        """Clear all flows and reset statistics."""
        with self.flow_lock:
            self.flows.clear()
            self.total_flows = 0
            self.active_flows = 0


# Example usage
if __name__ == "__main__":
    # Create flow builder
    builder = FlowBuilder(flow_timeout=60)
    
    # Simulate some packets
    packets = [
        {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 54321,
            'dst_port': 53,
            'protocol': 'UDP',
            'packet_size': 64,
            'flags': None
        },
        {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 54321,
            'dst_port': 53,
            'protocol': 'UDP',
            'packet_size': 128,
            'flags': None
        }
    ]
    
    # Process packets
    for pkt in packets:
        flow = builder.process_packet(pkt)
        print(f"Flow updated: {flow['flow_key']}")
    
    # Get flow features
    flows = builder.get_all_active_flows()
    for flow in flows:
        print(f"\nFlow Features:")
        print(f"  Key: {flow['flow_key']}")
        print(f"  Packets: {flow['packet_count']}")
        print(f"  Bytes: {flow['byte_count']}")
        print(f"  Avg packet size: {flow['avg_packet_size']:.2f}")
        print(f"  Packets/sec: {flow['packets_per_second']:.2f}")
