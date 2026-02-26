"""
Rule-Based Detection Module
Implements heuristic rules for detecting common network attacks.
Complements ML-based anomaly detection with signature-based detection.
"""

from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import threading


class RuleBasedDetector:
    """
    Detects network attacks using rule-based heuristics.
    Implements detection for port scans, traffic spikes, SYN floods, etc.
    """
    
    def __init__(self):
        """Initialize rule-based detector."""
        # Track connections per source IP
        self.source_connections = defaultdict(lambda: {
            'dst_ports': set(),
            'dst_ips': set(),
            'packet_count': 0,
            'syn_count': 0,
            'first_seen': None,
            'last_seen': None,
            'flows': []
        })
        
        # Track connections per destination IP
        self.dest_connections = defaultdict(lambda: {
            'src_ips': set(),
            'packet_count': 0,
            'syn_count': 0
        })
        
        # Alert history to prevent duplicates
        self.alert_history = defaultdict(lambda: {
            'count': 0,
            'last_alert': None
        })
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
        # Detection thresholds (configurable)
        self.thresholds = {
            'port_scan_ports': 20,  # Number of ports
            'port_scan_time': 60,   # Seconds
            'ip_scan_ips': 50,      # Number of IPs
            'ip_scan_time': 60,     # Seconds
            'syn_flood_count': 100, # SYN packets
            'syn_flood_time': 10,   # Seconds
            'traffic_spike_rate': 1000,  # Packets per second
            'ddos_sources': 20,     # Number of source IPs
            'ddos_time': 30         # Seconds
        }
    
    def update(self, flow: Dict):
        """
        Update tracking data with new flow.
        
        Args:
            flow: Flow dictionary
        """
        with self.lock:
            src_ip = flow['src_ip']
            dst_ip = flow['dst_ip']
            dst_port = flow.get('dst_port')
            timestamp = flow.get('last_seen', datetime.now())
            
            # Update source IP tracking
            src_data = self.source_connections[src_ip]
            if dst_port:
                src_data['dst_ports'].add(dst_port)
            src_data['dst_ips'].add(dst_ip)
            src_data['packet_count'] += flow.get('packet_count', 0)
            src_data['syn_count'] += flow.get('syn_count', 0)
            
            if src_data['first_seen'] is None:
                src_data['first_seen'] = timestamp
            src_data['last_seen'] = timestamp
            src_data['flows'].append(flow)
            
            # Update destination IP tracking
            dst_data = self.dest_connections[dst_ip]
            dst_data['src_ips'].add(src_ip)
            dst_data['packet_count'] += flow.get('packet_count', 0)
            dst_data['syn_count'] += flow.get('syn_count', 0)
    
    def detect_port_scan(self, src_ip: str) -> Optional[Dict]:
        """
        Detect port scanning activity.
        
        Args:
            src_ip: Source IP address to check
            
        Returns:
            Alert dictionary if detected, None otherwise
        """
        with self.lock:
            if src_ip not in self.source_connections:
                return None
            
            src_data = self.source_connections[src_ip]
            
            # Check if scanned many ports
            num_ports = len(src_data['dst_ports'])
            if num_ports < self.thresholds['port_scan_ports']:
                return None
            
            # Check time window
            if src_data['first_seen'] and src_data['last_seen']:
                duration = (src_data['last_seen'] - src_data['first_seen']).total_seconds()
                
                if duration <= self.thresholds['port_scan_time']:
                    # Check if we already alerted recently
                    alert_key = f"port_scan_{src_ip}"
                    if not self._should_alert(alert_key):
                        return None
                    
                    return {
                        'alert_type': 'port_scan',
                        'source_ip': src_ip,
                        'target_ip': list(src_data['dst_ips'])[0] if src_data['dst_ips'] else None,
                        'severity': 'high',
                        'description': f'Port scan detected: {num_ports} ports scanned in {duration:.1f}s',
                        'event_count': num_ports,
                        'details': {
                            'ports_scanned': num_ports,
                            'duration': duration,
                            'dst_ips': len(src_data['dst_ips'])
                        }
                    }
        
        return None
    
    def detect_ip_scan(self, src_ip: str) -> Optional[Dict]:
        """
        Detect IP scanning / network reconnaissance.
        
        Args:
            src_ip: Source IP address to check
            
        Returns:
            Alert dictionary if detected, None otherwise
        """
        with self.lock:
            if src_ip not in self.source_connections:
                return None
            
            src_data = self.source_connections[src_ip]
            
            # Check if contacted many IPs
            num_ips = len(src_data['dst_ips'])
            if num_ips < self.thresholds['ip_scan_ips']:
                return None
            
            # Check time window
            if src_data['first_seen'] and src_data['last_seen']:
                duration = (src_data['last_seen'] - src_data['first_seen']).total_seconds()
                
                if duration <= self.thresholds['ip_scan_time']:
                    alert_key = f"ip_scan_{src_ip}"
                    if not self._should_alert(alert_key):
                        return None
                    
                    return {
                        'alert_type': 'ip_scan',
                        'source_ip': src_ip,
                        'target_ip': None,
                        'severity': 'medium',
                        'description': f'IP scan detected: {num_ips} IPs contacted in {duration:.1f}s',
                        'event_count': num_ips,
                        'details': {
                            'ips_contacted': num_ips,
                            'duration': duration
                        }
                    }
        
        return None
    
    def detect_syn_flood(self, src_ip: str) -> Optional[Dict]:
        """
        Detect SYN flood attack.
        
        Args:
            src_ip: Source IP address to check
            
        Returns:
            Alert dictionary if detected, None otherwise
        """
        with self.lock:
            if src_ip not in self.source_connections:
                return None
            
            src_data = self.source_connections[src_ip]
            
            # Check SYN count
            syn_count = src_data['syn_count']
            if syn_count < self.thresholds['syn_flood_count']:
                return None
            
            # Check time window
            if src_data['first_seen'] and src_data['last_seen']:
                duration = (src_data['last_seen'] - src_data['first_seen']).total_seconds()
                
                if duration <= self.thresholds['syn_flood_time']:
                    alert_key = f"syn_flood_{src_ip}"
                    if not self._should_alert(alert_key):
                        return None
                    
                    return {
                        'alert_type': 'syn_flood',
                        'source_ip': src_ip,
                        'target_ip': list(src_data['dst_ips'])[0] if src_data['dst_ips'] else None,
                        'severity': 'critical',
                        'description': f'SYN flood detected: {syn_count} SYN packets in {duration:.1f}s',
                        'event_count': syn_count,
                        'details': {
                            'syn_count': syn_count,
                            'duration': duration,
                            'rate': syn_count / duration if duration > 0 else 0
                        }
                    }
        
        return None
    
    def detect_traffic_spike(self, src_ip: str) -> Optional[Dict]:
        """
        Detect unusual traffic volume spike.
        
        Args:
            src_ip: Source IP address to check
            
        Returns:
            Alert dictionary if detected, None otherwise
        """
        with self.lock:
            if src_ip not in self.source_connections:
                return None
            
            src_data = self.source_connections[src_ip]
            
            # Calculate packet rate
            if src_data['first_seen'] and src_data['last_seen']:
                duration = (src_data['last_seen'] - src_data['first_seen']).total_seconds()
                
                if duration > 0:
                    packet_rate = src_data['packet_count'] / duration
                    
                    if packet_rate >= self.thresholds['traffic_spike_rate']:
                        alert_key = f"traffic_spike_{src_ip}"
                        if not self._should_alert(alert_key):
                            return None
                        
                        return {
                            'alert_type': 'traffic_spike',
                            'source_ip': src_ip,
                            'target_ip': None,
                            'severity': 'medium',
                            'description': f'Traffic spike detected: {packet_rate:.0f} pkt/s',
                            'event_count': src_data['packet_count'],
                            'details': {
                                'packet_rate': packet_rate,
                                'total_packets': src_data['packet_count'],
                                'duration': duration
                            }
                        }
        
        return None
    
    def detect_ddos(self, dst_ip: str) -> Optional[Dict]:
        """
        Detect potential DDoS attack on destination.
        
        Args:
            dst_ip: Destination IP address to check
            
        Returns:
            Alert dictionary if detected, None otherwise
        """
        with self.lock:
            if dst_ip not in self.dest_connections:
                return None
            
            dst_data = self.dest_connections[dst_ip]
            
            # Check if many sources are attacking
            num_sources = len(dst_data['src_ips'])
            if num_sources < self.thresholds['ddos_sources']:
                return None
            
            alert_key = f"ddos_{dst_ip}"
            if not self._should_alert(alert_key):
                return None
            
            return {
                'alert_type': 'ddos',
                'source_ip': None,
                'target_ip': dst_ip,
                'severity': 'critical',
                'description': f'Potential DDoS: {num_sources} sources attacking {dst_ip}',
                'event_count': num_sources,
                'details': {
                    'source_count': num_sources,
                    'total_packets': dst_data['packet_count']
                }
            }
    
    def check_all_rules(self, flow: Dict) -> List[Dict]:
        """
        Check all detection rules for a flow.
        
        Args:
            flow: Flow dictionary
            
        Returns:
            List of alert dictionaries
        """
        # Update tracking
        self.update(flow)
        
        alerts = []
        src_ip = flow['src_ip']
        dst_ip = flow['dst_ip']
        
        # Run all detections
        checks = [
            self.detect_port_scan(src_ip),
            self.detect_ip_scan(src_ip),
            self.detect_syn_flood(src_ip),
            self.detect_traffic_spike(src_ip),
            self.detect_ddos(dst_ip)
        ]
        
        # Collect non-None alerts
        for alert in checks:
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _should_alert(self, alert_key: str, cooldown: int = 300) -> bool:
        """
        Check if we should generate an alert (prevents spam).
        
        Args:
            alert_key: Unique identifier for alert type
            cooldown: Seconds before re-alerting
            
        Returns:
            True if should alert, False otherwise
        """
        now = datetime.now()
        
        if alert_key in self.alert_history:
            last_alert = self.alert_history[alert_key]['last_alert']
            
            if last_alert and (now - last_alert).total_seconds() < cooldown:
                return False
        
        # Update alert history
        self.alert_history[alert_key]['count'] += 1
        self.alert_history[alert_key]['last_alert'] = now
        
        return True
    
    def cleanup_old_data(self, max_age: int = 600):
        """
        Remove old tracking data.
        
        Args:
            max_age: Maximum age in seconds
        """
        with self.lock:
            now = datetime.now()
            
            # Clean source connections
            expired_sources = []
            for src_ip, data in self.source_connections.items():
                if data['last_seen'] and (now - data['last_seen']).total_seconds() > max_age:
                    expired_sources.append(src_ip)
            
            for src_ip in expired_sources:
                del self.source_connections[src_ip]
            
            # Clean destination connections
            expired_dests = []
            for dst_ip in self.dest_connections:
                # Simple cleanup - could be improved with timestamps
                if len(self.dest_connections[dst_ip]['src_ips']) == 0:
                    expired_dests.append(dst_ip)
            
            for dst_ip in expired_dests:
                del self.dest_connections[dst_ip]
    
    def get_statistics(self) -> Dict:
        """Get current detection statistics."""
        with self.lock:
            return {
                'tracked_sources': len(self.source_connections),
                'tracked_destinations': len(self.dest_connections),
                'total_alerts': sum(h['count'] for h in self.alert_history.values()),
                'thresholds': self.thresholds.copy()
            }
    
    def update_thresholds(self, new_thresholds: Dict):
        """Update detection thresholds."""
        with self.lock:
            self.thresholds.update(new_thresholds)
    
    def reset(self):
        """Clear all tracking data."""
        with self.lock:
            self.source_connections.clear()
            self.dest_connections.clear()
            self.alert_history.clear()


# Example usage
if __name__ == "__main__":
    detector = RuleBasedDetector()
    
    # Simulate port scan
    print("Simulating port scan...")
    base_time = datetime.now()
    
    for i in range(30):
        flow = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.50',
            'src_port': 50000 + i,
            'dst_port': 1000 + i,
            'protocol': 'TCP',
            'packet_count': 5,
            'syn_count': 1,
            'first_seen': base_time,
            'last_seen': base_time + timedelta(seconds=i)
        }
        
        alerts = detector.check_all_rules(flow)
        
        for alert in alerts:
            print(f"\n[ALERT] {alert['alert_type'].upper()}")
            print(f"  Source: {alert['source_ip']}")
            print(f"  Severity: {alert['severity']}")
            print(f"  Description: {alert['description']}")
    
    # Print statistics
    stats = detector.get_statistics()
    print(f"\nStatistics:")
    print(f"  Tracked sources: {stats['tracked_sources']}")
    print(f"  Total alerts: {stats['total_alerts']}")
