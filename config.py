"""
Configuration File
Central configuration for the Network Anomaly Detector system.
Modify these settings to customize behavior.
"""

# Database Configuration
DATABASE_CONFIG = {
    'path': 'data/network_traffic.db',
    'cleanup_days': 7,  # Auto-delete data older than this
}

# Flow Builder Configuration
FLOW_CONFIG = {
    'timeout': 120,  # Seconds before inactive flow expires
    'cleanup_interval': 60,  # Seconds between cleanup operations
}

# Feature Extraction Configuration
FEATURE_CONFIG = {
    'scaler_type': 'standard',  # 'standard' or 'minmax'
    'scaler_path': 'models/feature_scaler.pkl',
}

# Machine Learning Model Configuration
ML_CONFIG = {
    'contamination': 0.1,  # Expected proportion of anomalies (0.0 to 0.5)
    'random_state': 42,  # For reproducibility
    'n_estimators': 100,  # Number of trees in Isolation Forest
    'model_path': 'models/anomaly_detector.pkl',
    
    # Severity thresholds (anomaly score boundaries)
    'severity_thresholds': {
        'critical': -0.5,  # Very anomalous
        'high': -0.3,
        'medium': -0.1,
        'low': 0.0,
    }
}

# Rule-Based Detection Configuration
RULES_CONFIG = {
    # Port scan detection
    'port_scan_ports': 20,  # Number of ports to trigger alert
    'port_scan_time': 60,  # Time window in seconds
    
    # IP scan detection
    'ip_scan_ips': 50,  # Number of IPs to trigger alert
    'ip_scan_time': 60,  # Time window in seconds
    
    # SYN flood detection
    'syn_flood_count': 100,  # Number of SYN packets
    'syn_flood_time': 10,  # Time window in seconds
    
    # Traffic spike detection
    'traffic_spike_rate': 1000,  # Packets per second
    
    # DDoS detection
    'ddos_sources': 20,  # Number of attacking source IPs
    'ddos_time': 30,  # Time window in seconds
    
    # Alert cooldown (prevent spam)
    'alert_cooldown': 300,  # Seconds between same alerts
}

# Packet Capture Configuration
CAPTURE_CONFIG = {
    'default_interface': None,  # None = auto-select, or specify like 'eth0'
    'buffer_size': 65536,  # Packet buffer size
    'promiscuous_mode': True,  # Capture all packets on network
}

# Web Dashboard Configuration
DASHBOARD_CONFIG = {
    'host': '0.0.0.0',  # Listen on all interfaces
    'port': 5000,  # Web server port
    'debug': False,  # Debug mode (set to True for development)
    'refresh_interval': 5000,  # Dashboard refresh in milliseconds
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': 'INFO',  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    'log_file': 'logs/network_detector.log',
    'max_file_size': 10 * 1024 * 1024,  # 10 MB
    'backup_count': 5,  # Number of backup log files
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'max_flows_in_memory': 10000,  # Maximum concurrent flows
    'batch_size': 100,  # Batch size for ML processing
    'thread_count': -1,  # -1 = use all CPU cores
}

# Visualization Configuration
VISUALIZATION_CONFIG = {
    'timeline_hours': 24,  # Hours to show in timeline chart
    'top_talkers_count': 10,  # Number of top talkers to display
    'recent_flows_limit': 100,  # Recent flows to show
    'recent_anomalies_limit': 50,  # Recent anomalies to show
    'recent_alerts_limit': 50,  # Recent alerts to show
    'suspicious_ip_threshold': 3,  # Anomaly count to mark IP as suspicious
}

# File Paths
PATHS = {
    'data_dir': 'data',
    'models_dir': 'models',
    'logs_dir': 'logs',
    'pcap_dir': 'data',
}

# Feature Names (for reference)
FEATURE_NAMES = [
    'packet_count',
    'byte_count',
    'duration',
    'avg_packet_size',
    'packets_per_second',
    'bytes_per_second',
    'syn_count',
    'fin_count',
    'rst_count',
    'src_port',
    'dst_port',
    'is_well_known_port',
    'protocol_encoded'
]

# Protocol Mapping
PROTOCOL_MAPPING = {
    'TCP': 0,
    'UDP': 1,
    'ICMP': 2,
    'OTHER': 3
}

# Common Well-Known Ports
WELL_KNOWN_PORTS = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB'
}

# Alert Severity Colors (for UI)
SEVERITY_COLORS = {
    'critical': '#f44336',  # Red
    'high': '#ff9800',  # Orange
    'medium': '#ffc107',  # Yellow
    'low': '#8bc34a',  # Light green
    'normal': '#4CAF50'  # Green
}

# Export configuration function
def get_config(section: str = None):
    """
    Get configuration section.
    
    Args:
        section: Configuration section name (None for all)
        
    Returns:
        Configuration dictionary
    """
    all_config = {
        'database': DATABASE_CONFIG,
        'flow': FLOW_CONFIG,
        'features': FEATURE_CONFIG,
        'ml': ML_CONFIG,
        'rules': RULES_CONFIG,
        'capture': CAPTURE_CONFIG,
        'dashboard': DASHBOARD_CONFIG,
        'logging': LOGGING_CONFIG,
        'performance': PERFORMANCE_CONFIG,
        'visualization': VISUALIZATION_CONFIG,
        'paths': PATHS
    }
    
    if section:
        return all_config.get(section, {})
    return all_config


if __name__ == "__main__":
    import json
    
    print("Network Anomaly Detector - Configuration")
    print("=" * 60)
    
    config = get_config()
    
    for section, settings in config.items():
        print(f"\n{section.upper()}:")
        print(json.dumps(settings, indent=2))
