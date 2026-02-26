"""
Flask Dashboard Module
Web-based interface for monitoring network traffic and anomalies.
Provides real-time visualization and control panel.
"""

from flask import Flask, render_template, jsonify, request
import threading
import time
from datetime import datetime, timedelta
import json
import os

# Import project modules
from database import DatabaseManager
from packet_capture import PacketCapture
from flow_builder import FlowBuilder
from features import FeatureExtractor
from model import AnomalyDetector
from rules import RuleBasedDetector


class NetworkMonitor:
    """
    Main network monitoring system that coordinates all components.
    """
    
    def __init__(self):
        """Initialize all components."""
        # Core components
        self.db = DatabaseManager('data/network_traffic.db')
        self.flow_builder = FlowBuilder(flow_timeout=120)
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector(contamination=0.1)
        self.rule_detector = RuleBasedDetector()
        
        # Packet capture
        self.packet_capture = None
        self.capture_interface = None
        
        # State
        self.is_running = False
        self.is_trained = False
        
        # Statistics
        self.stats = {
            'start_time': None,
            'total_packets': 0,
            'total_flows': 0,
            'total_anomalies': 0,
            'total_alerts': 0
        }
        
        # Try to load existing model
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models if available."""
        try:
            if os.path.exists('models/anomaly_detector.pkl'):
                self.anomaly_detector.load_model('models/anomaly_detector.pkl')
                self.is_trained = True
                print("Loaded existing anomaly detection model")
            
            if os.path.exists('models/feature_scaler.pkl'):
                self.feature_extractor.load_scaler('models/feature_scaler.pkl')
                print("Loaded existing feature scaler")
        except Exception as e:
            print(f"Could not load models: {e}")
    
    def train_on_baseline(self, flows):
        """Train models on baseline normal traffic."""
        if len(flows) < 10:
            print("Not enough flows for training")
            return False
        
        try:
            # Extract and normalize features
            features = self.feature_extractor.fit_transform(flows)
            
            # Train anomaly detector
            metrics = self.anomaly_detector.train(features)
            
            # Save models
            self.anomaly_detector.save_model('models/anomaly_detector.pkl')
            self.feature_extractor.save_scaler('models/feature_scaler.pkl')
            
            self.is_trained = True
            print(f"Training complete: {metrics}")
            return True
            
        except Exception as e:
            print(f"Training error: {e}")
            return False
    
    def packet_callback(self, packet_info):
        """Handle each captured packet."""
        try:
            # Update statistics
            self.stats['total_packets'] += 1
            
            # Build flow
            flow = self.flow_builder.process_packet(packet_info)
            
            # Get flow features
            flow_features = self.flow_builder.get_flow_features(flow['flow_key'])
            
            if not flow_features:
                return
            
            # Save to database
            flow_id = self.db.insert_flow(flow_features)
            self.stats['total_flows'] = self.flow_builder.total_flows
            
            # Check rule-based detections
            alerts = self.rule_detector.check_all_rules(flow_features)
            for alert in alerts:
                self.db.insert_alert(alert)
                self.stats['total_alerts'] += 1
                print(f"[ALERT] {alert['alert_type']}: {alert['description']}")
            
            # ML-based anomaly detection (if trained)
            if self.is_trained:
                try:
                    features = self.feature_extractor.transform_single(flow_features)
                    analysis = self.anomaly_detector.analyze_flow(flow_features, features)
                    
                    if analysis['is_anomaly']:
                        anomaly_data = {
                            'flow_id': flow_id,
                            'src_ip': analysis['src_ip'],
                            'dst_ip': analysis['dst_ip'],
                            'anomaly_score': analysis['anomaly_score'],
                            'anomaly_type': 'ml_detection',
                            'severity': analysis['severity'],
                            'details': analysis.get('anomaly_indicators', {})
                        }
                        
                        self.db.insert_anomaly(anomaly_data)
                        self.stats['total_anomalies'] += 1
                        
                        print(f"[ANOMALY] {analysis['src_ip']} -> {analysis['dst_ip']} "
                              f"(score: {analysis['anomaly_score']:.3f}, "
                              f"severity: {analysis['severity']})")
                        
                except Exception as e:
                    print(f"Anomaly detection error: {e}")
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_capture(self, interface=None):
        """Start packet capture."""
        if self.is_running:
            return False
        
        self.packet_capture = PacketCapture(
            interface=interface,
            callback=self.packet_callback
        )
        
        self.capture_interface = interface
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        # Start capture in background
        self.packet_capture.start_capture()
        
        # Start cleanup threads
        self.flow_builder.start_cleanup_thread()
        
        return True
    
    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_running:
            return False
        
        self.is_running = False
        
        if self.packet_capture:
            self.packet_capture.stop_capture()
        
        self.flow_builder.stop_cleanup_thread()
        
        return True
    
    def load_pcap_file(self, filepath):
        """Load traffic from PCAP file."""
        try:
            print(f"Loading PCAP file: {filepath}")
            
            capture = PacketCapture(callback=self.packet_callback)
            capture.capture_from_file(filepath)
            
            print(f"Loaded {capture.packet_count} packets from file")
            return True
            
        except Exception as e:
            print(f"Error loading PCAP: {e}")
            return False
    
    def get_status(self):
        """Get current system status."""
        return {
            'is_running': self.is_running,
            'is_trained': self.is_trained,
            'interface': self.capture_interface,
            'stats': self.stats,
            'flow_stats': self.flow_builder.get_statistics(),
            'rule_stats': self.rule_detector.get_statistics(),
            'db_stats': self.db.get_statistics()
        }


# Initialize Flask app
app = Flask(__name__)
monitor = NetworkMonitor()


@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/status')
def api_status():
    """Get system status."""
    return jsonify(monitor.get_status())


@app.route('/api/flows')
def api_flows():
    """Get recent flows."""
    limit = request.args.get('limit', 100, type=int)
    flows = monitor.db.get_recent_flows(limit)
    return jsonify(flows)


@app.route('/api/anomalies')
def api_anomalies():
    """Get recent anomalies."""
    limit = request.args.get('limit', 50, type=int)
    anomalies = monitor.db.get_recent_anomalies(limit)
    return jsonify(anomalies)


@app.route('/api/alerts')
def api_alerts():
    """Get recent alerts."""
    limit = request.args.get('limit', 50, type=int)
    alerts = monitor.db.get_recent_alerts(limit)
    return jsonify(alerts)


@app.route('/api/suspicious_ips')
def api_suspicious_ips():
    """Get suspicious IP addresses."""
    threshold = request.args.get('threshold', 3, type=int)
    ips = monitor.db.get_suspicious_ips(threshold)
    return jsonify(ips)


@app.route('/api/top_talkers')
def api_top_talkers():
    """Get top talkers."""
    limit = request.args.get('limit', 10, type=int)
    talkers = monitor.db.get_top_talkers(limit)
    return jsonify(talkers)


@app.route('/api/timeline')
def api_timeline():
    """Get traffic timeline."""
    hours = request.args.get('hours', 24, type=int)
    timeline = monitor.db.get_traffic_timeline(hours)
    return jsonify(timeline)


@app.route('/api/interfaces')
def api_interfaces():
    """Get available network interfaces."""
    interfaces = PacketCapture.get_available_interfaces()
    return jsonify(interfaces)


@app.route('/api/start_capture', methods=['POST'])
def api_start_capture():
    """Start packet capture."""
    data = request.json or {}
    interface = data.get('interface')
    
    success = monitor.start_capture(interface)
    return jsonify({'success': success})


@app.route('/api/stop_capture', methods=['POST'])
def api_stop_capture():
    """Stop packet capture."""
    success = monitor.stop_capture()
    return jsonify({'success': success})


@app.route('/api/load_pcap', methods=['POST'])
def api_load_pcap():
    """Load PCAP file."""
    data = request.json or {}
    filepath = data.get('filepath')
    
    if not filepath:
        return jsonify({'success': False, 'error': 'No filepath provided'})
    
    success = monitor.load_pcap_file(filepath)
    return jsonify({'success': success})


@app.route('/api/train_model', methods=['POST'])
def api_train_model():
    """Train anomaly detection model on current flows."""
    flows = monitor.flow_builder.get_all_active_flows()
    
    if len(flows) < 10:
        return jsonify({
            'success': False,
            'error': 'Not enough flows for training (minimum 10)'
        })
    
    success = monitor.train_on_baseline(flows)
    return jsonify({'success': success})


def run_server(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask server."""
    print(f"Starting dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Run server
    run_server(debug=True)
