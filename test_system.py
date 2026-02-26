"""
Test Script
Comprehensive testing of all system components.
Tests packet capture, flow building, feature extraction, ML models, and rules.
"""

import sys
import os
from datetime import datetime
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import DatabaseManager
from flow_builder import FlowBuilder
from features import FeatureExtractor, generate_synthetic_flows
from model import AnomalyDetector
from rules import RuleBasedDetector
from packet_capture import PacketCapture


class SystemTester:
    """
    Comprehensive system testing suite.
    Tests all components in isolation and integration.
    """
    
    def __init__(self):
        """Initialize test environment."""
        self.results = {
            'passed': 0,
            'failed': 0,
            'errors': []
        }
    
    def log(self, message: str, status: str = "INFO"):
        """Print formatted log message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        symbols = {
            "INFO": "ℹ️",
            "PASS": "✅",
            "FAIL": "❌",
            "WARN": "⚠️"
        }
        symbol = symbols.get(status, "•")
        print(f"[{timestamp}] {symbol} {message}")
    
    def assert_test(self, condition: bool, test_name: str):
        """Assert a test condition."""
        if condition:
            self.log(f"{test_name}: PASSED", "PASS")
            self.results['passed'] += 1
        else:
            self.log(f"{test_name}: FAILED", "FAIL")
            self.results['failed'] += 1
            self.results['errors'].append(test_name)
    
    def test_database(self):
        """Test database operations."""
        self.log("Testing Database Module...", "INFO")
        
        try:
            # Create test database
            db = DatabaseManager('data/test_traffic.db')
            
            # Test flow insertion
            flow_data = {
                'flow_key': 'test_flow_1',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 12345,
                'dst_port': 80,
                'protocol': 'TCP',
                'packet_count': 10,
                'byte_count': 5000,
                'duration': 1.5,
                'avg_packet_size': 500,
                'packets_per_second': 6.67
            }
            
            flow_id = db.insert_flow(flow_data)
            self.assert_test(flow_id > 0, "Database: Insert flow")
            
            # Test anomaly insertion
            anomaly_data = {
                'flow_id': flow_id,
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'anomaly_score': -0.5,
                'anomaly_type': 'test_anomaly',
                'severity': 'high',
                'details': {'test': 'data'}
            }
            
            anomaly_id = db.insert_anomaly(anomaly_data)
            self.assert_test(anomaly_id > 0, "Database: Insert anomaly")
            
            # Test retrieval
            flows = db.get_recent_flows(10)
            self.assert_test(len(flows) > 0, "Database: Retrieve flows")
            
            # Cleanup
            db.reset_database()
            
        except Exception as e:
            self.log(f"Database test error: {e}", "FAIL")
            self.results['failed'] += 1
    
    def test_flow_builder(self):
        """Test flow builder."""
        self.log("Testing Flow Builder Module...", "INFO")
        
        try:
            builder = FlowBuilder()
            
            # Create test packet
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 54321,
                'dst_port': 53,
                'protocol': 'UDP',
                'packet_size': 64,
                'flags': None
            }
            
            # Process packet
            flow = builder.process_packet(packet_info)
            self.assert_test(flow is not None, "FlowBuilder: Process packet")
            self.assert_test(flow['packet_count'] == 1, "FlowBuilder: Packet count")
            
            # Process second packet in same flow
            packet_info2 = packet_info.copy()
            packet_info2['packet_size'] = 128
            flow2 = builder.process_packet(packet_info2)
            
            self.assert_test(flow2['packet_count'] == 2, "FlowBuilder: Flow aggregation")
            
            # Get flow features
            features = builder.get_flow_features(flow['flow_key'])
            self.assert_test(features is not None, "FlowBuilder: Extract features")
            self.assert_test('avg_packet_size' in features, "FlowBuilder: Feature calculation")
            
        except Exception as e:
            self.log(f"FlowBuilder test error: {e}", "FAIL")
            self.results['failed'] += 1
    
    def test_feature_extraction(self):
        """Test feature extraction."""
        self.log("Testing Feature Extraction Module...", "INFO")
        
        try:
            # Generate synthetic flows
            flows = generate_synthetic_flows(100)
            self.assert_test(len(flows) == 100, "Features: Generate synthetic data")
            
            # Create extractor
            extractor = FeatureExtractor()
            
            # Extract features
            features = extractor.fit_transform(flows)
            self.assert_test(features.shape[0] == 100, "Features: Extract batch")
            self.assert_test(features.shape[1] > 0, "Features: Feature count")
            
            # Test single flow
            single_features = extractor.transform_single(flows[0])
            self.assert_test(single_features.shape[0] == 1, "Features: Single flow")
            
            # Test scaler save/load
            extractor.save_scaler('models/test_scaler.pkl')
            
            new_extractor = FeatureExtractor()
            new_extractor.load_scaler('models/test_scaler.pkl')
            self.assert_test(new_extractor.is_fitted, "Features: Scaler persistence")
            
        except Exception as e:
            self.log(f"Feature extraction test error: {e}", "FAIL")
            self.results['failed'] += 1
    
    def test_anomaly_detection(self):
        """Test ML anomaly detection."""
        self.log("Testing Anomaly Detection Module...", "INFO")
        
        try:
            # Generate training data
            train_flows = generate_synthetic_flows(200)
            extractor = FeatureExtractor()
            train_features = extractor.fit_transform(train_flows)
            
            # Train model
            detector = AnomalyDetector(contamination=0.1)
            metrics = detector.train(train_features)
            
            self.assert_test(detector.is_trained, "AnomalyDetector: Training")
            self.assert_test(metrics['n_samples'] == 200, "AnomalyDetector: Training metrics")
            
            # Test prediction
            test_flows = generate_synthetic_flows(50)
            test_features = extractor.transform(test_flows)
            
            predictions, scores = detector.predict(test_features)
            self.assert_test(len(predictions) == 50, "AnomalyDetector: Prediction")
            self.assert_test(len(scores) == 50, "AnomalyDetector: Anomaly scores")
            
            # Test single prediction
            analysis = detector.analyze_flow(test_flows[0], test_features[0:1])
            self.assert_test('is_anomaly' in analysis, "AnomalyDetector: Flow analysis")
            self.assert_test('severity' in analysis, "AnomalyDetector: Severity classification")
            
            # Test model persistence
            detector.save_model('models/test_model.pkl')
            
            new_detector = AnomalyDetector()
            new_detector.load_model('models/test_model.pkl')
            self.assert_test(new_detector.is_trained, "AnomalyDetector: Model persistence")
            
        except Exception as e:
            self.log(f"Anomaly detection test error: {e}", "FAIL")
            self.results['failed'] += 1
    
    def test_rule_based_detection(self):
        """Test rule-based detection."""
        self.log("Testing Rule-Based Detection Module...", "INFO")
        
        try:
            detector = RuleBasedDetector()
            
            # Test port scan detection
            for i in range(30):
                flow = {
                    'src_ip': '10.0.0.100',
                    'dst_ip': '192.168.1.50',
                    'src_port': 50000,
                    'dst_port': 1000 + i,
                    'protocol': 'TCP',
                    'packet_count': 1,
                    'syn_count': 1,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now()
                }
                
                alerts = detector.check_all_rules(flow)
            
            # Should detect port scan
            port_scan_alert = detector.detect_port_scan('10.0.0.100')
            self.assert_test(port_scan_alert is not None, "RuleDetector: Port scan detection")
            
            # Reset detector
            detector.reset()
            
            # Test SYN flood detection
            for i in range(120):
                flow = {
                    'src_ip': '10.0.0.200',
                    'dst_ip': '192.168.1.60',
                    'src_port': 50000 + i,
                    'dst_port': 80,
                    'protocol': 'TCP',
                    'packet_count': 1,
                    'syn_count': 1,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now()
                }
                
                detector.update(flow)
            
            syn_flood_alert = detector.detect_syn_flood('10.0.0.200')
            self.assert_test(syn_flood_alert is not None, "RuleDetector: SYN flood detection")
            
        except Exception as e:
            self.log(f"Rule-based detection test error: {e}", "FAIL")
            self.results['failed'] += 1
    
    def test_packet_capture(self):
        """Test packet capture (basic functionality)."""
        self.log("Testing Packet Capture Module...", "INFO")
        
        try:
            # Test interface listing
            interfaces = PacketCapture.get_available_interfaces()
            self.assert_test(isinstance(interfaces, list), "PacketCapture: List interfaces")
            
            # Test packet parsing
            capture = PacketCapture()
            
            # Create mock packet info
            test_packet_info = {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.1',
                'dst_ip': '8.8.8.8',
                'src_port': 12345,
                'dst_port': 53,
                'protocol': 'UDP',
                'packet_size': 64
            }
            
            # Just verify structure exists
            self.assert_test(hasattr(capture, 'parse_packet'), "PacketCapture: Has parse method")
            self.assert_test(hasattr(capture, 'start_capture'), "PacketCapture: Has start method")
            
        except Exception as e:
            self.log(f"Packet capture test error: {e}", "FAIL")
            self.results['failed'] += 1
    
    def test_integration(self):
        """Test integration of all components."""
        self.log("Testing System Integration...", "INFO")
        
        try:
            # Create all components
            db = DatabaseManager('data/integration_test.db')
            builder = FlowBuilder()
            extractor = FeatureExtractor()
            detector = AnomalyDetector(contamination=0.1)
            rules = RuleBasedDetector()
            
            # Generate training data
            train_flows = generate_synthetic_flows(100)
            train_features = extractor.fit_transform(train_flows)
            detector.train(train_features)
            
            # Simulate packet processing pipeline
            test_packet = {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 54321,
                'dst_port': 80,
                'protocol': 'TCP',
                'packet_size': 1400,
                'flags': 'SYN'
            }
            
            # Process through pipeline
            flow = builder.process_packet(test_packet)
            flow_features = builder.get_flow_features(flow['flow_key'])
            
            # Save to database
            flow_id = db.insert_flow(flow_features)
            
            # ML detection
            features = extractor.transform_single(flow_features)
            analysis = detector.analyze_flow(flow_features, features)
            
            # Rule detection
            alerts = rules.check_all_rules(flow_features)
            
            # Verify pipeline
            self.assert_test(flow_id > 0, "Integration: Packet -> Flow -> DB")
            self.assert_test('is_anomaly' in analysis, "Integration: ML detection")
            self.assert_test(isinstance(alerts, list), "Integration: Rule detection")
            
            # Cleanup
            db.reset_database()
            
        except Exception as e:
            self.log(f"Integration test error: {e}", "FAIL")
            self.results['failed'] += 1
    
    def run_all_tests(self):
        """Run all test suites."""
        print("\n" + "=" * 70)
        print("🧪 NETWORK ANOMALY DETECTOR - COMPREHENSIVE TEST SUITE")
        print("=" * 70 + "\n")
        
        start_time = time.time()
        
        # Run test suites
        self.test_database()
        print()
        
        self.test_flow_builder()
        print()
        
        self.test_feature_extraction()
        print()
        
        self.test_anomaly_detection()
        print()
        
        self.test_rule_based_detection()
        print()
        
        self.test_packet_capture()
        print()
        
        self.test_integration()
        print()
        
        # Print summary
        elapsed = time.time() - start_time
        
        print("=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"✅ Passed: {self.results['passed']}")
        print(f"❌ Failed: {self.results['failed']}")
        print(f"⏱️  Time: {elapsed:.2f}s")
        
        if self.results['failed'] > 0:
            print(f"\n❌ Failed tests:")
            for error in self.results['errors']:
                print(f"   - {error}")
        
        print("=" * 70)
        
        return self.results['failed'] == 0


if __name__ == "__main__":
    # Ensure directories exist
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    # Run tests
    tester = SystemTester()
    success = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)
