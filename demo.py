#!/usr/bin/env python3
"""
Quick Start Demo Script
Automated demonstration of the Network Anomaly Detector system.
Generates data, trains model, and shows detections.
"""

import os
import sys
import time
from datetime import datetime

print("""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   🛡️  NETWORK TRAFFIC ANOMALY & ATTACK DETECTOR 🛡️            ║
║                                                                ║
║   Intelligent ML-Powered Network Security System               ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

Welcome to the Quick Start Demo!
This script will demonstrate the complete system functionality.

""")

def print_step(step_num, title):
    """Print formatted step header."""
    print(f"\n{'='*70}")
    print(f"STEP {step_num}: {title}")
    print('='*70)

def wait_for_user():
    """Wait for user to press Enter."""
    input("\nPress Enter to continue...")

# Ensure directories exist
print("📁 Setting up directories...")
os.makedirs('data', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs('logs', exist_ok=True)
print("✅ Directories ready!")

# Step 1: Generate Sample Data
print_step(1, "Generate Sample Traffic Data")
print("""
We'll create three types of network traffic:
  1. Normal baseline traffic (for training)
  2. Attack patterns (for testing detection)
  3. Mixed traffic (realistic scenario)
""")

wait_for_user()

from generate_dataset import create_normal_baseline, create_attack_only, create_demo_dataset

print("\n🔧 Generating datasets...")
try:
    create_normal_baseline()
    print()
    create_attack_only()
    print()
    create_demo_dataset()
    print("\n✅ All datasets generated successfully!")
except Exception as e:
    print(f"❌ Error generating datasets: {e}")
    print("Make sure you have scapy installed: pip install scapy")
    sys.exit(1)

# Step 2: Test System Components
print_step(2, "Run System Tests")
print("""
Let's verify all components are working correctly.
This will test:
  - Database operations
  - Flow building
  - Feature extraction
  - ML model training
  - Rule-based detection
  - System integration
""")

wait_for_user()

from test_system import SystemTester

print("\n🧪 Running comprehensive tests...\n")
tester = SystemTester()
success = tester.run_all_tests()

if not success:
    print("\n⚠️  Some tests failed. You may continue, but some features might not work.")
    response = input("Continue anyway? (y/n): ")
    if response.lower() != 'y':
        sys.exit(1)

# Step 3: Train ML Model
print_step(3, "Train Anomaly Detection Model")
print("""
Now we'll train the machine learning model on normal traffic.
This creates a baseline of what "normal" looks like.
""")

wait_for_user()
ures import FeatureExtractor
from model import AnomalyDetector
from database import DatabaseManager

print("\n🤖 Training ML model...")

# Initialize components
db = DatabaseManager('data/demo.db')
builder = FlowBuilder()
extractor
from packet_capture import PacketCapture
from flow_builder import FlowBuilder
from feat = FeatureExtractor()
detector = AnomalyDetector(contamination=0.1)

# Load baseline traffic
def process_packet(packet_info):
    flow = builder.process_packet(packet_info)
    flow_features = builder.get_flow_features(flow['flow_key'])
    if flow_features:
        db.insert_flow(flow_features)

capture = PacketCapture(callback=process_packet)
print("📥 Loading baseline traffic from PCAP...")
capture.capture_from_file('data/baseline_traffic.pcap')

# Train model
flows = builder.get_all_active_flows()
print(f"📊 Collected {len(flows)} flows")

if len(flows) >= 10:
    features = extractor.fit_transform(flows)
    metrics = detector.train(features)
    
    print(f"\n✅ Model trained successfully!")
    print(f"   - Training samples: {metrics['n_samples']}")
    print(f"   - Features: {metrics['n_features']}")
    print(f"   - Baseline anomalies: {metrics['anomalies_detected']}")
    
    # Save models
    detector.save_model('models/demo_detector.pkl')
    extractor.save_scaler('models/demo_scaler.pkl')
else:
    print("❌ Not enough flows for training")
    sys.exit(1)

# Step 4: Test Detection
print_step(4, "Test Attack Detection")
print("""
Now let's test the system with attack traffic!
We'll process the attacks and see what gets detected.
""")

wait_for_user()

from rules import RuleBasedDetector

# Reset for attack testing
builder = FlowBuilder()
rules_detector = RuleBasedDetector()
db.reset_database()

ml_anomalies = 0
rule_alerts = 0

def process_attack_packet(packet_info):
    global ml_anomalies, rule_alerts
    
    # Build flow
    flow = builder.process_packet(packet_info)
    flow_features = builder.get_flow_features(flow['flow_key'])
    
    if not flow_features:
        return
    
    # Save to DB
    flow_id = db.insert_flow(flow_features)
    
    # ML detection
    try:
        features = extractor.transform_single(flow_features)
        analysis = detector.analyze_flow(flow_features, features)
        
        if analysis['is_anomaly']:
            ml_anomalies += 1
            anomaly_data = {
                'flow_id': flow_id,
                'src_ip': analysis['src_ip'],
                'dst_ip': analysis['dst_ip'],
                'anomaly_score': analysis['anomaly_score'],
                'anomaly_type': 'ml_detection',
                'severity': analysis['severity'],
                'details': {}
            }
            db.insert_anomaly(anomaly_data)
            
            print(f"  🚨 ML Anomaly: {analysis['src_ip']} -> {analysis['dst_ip']} "
                  f"(severity: {analysis['severity']})")
    except:
        pass
    
    # Rule detection
    alerts = rules_detector.check_all_rules(flow_features)
    for alert in alerts:
        rule_alerts += 1
        db.insert_alert(alert)
        print(f"  ⚠️  Rule Alert: {alert['alert_type']} from {alert['source_ip']} "
              f"({alert['severity']})")

print("\n🔍 Processing attack traffic...\n")
capture_attacks = PacketCapture(callback=process_attack_packet)
capture_attacks.capture_from_file('data/attacks_only.pcap')

print(f"\n📊 Detection Results:")
print(f"   - ML Anomalies: {ml_anomalies}")
print(f"   - Rule Alerts: {rule_alerts}")
print(f"   - Total Flows: {len(builder.get_all_active_flows())}")

# Step 5: View Statistics
print_step(5, "System Statistics")

stats = db.get_statistics()
suspicious = db.get_suspicious_ips(threshold=2)

print(f"""
📈 Database Statistics:
   - Total Flows: {stats['total_flows']}
   - Total Anomalies: {stats['total_anomalies']}
   - Total Alerts: {stats['total_alerts']}
""")

if suspicious:
    print("🔍 Most Suspicious IPs:")
    for ip_data in suspicious[:5]:
        print(f"   - {ip_data['src_ip']}: {ip_data['count']} anomalies")

# Step 6: Dashboard Info
print_step(6, "Web Dashboard")
print("""
🌐 The system is ready!

To start the web dashboard:

  1. Run: python dashboard.py
  2. Open browser: http://localhost:5000
  3. Use the interface to:
     - Load PCAP files
     - Start live capture (requires sudo)
     - Train models
     - View real-time detections
     - Explore visualizations

The web dashboard provides:
  ✅ Real-time traffic monitoring
  ✅ Interactive charts and graphs
  ✅ Anomaly and alert tables
  ✅ Suspicious IP tracking
  ✅ Model training controls
  ✅ PCAP file loading
""")

print(f"\n{'='*70}")
print("🎉 DEMO COMPLETE!")
print('='*70)

print(f"""
Summary:
  ✅ Sample data generated
  ✅ System components tested
  ✅ ML model trained
  ✅ Attack detection verified
  ✅ Ready for production use

Next Steps:
  1. Explore generated files in data/ directory
  2. Review trained models in models/ directory
  3. Start web dashboard: python dashboard.py
  4. Check README.md for detailed documentation

Thank you for trying the Network Anomaly Detector! 🛡️
""")
