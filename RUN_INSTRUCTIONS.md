# 🚀 RUN INSTRUCTIONS - Network Anomaly Detector

## Quick Start (Recommended)

```bash
# Option 1: Automated setup
python quickstart.py

# Option 2: Manual setup
pip install -r requirements.txt
python sample_data_generator.py
python dashboard.py --auto-start
```

Then open browser: **http://127.0.0.1:5000**

---

## Detailed Instructions

### Prerequisites
- Python 3.8+ installed
- Terminal/Command Prompt access
- (Optional) Root/sudo access for live packet capture

### Step 1: Install Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install packages
pip install -r requirements.txt
```

Expected output:
```
Successfully installed scapy-2.5.0 scikit-learn-1.3.2 numpy-1.24.3 Flask-3.0.0 ...
```

### Step 2: Generate Test Data

```bash
python sample_data_generator.py
```

Expected output:
```
Sample Network Traffic Generator
============================================================
1. Generating normal HTTP/HTTPS traffic...
2. Generating DNS queries...
...
✓ Sample dataset created: data/sample_traffic.pcap
  Total packets: 1500
```

### Step 3: Run System Tests (Optional)

```bash
python test_system.py
```

Expected output:
```
████████████████████████████████████████████████████████████
  NETWORK ANOMALY DETECTOR - COMPREHENSIVE TEST SUITE
████████████████████████████████████████████████████████████

✓ PASS - Configuration
✓ PASS - Logging
...
Results: 9/9 tests passed (100.0%)
🎉 ALL TESTS PASSED!
```

### Step 4: Start the Dashboard

```bash
# With auto-start (uses demo data)
python dashboard.py --auto-start

# Or manual start
python dashboard.py
```

Expected output:
```
============================================================
Network Anomaly Detection Dashboard
============================================================
Dashboard URL: http://127.0.0.1:5000
Press Ctrl+C to stop
============================================================
```

### Step 5: Use the Dashboard

1. **Open browser**: Navigate to `http://127.0.0.1:5000`

2. **Start Analysis**: Click "▶ Start Analysis" button

3. **Monitor Traffic**:
   - View real-time statistics (packets, flows, anomalies)
   - Check Recent Anomalies table
   - Monitor Attack Detections
   - Review Suspicious IPs
   - Analyze Network Flows

4. **Stop Analysis**: Click "⏹ Stop Analysis" button when done

---

## Alternative Run Modes

### Mode 1: Command-Line Analysis (Offline PCAP)

```bash
cd modules
python analyzer.py -f ../data/sample_traffic.pcap -t 60
```

This will:
- Load the PCAP file
- Analyze traffic for 60 seconds
- Print statistics every 10 seconds
- Display final results

### Mode 2: Live Packet Capture (Requires Root)

```bash
# List available network interfaces
python -c "from modules.packet_capture import PacketCapture; print(PacketCapture.get_available_interfaces())"

# Capture from specific interface (replace eth0 with your interface)
sudo python modules/analyzer.py -i eth0 -t 120
```

**Note**: Live capture requires root/administrator privileges.

### Mode 3: Custom Dashboard Configuration

```bash
# Use custom host and port
python dashboard.py --host 0.0.0.0 --port 8080

# Enable debug mode
python dashboard.py --debug
```

---

## Testing Individual Modules

Each module can be tested independently:

```bash
cd modules

# Test packet capture
python packet_capture.py

# Test flow building
python flow_builder.py

# Test feature extraction
python features.py

# Test ML model
python model.py

# Test attack detection
python rules.py

# Test database
python database.py
```

---

## Generating Custom Test Data

```bash
# Generate custom PCAP with specific attacks
python sample_data_generator.py \
  --normal 1000 \
  --port-scan \
  --syn-flood \
  -o custom_test.pcap
```

Parameters:
- `--normal N`: Generate N normal packets
- `--port-scan`: Include port scan attack
- `--syn-flood`: Include SYN flood attack
- `-o FILE`: Output filename

---

## Configuration Customization

Edit `config.py` to customize:

```python
# Example: Change flow timeout
FLOW_CONFIG = {
    'flow_timeout': 180,  # 3 minutes instead of 2
}

# Example: Adjust anomaly detection sensitivity
ML_CONFIG = {
    'contamination': 0.05,  # Expect 5% anomalies instead of 10%
    'anomaly_threshold': -0.6,  # Stricter threshold
}

# Example: Tune port scan detection
RULES_CONFIG = {
    'port_scan': {
        'unique_ports_threshold': 15,  # Alert after 15 ports (was 20)
    }
}
```

After changes, restart the dashboard.

---

## Troubleshooting

### Issue: "Permission denied" when capturing

**Solution**: Run with sudo/root privileges:
```bash
sudo python modules/analyzer.py -i eth0
```

Or use offline PCAP file mode (no privileges needed).

### Issue: "Module not found" errors

**Solution**: Install dependencies:
```bash
pip install -r requirements.txt
```

### Issue: Port 5000 already in use

**Solution**: Use different port:
```bash
python dashboard.py --port 8080
```

### Issue: No packets captured

**Solutions**:
1. Check interface name is correct
2. Ensure interface is up and has traffic
3. Try capturing on all interfaces (Linux):
   ```bash
   sudo python modules/analyzer.py -i any
   ```

### Issue: Scapy installation fails

**Solution**: Install system dependencies first:

**Ubuntu/Debian**:
```bash
sudo apt-get install python3-dev libpcap-dev
pip install scapy
```

**macOS**:
```bash
brew install libpcap
pip install scapy
```

**Windows**:
- Install Npcap from: https://npcap.com/
- Then: `pip install scapy`

### Issue: Database locked errors

**Solution**: Stop all running instances and delete database:
```bash
rm data/network_traffic.db
```

---

## Expected Performance

On typical hardware (4-core CPU, 8GB RAM):

- **Packet Processing**: 1,000-5,000 packets/second
- **Active Flows**: Up to 10,000 concurrent flows
- **Memory Usage**: ~100-200 MB
- **Disk Usage**: ~10 MB for 100,000 packets
- **ML Training Time**: 1-5 seconds for 100 samples

---

## Directory Structure After Running

```
network_anomaly_detector/
├── modules/              # Python modules
├── templates/            # HTML templates
├── data/                 # Data directory (created)
│   ├── network_traffic.db      # SQLite database
│   ├── sample_traffic.pcap     # Sample PCAP
│   └── *.pcap                  # Other PCAP files
├── logs/                 # Log files (created)
│   └── network_detector.log    # Application log
├── models/               # ML models (created)
│   └── isolation_forest.pkl    # Trained model
├── config.py
├── dashboard.py
├── quickstart.py
├── test_system.py
├── sample_data_generator.py
├── requirements.txt
└── README.md
```

---

## Next Steps

After successful setup:

1. **Experiment with Configuration**
   - Adjust detection thresholds in `config.py`
   - Try different ML parameters
   - Modify attack detection rules

2. **Analyze Real Traffic**
   - Capture from your network interface
   - Import existing PCAP files
   - Test with different traffic patterns

3. **Extend Functionality**
   - Add new attack detectors to `modules/rules.py`
   - Implement additional ML models
   - Create custom visualizations

4. **Integration**
   - Export data to SIEM systems
   - Set up automated alerts
   - Build custom reporting

---

## Support & Documentation

- Full documentation: `README.md`
- Module documentation: Check docstrings in each `.py` file
- Configuration reference: `config.py`
- Test examples: `test_system.py`

---

## Clean Up

To remove all generated data:

```bash
# Remove database
rm data/network_traffic.db

# Remove logs
rm -rf logs/*

# Remove models
rm -rf models/*

# Remove generated PCAP files
rm data/*.pcap
```

---

**Enjoy using the Network Anomaly Detector! 🛡️**
