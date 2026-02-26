#!/usr/bin/env python3
"""
Quick Start Script
Automated setup and launch for Network Anomaly Detector
"""

import sys
import os
from pathlib import Path
import subprocess
import time

def print_banner():
    """Print welcome banner"""
    print("=" * 70)
    print("  🛡️  NETWORK ANOMALY DETECTOR - QUICK START")
    print("=" * 70)
    print()

def check_python_version():
    """Check Python version"""
    print("Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required. Current version:", sys.version)
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    print()

def install_dependencies():
    """Install required packages"""
    print("Installing dependencies...")
    print("This may take a few minutes...")
    print()
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-q", "-r", "requirements.txt"
        ])
        print("✓ Dependencies installed successfully")
        print()
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        print("Please run: pip install -r requirements.txt")
        sys.exit(1)

def generate_sample_data():
    """Generate sample PCAP file"""
    print("Generating sample network traffic data...")
    
    try:
        from sample_data_generator import generate_sample_dataset
        pcap_file = generate_sample_dataset()
        print(f"✓ Sample data created: {pcap_file}")
        print()
        return pcap_file
    except Exception as e:
        print(f"❌ Failed to generate sample data: {str(e)}")
        return None

def run_tests():
    """Run basic system tests"""
    print("Running system tests...")
    print()
    
    try:
        result = subprocess.run(
            [sys.executable, "test_system.py"],
            capture_output=False,
            timeout=60
        )
        
        if result.returncode == 0:
            print()
            print("✓ All tests passed!")
        else:
            print()
            print("⚠️  Some tests failed, but continuing...")
        print()
    except subprocess.TimeoutExpired:
        print("⚠️  Tests timed out, skipping...")
        print()
    except Exception as e:
        print(f"⚠️  Test error: {str(e)}")
        print()

def start_dashboard():
    """Start the web dashboard"""
    print("=" * 70)
    print("  Starting Web Dashboard...")
    print("=" * 70)
    print()
    print("  Dashboard will open at: http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop")
    print()
    print("  Features:")
    print("    • Real-time traffic monitoring")
    print("    • Anomaly detection alerts")
    print("    • Attack pattern recognition")
    print("    • Network flow analysis")
    print()
    print("=" * 70)
    print()
    
    try:
        subprocess.run([
            sys.executable, "dashboard.py", "--auto-start"
        ])
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    except Exception as e:
        print(f"❌ Dashboard error: {str(e)}")

def main():
    """Main quick start routine"""
    print_banner()
    
    # Change to script directory
    os.chdir(Path(__file__).parent)
    
    # Interactive menu
    print("Quick Start Options:")
    print("  1. Full Setup (Install dependencies + Generate data + Run tests + Start dashboard)")
    print("  2. Start Dashboard Only (Skip setup)")
    print("  3. Run Tests Only")
    print("  4. Generate Sample Data Only")
    print()
    
    choice = input("Select option (1-4) [1]: ").strip() or "1"
    print()
    
    if choice == "1":
        # Full setup
        check_python_version()
        install_dependencies()
        generate_sample_data()
        
        run_test = input("Run system tests? (y/n) [y]: ").strip().lower() or "y"
        if run_test == "y":
            run_tests()
        
        input("Press Enter to start the dashboard...")
        start_dashboard()
        
    elif choice == "2":
        # Dashboard only
        start_dashboard()
        
    elif choice == "3":
        # Tests only
        check_python_version()
        run_tests()
        
    elif choice == "4":
        # Generate data only
        generate_sample_data()
        
    else:
        print("Invalid option")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
