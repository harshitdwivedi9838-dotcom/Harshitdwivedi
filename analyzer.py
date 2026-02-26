"""
Main Analyzer Module
Orchestrates packet capture, flow building, feature extraction, and anomaly detection
"""

import time
import sys
from threading import Thread, Event
from queue import Queue, Empty
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from packet_capture import PacketCapture
from flow_builder import FlowBuilder
from features import FeatureExtractor
from model import AnomalyDetector
from rules import AttackDetector
from database import DatabaseManager
import config
from logger import logger

class NetworkAnalyzer:
    """
    Main orchestrator for network traffic analysis and anomaly detection
    """
    
    def __init__(self, interface=None, pcap_file=None, db_path=None):
        """
        Initialize network analyzer
        
        Args:
            interface: Network interface for live capture
            pcap_file: PCAP file for offline analysis
            db_path: Database path
        """
        # Initialize components
        self.db = DatabaseManager(db_path)
        self.flow_builder = FlowBuilder()
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.attack_detector = AttackDetector()
        
        # Packet capture
        self.packet_queue = Queue(maxsize=config.CAPTURE_CONFIG['capture_buffer_size'])
        self.packet_capture = PacketCapture(
            interface=interface,
            pcap_file=pcap_file,
            packet_queue=self.packet_queue
        )
        
        # Analysis control
        self.is_running = False
        self.stop_event = Event()
        self.analysis_thread = None
        self.cleanup_thread = None
        
        # Statistics
        self.total_packets_analyzed = 0
        self.total_flows_analyzed = 0
        self.total_anomalies_detected = 0
        self.total_attacks_detected = 0
        self.start_time = None
        
        # Training data collection
        self.training_flows = []
        self.min_training_flows = config.ML_CONFIG['min_training_samples']
        self.auto_train_enabled = True
        
        logger.log_system_event("NetworkAnalyzer initialized")
    
    def start(self):
        """Start the analysis system"""
        if self.is_running:
            logger.warning("Analyzer already running")
            return
        
        self.is_running = True
        self.stop_event.clear()
        self.start_time = time.time()
        
        # Start packet capture
        logger.info("Starting packet capture...")
        self.packet_capture.start_capture()
        
        # Start analysis thread
        logger.info("Starting analysis thread...")
        self.analysis_thread = Thread(target=self._analysis_loop)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        
        # Start cleanup thread
        logger.info("Starting cleanup thread...")
        self.cleanup_thread = Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        logger.log_system_event("Network analysis started")
    
    def stop(self):
        """Stop the analysis system"""
        if not self.is_running:
            return
        
        logger.info("Stopping network analyzer...")
        self.is_running = False
        self.stop_event.set()
        
        # Stop packet capture
        self.packet_capture.stop_capture()
        
        # Wait for threads
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        
        # Finalize all flows
        logger.info("Finalizing flows...")
        expired_flows = self.flow_builder.finalize_all_flows()
        for flow in expired_flows:
            self._analyze_flow(flow)
        
        # Log final statistics
        duration = time.time() - self.start_time if self.start_time else 0
        logger.log_system_event(
            "Network analysis stopped",
            f"Duration: {duration:.1f}s, Packets: {self.total_packets_analyzed}, "
            f"Flows: {self.total_flows_analyzed}, Anomalies: {self.total_anomalies_detected}"
        )
    
    def _analysis_loop(self):
        """Main analysis loop - processes packets continuously"""
        logger.info("Analysis loop started")
        
        while not self.stop_event.is_set():
            try:
                # Get packet from queue
                packet = self.packet_queue.get(timeout=1)
                
                # Process packet into flow
                flow = self.flow_builder.process_packet(packet)
                self.total_packets_analyzed += 1
                
                # Log progress
                if self.total_packets_analyzed % 1000 == 0:
                    logger.info(f"Analyzed {self.total_packets_analyzed} packets, "
                              f"{len(self.flow_builder.active_flows)} active flows")
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Analysis loop error: {str(e)}")
    
    def _cleanup_loop(self):
        """Periodic cleanup and flow analysis"""
        logger.info("Cleanup loop started")
        
        cleanup_interval = config.FLOW_CONFIG['flow_cleanup_interval']
        last_cleanup = time.time()
        last_timeline_update = time.time()
        
        while not self.stop_event.is_set():
            try:
                current_time = time.time()
                
                # Cleanup expired flows
                if current_time - last_cleanup >= cleanup_interval:
                    expired_flows = self.flow_builder.cleanup_expired_flows()
                    
                    # Analyze expired flows
                    for flow in expired_flows:
                        self._analyze_flow(flow)
                    
                    last_cleanup = current_time
                
                # Update traffic timeline
                if current_time - last_timeline_update >= 60:  # Every minute
                    self._update_timeline()
                    last_timeline_update = current_time
                
                # Sleep
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Cleanup loop error: {str(e)}")
    
    def _analyze_flow(self, flow):
        """
        Analyze a completed flow for anomalies and attacks
        
        Args:
            flow: Flow object
        """
        try:
            flow_dict = flow.to_dict()
            self.total_flows_analyzed += 1
            
            # Save flow to database
            flow_id = self.db.insert_flow(flow_dict)
            
            # Extract features
            features = self.feature_extractor.extract_features(flow_dict)
            
            # Collect for training if model not trained
            if not self.anomaly_detector.is_trained and self.auto_train_enabled:
                self.training_flows.append(flow_dict)
                
                # Train when we have enough data
                if len(self.training_flows) >= self.min_training_flows:
                    self._train_model()
            
            # Check for anomalies (ML-based)
            if self.anomaly_detector.is_trained:
                normalized_features = self.feature_extractor.normalize_features(features)
                is_anomaly, score = self.anomaly_detector.is_anomaly(normalized_features)
                
                if is_anomaly:
                    self._handle_anomaly(flow_dict, flow_id, score, "ML Model")
            
            # Check for attacks (rule-based)
            attacks = self.attack_detector.analyze_flow(flow_dict)
            for attack in attacks:
                self._handle_attack(attack, flow_id)
            
        except Exception as e:
            logger.error(f"Flow analysis error: {str(e)}")
    
    def _train_model(self):
        """Train the ML model on collected flows"""
        logger.info(f"Training model on {len(self.training_flows)} flows...")
        
        try:
            # Extract features
            feature_matrix = self.feature_extractor.extract_features_batch(self.training_flows)
            
            # Fit scaler
            self.feature_extractor.fit_scaler(self.training_flows)
            
            # Normalize
            normalized_features = self.feature_extractor.normalize_features(feature_matrix)
            
            # Train model
            self.anomaly_detector.train(normalized_features)
            
            logger.info("Model training completed successfully")
            
        except Exception as e:
            logger.error(f"Model training failed: {str(e)}")
    
    def _handle_anomaly(self, flow: dict, flow_id: int, score: float, method: str):
        """
        Handle detected anomaly
        
        Args:
            flow: Flow dictionary
            flow_id: Database flow ID
            score: Anomaly score
            method: Detection method
        """
        self.total_anomalies_detected += 1
        
        # Determine severity based on score
        if score < -0.8:
            severity = 'CRITICAL'
        elif score < -0.6:
            severity = 'HIGH'
        elif score < -0.4:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        # Create anomaly record
        anomaly = {
            'flow_id': flow_id,
            'flow_key': flow['flow_key'],
            'anomaly_score': float(score),
            'detection_method': method,
            'severity': severity,
            'src_ip': flow['src_ip'],
            'dst_ip': flow['dst_ip'],
            'protocol': flow['protocol'],
            'reason': f"Anomalous behavior detected (score: {score:.3f})"
        }
        
        # Save to database
        self.db.insert_anomaly(anomaly)
        
        # Log
        logger.log_anomaly_detected(flow['flow_key'], score, anomaly['reason'])
    
    def _handle_attack(self, attack: dict, flow_id: int = None):
        """
        Handle detected attack
        
        Args:
            attack: Attack dictionary
            flow_id: Optional database flow ID
        """
        self.total_attacks_detected += 1
        
        # Add flow_id if available
        if flow_id:
            attack['flow_id'] = flow_id
        
        # Save to database
        self.db.insert_attack(attack)
        
        # Attack is already logged by AttackDetector
    
    def _update_timeline(self):
        """Update traffic timeline in database"""
        try:
            capture_stats = self.packet_capture.get_statistics()
            flow_stats = self.flow_builder.get_statistics()
            
            self.db.update_traffic_timeline(
                packet_count=capture_stats['total_packets'],
                byte_count=0,  # Could track if needed
                flow_count=flow_stats['total_flows_created'],
                anomaly_count=self.total_anomalies_detected
            )
        except Exception as e:
            logger.error(f"Timeline update error: {str(e)}")
    
    def get_statistics(self) -> dict:
        """
        Get comprehensive system statistics
        
        Returns:
            Statistics dictionary
        """
        duration = time.time() - self.start_time if self.start_time else 0
        
        return {
            'system': {
                'is_running': self.is_running,
                'uptime': duration,
                'packets_analyzed': self.total_packets_analyzed,
                'flows_analyzed': self.total_flows_analyzed,
                'anomalies_detected': self.total_anomalies_detected,
                'attacks_detected': self.total_attacks_detected,
                'packets_per_second': self.total_packets_analyzed / duration if duration > 0 else 0,
            },
            'capture': self.packet_capture.get_statistics(),
            'flows': self.flow_builder.get_statistics(),
            'features': self.feature_extractor.get_statistics(),
            'model': self.anomaly_detector.get_statistics(),
            'attacks': self.attack_detector.get_statistics(),
            'database': self.db.get_statistics_summary(),
        }
    
    def get_recent_anomalies(self, limit=50):
        """Get recent anomalies from database"""
        return self.db.get_recent_anomalies(limit)
    
    def get_recent_attacks(self, limit=50):
        """Get recent attacks from database"""
        return self.db.get_recent_attacks(limit)
    
    def get_suspicious_ips(self, min_anomalies=3):
        """Get suspicious IPs from database"""
        return self.db.get_suspicious_ips(min_anomalies)

if __name__ == "__main__":
    # Test analyzer
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Anomaly Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface')
    parser.add_argument('-f', '--file', help='PCAP file for offline analysis')
    parser.add_argument('-t', '--time', type=int, default=60, 
                       help='Analysis duration in seconds')
    
    args = parser.parse_args()
    
    print("Network Anomaly Analyzer - Test Mode")
    print("=" * 50)
    
    # Create analyzer
    if args.file:
        print(f"Analyzing PCAP file: {args.file}")
        analyzer = NetworkAnalyzer(pcap_file=args.file)
    else:
        interface = args.interface or config.CAPTURE_CONFIG['interface']
        print(f"Analyzing live traffic on interface: {interface}")
        analyzer = NetworkAnalyzer(interface=interface)
    
    # Start analysis
    analyzer.start()
    
    # Run for specified time
    try:
        print(f"\nRunning for {args.time} seconds...")
        print("Press Ctrl+C to stop early\n")
        
        for i in range(args.time):
            time.sleep(1)
            if i % 10 == 0:
                stats = analyzer.get_statistics()
                print(f"[{i}s] Packets: {stats['system']['packets_analyzed']}, "
                      f"Flows: {stats['system']['flows_analyzed']}, "
                      f"Anomalies: {stats['system']['anomalies_detected']}")
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    
    # Stop analysis
    analyzer.stop()
    
    # Print final statistics
    print("\n" + "=" * 50)
    print("Final Statistics:")
    stats = analyzer.get_statistics()
    for category, values in stats.items():
        print(f"\n{category.upper()}:")
        if isinstance(values, dict):
            for key, val in values.items():
                print(f"  {key}: {val}")
