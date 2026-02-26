"""
Machine Learning Model Module
Implements anomaly detection using Isolation Forest algorithm.
Handles training, prediction, and model persistence.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Tuple, Optional
import joblib
import os
from datetime import datetime


class AnomalyDetector:
    """
    ML-based anomaly detector using Isolation Forest.
    Detects unusual network traffic patterns.
    """
    
    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """
        Initialize anomaly detector.
        
        Args:
            contamination: Expected proportion of anomalies (0.0 to 0.5)
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.random_state = random_state
        
        # Initialize Isolation Forest
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,  # Use all CPU cores
            verbose=0
        )
        
        self.is_trained = False
        self.training_date = None
        self.feature_count = None
        
        # Thresholds for severity classification
        self.severity_thresholds = {
            'critical': -0.5,  # Very anomalous
            'high': -0.3,
            'medium': -0.1,
            'low': 0.0
        }
    
    def train(self, features: np.ndarray) -> Dict:
        """
        Train the anomaly detection model.
        
        Args:
            features: Normalized feature matrix (n_samples, n_features)
            
        Returns:
            Training metrics dictionary
        """
        if len(features) == 0:
            raise ValueError("Cannot train on empty feature set")
        
        print(f"Training Isolation Forest on {len(features)} samples...")
        
        # Store feature count for validation
        self.feature_count = features.shape[1]
        
        # Train model
        self.model.fit(features)
        self.is_trained = True
        self.training_date = datetime.now()
        
        # Calculate training metrics
        scores = self.model.score_samples(features)
        predictions = self.model.predict(features)
        
        metrics = {
            'n_samples': len(features),
            'n_features': features.shape[1],
            'contamination': self.contamination,
            'anomalies_detected': int(np.sum(predictions == -1)),
            'anomaly_rate': float(np.mean(predictions == -1)),
            'mean_score': float(np.mean(scores)),
            'std_score': float(np.std(scores)),
            'min_score': float(np.min(scores)),
            'max_score': float(np.max(scores)),
            'training_date': self.training_date.isoformat()
        }
        
        print(f"Training complete. Detected {metrics['anomalies_detected']} anomalies "
              f"({metrics['anomaly_rate']*100:.1f}%)")
        
        return metrics
    
    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies for new data.
        
        Args:
            features: Normalized feature matrix
            
        Returns:
            Tuple of (predictions, anomaly_scores)
            predictions: -1 for anomaly, 1 for normal
            anomaly_scores: Anomaly scores (lower = more anomalous)
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        if features.shape[1] != self.feature_count:
            raise ValueError(f"Feature count mismatch. Expected {self.feature_count}, "
                           f"got {features.shape[1]}")
        
        predictions = self.model.predict(features)
        scores = self.model.score_samples(features)
        
        return predictions, scores
    
    def predict_single(self, features: np.ndarray) -> Tuple[int, float]:
        """
        Predict anomaly for a single sample.
        
        Args:
            features: Single normalized feature vector
            
        Returns:
            Tuple of (prediction, anomaly_score)
        """
        predictions, scores = self.predict(features)
        return int(predictions[0]), float(scores[0])
    
    def classify_severity(self, anomaly_score: float) -> str:
        """
        Classify anomaly severity based on score.
        
        Args:
            anomaly_score: Anomaly score from model
            
        Returns:
            Severity level: 'critical', 'high', 'medium', 'low', or 'normal'
        """
        if anomaly_score < self.severity_thresholds['critical']:
            return 'critical'
        elif anomaly_score < self.severity_thresholds['high']:
            return 'high'
        elif anomaly_score < self.severity_thresholds['medium']:
            return 'medium'
        elif anomaly_score < self.severity_thresholds['low']:
            return 'low'
        else:
            return 'normal'
    
    def analyze_flow(self, flow: Dict, features: np.ndarray) -> Dict:
        """
        Comprehensive analysis of a single flow.
        
        Args:
            flow: Flow dictionary
            features: Normalized feature vector
            
        Returns:
            Analysis results dictionary
        """
        if not self.is_trained:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'severity': 'unknown',
                'error': 'Model not trained'
            }
        
        prediction, score = self.predict_single(features)
        severity = self.classify_severity(score)
        
        analysis = {
            'flow_key': flow.get('flow_key'),
            'src_ip': flow.get('src_ip'),
            'dst_ip': flow.get('dst_ip'),
            'protocol': flow.get('protocol'),
            'is_anomaly': prediction == -1,
            'anomaly_score': score,
            'severity': severity,
            'packet_count': flow.get('packet_count', 0),
            'byte_count': flow.get('byte_count', 0),
            'duration': flow.get('duration', 0),
            'packets_per_second': flow.get('packets_per_second', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        # Add explanatory features for anomalies
        if prediction == -1:
            analysis['anomaly_indicators'] = self._identify_anomaly_indicators(flow)
        
        return analysis
    
    def _identify_anomaly_indicators(self, flow: Dict) -> List[str]:
        """Identify which features make this flow anomalous."""
        indicators = []
        
        # High packet rate
        if flow.get('packets_per_second', 0) > 1000:
            indicators.append('high_packet_rate')
        
        # Large byte count
        if flow.get('byte_count', 0) > 1000000:
            indicators.append('high_byte_count')
        
        # Many packets
        if flow.get('packet_count', 0) > 10000:
            indicators.append('high_packet_count')
        
        # Short duration with many packets
        if flow.get('duration', 1) < 1.0 and flow.get('packet_count', 0) > 100:
            indicators.append('burst_traffic')
        
        # Unusual port
        dst_port = flow.get('dst_port', 0)
        if dst_port and dst_port not in [80, 443, 22, 53, 21, 25, 110, 143]:
            indicators.append('unusual_port')
        
        # Many SYN packets (potential SYN flood)
        if flow.get('syn_count', 0) > 50:
            indicators.append('excessive_syn')
        
        return indicators
    
    def save_model(self, filepath: str):
        """Save trained model to disk."""
        if not self.is_trained:
            print("Warning: Saving untrained model")
        
        model_data = {
            'model': self.model,
            'is_trained': self.is_trained,
            'training_date': self.training_date,
            'feature_count': self.feature_count,
            'contamination': self.contamination,
            'random_state': self.random_state,
            'severity_thresholds': self.severity_thresholds
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.is_trained = model_data['is_trained']
        self.training_date = model_data['training_date']
        self.feature_count = model_data['feature_count']
        self.contamination = model_data.get('contamination', 0.1)
        self.random_state = model_data.get('random_state', 42)
        self.severity_thresholds = model_data.get('severity_thresholds', self.severity_thresholds)
        
        print(f"Model loaded from {filepath}")
        print(f"Trained on {self.training_date}")
    
    def get_model_info(self) -> Dict:
        """Get information about the current model."""
        return {
            'is_trained': self.is_trained,
            'training_date': self.training_date.isoformat() if self.training_date else None,
            'feature_count': self.feature_count,
            'contamination': self.contamination,
            'n_estimators': self.model.n_estimators,
            'max_samples': self.model.max_samples
        }


# Example usage
if __name__ == "__main__":
    from features import generate_synthetic_flows, FeatureExtractor
    
    print("Generating synthetic training data...")
    train_flows = generate_synthetic_flows(1000)
    
    # Extract features
    print("Extracting features...")
    extractor = FeatureExtractor()
    train_features = extractor.fit_transform(train_flows)
    
    # Train model
    print("\nTraining anomaly detector...")
    detector = AnomalyDetector(contamination=0.1)
    metrics = detector.train(train_features)
    
    print(f"\nTraining Metrics:")
    print(f"  Samples: {metrics['n_samples']}")
    print(f"  Features: {metrics['n_features']}")
    print(f"  Anomalies: {metrics['anomalies_detected']}")
    print(f"  Mean score: {metrics['mean_score']:.3f}")
    
    # Test prediction
    print("\nTesting prediction on new data...")
    test_flows = generate_synthetic_flows(100)
    test_features = extractor.transform(test_flows)
    
    predictions, scores = detector.predict(test_features)
    anomaly_count = np.sum(predictions == -1)
    
    print(f"Detected {anomaly_count} anomalies in {len(test_flows)} flows")
    
    # Analyze a single flow
    print("\nAnalyzing single flow...")
    analysis = detector.analyze_flow(test_flows[0], test_features[0:1])
    print(f"Flow analysis:")
    print(f"  Anomaly: {analysis['is_anomaly']}")
    print(f"  Score: {analysis['anomaly_score']:.3f}")
    print(f"  Severity: {analysis['severity']}")
    
    # Save model
    print("\nSaving model...")
    detector.save_model('models/anomaly_detector.pkl')
