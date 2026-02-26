"""
Feature Extraction Module
Converts network flows into normalized feature vectors for machine learning.
Handles feature scaling, encoding, and selection.
"""

import numpy as np
from typing import Dict, List, Tuple
from sklearn.preprocessing import StandardScaler, MinMaxScaler
import joblib
import os


class FeatureExtractor:
    """
    Extracts and normalizes features from network flows for ML models.
    Maintains consistent feature representation across training and inference.
    """
    
    # Define feature columns
    NUMERIC_FEATURES = [
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
        'is_well_known_port'
    ]
    
    PROTOCOL_MAPPING = {
        'TCP': 0,
        'UDP': 1,
        'ICMP': 2,
        'OTHER': 3
    }
    
    def __init__(self, scaler_type: str = 'standard'):
        """
        Initialize feature extractor.
        
        Args:
            scaler_type: Type of scaler ('standard' or 'minmax')
        """
        self.scaler_type = scaler_type
        self.scaler = None
        self.is_fitted = False
        
        if scaler_type == 'standard':
            self.scaler = StandardScaler()
        else:
            self.scaler = MinMaxScaler()
    
    def extract_features(self, flow: Dict) -> np.ndarray:
        """
        Extract feature vector from a single flow.
        
        Args:
            flow: Flow dictionary with statistics
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # Extract numeric features
        for feature_name in self.NUMERIC_FEATURES:
            value = flow.get(feature_name, 0)
            
            # Handle None values
            if value is None:
                value = 0
            
            # Add safety checks for derived features
            if feature_name in ['packets_per_second', 'bytes_per_second']:
                if flow.get('duration', 0) <= 0:
                    value = 0
            
            features.append(float(value))
        
        # Encode protocol
        protocol = flow.get('protocol', 'OTHER')
        protocol_code = self.PROTOCOL_MAPPING.get(protocol, 3)
        features.append(float(protocol_code))
        
        return np.array(features).reshape(1, -1)
    
    def extract_batch_features(self, flows: List[Dict]) -> np.ndarray:
        """
        Extract features from multiple flows.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            2D numpy array of features
        """
        if not flows:
            return np.array([])
        
        feature_list = []
        for flow in flows:
            features = self.extract_features(flow)
            feature_list.append(features[0])
        
        return np.array(feature_list)
    
    def fit_scaler(self, flows: List[Dict]):
        """
        Fit the scaler on training data.
        
        Args:
            flows: List of flow dictionaries for training
        """
        features = self.extract_batch_features(flows)
        
        if len(features) > 0:
            # Replace inf and nan values
            features = np.nan_to_num(features, nan=0.0, posinf=1e10, neginf=-1e10)
            
            self.scaler.fit(features)
            self.is_fitted = True
            print(f"Scaler fitted on {len(flows)} flows")
    
    def transform(self, flows: List[Dict]) -> np.ndarray:
        """
        Transform flows into normalized features.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            Normalized feature matrix
        """
        if not self.is_fitted:
            raise ValueError("Scaler not fitted. Call fit_scaler() first.")
        
        features = self.extract_batch_features(flows)
        
        if len(features) == 0:
            return np.array([])
        
        # Replace inf and nan values
        features = np.nan_to_num(features, nan=0.0, posinf=1e10, neginf=-1e10)
        
        # Transform
        normalized = self.scaler.transform(features)
        return normalized
    
    def fit_transform(self, flows: List[Dict]) -> np.ndarray:
        """
        Fit scaler and transform in one step.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            Normalized feature matrix
        """
        self.fit_scaler(flows)
        return self.transform(flows)
    
    def transform_single(self, flow: Dict) -> np.ndarray:
        """
        Transform a single flow (for real-time prediction).
        
        Args:
            flow: Single flow dictionary
            
        Returns:
            Normalized feature vector
        """
        return self.transform([flow])
    
    def save_scaler(self, filepath: str):
        """Save the fitted scaler to disk."""
        if not self.is_fitted:
            print("Warning: Saving unfitted scaler")
        
        scaler_data = {
            'scaler': self.scaler,
            'scaler_type': self.scaler_type,
            'is_fitted': self.is_fitted
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(scaler_data, filepath)
        print(f"Scaler saved to {filepath}")
    
    def load_scaler(self, filepath: str):
        """Load a fitted scaler from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Scaler file not found: {filepath}")
        
        scaler_data = joblib.load(filepath)
        self.scaler = scaler_data['scaler']
        self.scaler_type = scaler_data['scaler_type']
        self.is_fitted = scaler_data['is_fitted']
        
        print(f"Scaler loaded from {filepath}")
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names in order."""
        return self.NUMERIC_FEATURES + ['protocol_encoded']
    
    def get_feature_importance(self, flows: List[Dict]) -> Dict[str, float]:
        """
        Calculate basic feature statistics for analysis.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            Dictionary with feature statistics
        """
        features = self.extract_batch_features(flows)
        
        if len(features) == 0:
            return {}
        
        feature_names = self.get_feature_names()
        importance = {}
        
        for i, name in enumerate(feature_names):
            col = features[:, i]
            importance[name] = {
                'mean': float(np.mean(col)),
                'std': float(np.std(col)),
                'min': float(np.min(col)),
                'max': float(np.max(col))
            }
        
        return importance


def generate_synthetic_flows(n_flows: int = 100) -> List[Dict]:
    """
    Generate synthetic flow data for testing.
    
    Args:
        n_flows: Number of flows to generate
        
    Returns:
        List of synthetic flow dictionaries
    """
    from datetime import datetime, timedelta
    import random
    
    flows = []
    base_time = datetime.now()
    
    for i in range(n_flows):
        # Normal traffic characteristics
        if i < n_flows * 0.9:  # 90% normal
            packet_count = random.randint(5, 100)
            byte_count = random.randint(500, 50000)
            duration = random.uniform(0.1, 60.0)
        else:  # 10% anomalous
            packet_count = random.randint(500, 5000)  # High packet count
            byte_count = random.randint(50000, 500000)  # High byte count
            duration = random.uniform(0.01, 1.0)  # Short duration
        
        flow = {
            'flow_key': f'flow_{i}',
            'src_ip': f'192.168.1.{random.randint(1, 254)}',
            'dst_ip': f'10.0.0.{random.randint(1, 254)}',
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 53, 21]),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'packet_count': packet_count,
            'byte_count': byte_count,
            'duration': duration,
            'avg_packet_size': byte_count / packet_count,
            'packets_per_second': packet_count / duration,
            'bytes_per_second': byte_count / duration,
            'syn_count': random.randint(0, 5),
            'fin_count': random.randint(0, 2),
            'rst_count': random.randint(0, 1),
            'is_well_known_port': 1 if random.random() > 0.3 else 0,
            'first_seen': base_time + timedelta(seconds=i),
            'last_seen': base_time + timedelta(seconds=i + duration)
        }
        
        flows.append(flow)
    
    return flows


# Example usage
if __name__ == "__main__":
    # Generate synthetic data
    print("Generating synthetic flows...")
    flows = generate_synthetic_flows(100)
    
    # Create feature extractor
    extractor = FeatureExtractor(scaler_type='standard')
    
    # Extract and normalize features
    print("\nExtracting features...")
    normalized_features = extractor.fit_transform(flows)
    
    print(f"Feature matrix shape: {normalized_features.shape}")
    print(f"Feature names: {extractor.get_feature_names()}")
    
    # Show feature statistics
    print("\nFeature importance:")
    importance = extractor.get_feature_importance(flows)
    for name, stats in list(importance.items())[:5]:
        print(f"  {name}: mean={stats['mean']:.2f}, std={stats['std']:.2f}")
    
    # Test single flow transformation
    print("\nTesting single flow transformation...")
    single_flow = flows[0]
    single_features = extractor.transform_single(single_flow)
    print(f"Single flow features shape: {single_features.shape}")
    
    # Save scaler
    print("\nSaving scaler...")
    extractor.save_scaler('models/feature_scaler.pkl')
