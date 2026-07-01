import pandas as pd
import numpy as np
import os
import logging
import hashlib
import random
from datetime import datetime, timedelta

class DatasetGenerator:
    def __init__(self):
        # Updated feature names for 2025 ransomware detection
        self.feature_names = [
            'file_size', 'file_age', 'is_executable', 'is_script', 'is_document',
            'has_double_extension', 'path_length', 'filename_length', 'entropy',
            'has_high_entropy', 'hash_known_malware', 'cpu_usage', 'memory_usage',
            'active_processes', 'network_connections', 'has_crypto_strings',
            'has_ransom_strings', 'string_entropy', 'encryption_ratio',
            'file_modification_rate', 'api_calls_count', 'registry_changes',
            'process_injection', 'file_extension_spoofing', 'obfuscation_score'
        ]

        self.threat_types = ['benign', 'malware', 'ransomware', 'suspicious']

        # Path to real 2025 dataset
        self.dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                      'datasets', 'ransomware_2025_dataset.csv')

    def generate_training_data(self, num_samples=10000, use_real_data=True):
        """Generate training data - prefer real 2025 dataset if available"""
        try:
            # Try to use real 2025 ransomware dataset first
            if use_real_data and os.path.exists(self.dataset_path):
                logging.info("Loading real 2025 ransomware dataset...")
                return self.load_real_dataset()
            else:
                logging.info("Real dataset not found, generating synthetic data...")
                return self.generate_synthetic_data(num_samples)

        except Exception as e:
            logging.error(f"Error loading real dataset: {e}")
            logging.info("Falling back to synthetic data generation...")
            return self.generate_synthetic_data(num_samples)

    def load_real_dataset(self):
        """Load the real 2025 ransomware dataset"""
        try:
            df = pd.read_csv(self.dataset_path)

            # Separate features and labels
            features = df.drop('label', axis=1) if 'label' in df.columns else df
            labels = df['label'].tolist() if 'label' in df.columns else []

            logging.info(f"Loaded real dataset: {len(df)} samples, {len(features.columns)} features")

            # Update feature names if needed
            if list(features.columns) != self.feature_names:
                logging.warning("Feature names mismatch, updating...")
                features.columns = self.feature_names[:len(features.columns)]

            return features, labels

        except Exception as e:
            logging.error(f"Error loading real dataset: {e}")
            raise

    def generate_synthetic_data(self, num_samples=10000):
        """Generate synthetic training data as fallback"""
        try:
            logging.info(f"Generating {num_samples} synthetic training samples...")

            features = []
            labels = []

            # Generate samples for each threat type
            samples_per_type = num_samples // len(self.threat_types)

            for threat_type in self.threat_types:
                for _ in range(samples_per_type):
                    sample_features = self.generate_sample_features(threat_type)
                    features.append(sample_features)
                    labels.append(threat_type)

            # Create DataFrame
            feature_df = pd.DataFrame(features, columns=self.feature_names)

            logging.info(f"Generated {len(features)} synthetic training samples")
            return feature_df, labels

        except Exception as e:
            logging.error(f"Error generating synthetic training data: {e}")
            return pd.DataFrame(), []

    def generate_sample_features(self, threat_type):
        """Generate features for a specific threat type"""
        if threat_type == 'benign':
            return self.generate_benign_features_2025()
        elif threat_type == 'malware':
            return self.generate_malware_features_2025()
        elif threat_type == 'ransomware':
            return self.generate_ransomware_features_2025()
        elif threat_type == 'suspicious':
            return self.generate_suspicious_features_2025()
        else:
            return self.generate_benign_features_2025()

    def generate_ransomware_features_2025(self):
        """Generate 2025 ransomware-specific features based on latest research"""
        # Choose a random ransomware family for variety
        ransomware_families = [
            'LockBit', 'BlackCat', 'RansomHub', 'Play', 'Cl0p',
            'BlackBasta', 'RansomEXX', 'Conti', 'REvil', 'DarkSide',
            'MedeaLocker', 'Cuba', 'HIVE', 'Yanluowang', 'Karakurt',
            'Ragnarok', 'BianLian', 'Royal', 'Knight', 'Daixin',
            'Trigona', 'Mamba', 'WhiteRabbit', 'Luna', 'Stormous'
        ]
        family = np.random.choice(ransomware_families)

        features = {
            'file_size': np.random.lognormal(mean=np.random.uniform(14, 18), sigma=np.random.uniform(1.2, 2.0)),
            'file_age': np.random.exponential(scale=np.random.uniform(1, 7)),  # Very recent files
            'is_executable': np.random.choice([0, 1], p=[0.15, 0.85]),  # 85% executables
            'is_script': np.random.choice([0, 1], p=[0.7, 0.3]),  # 30% scripts
            'is_document': np.random.choice([0, 1], p=[0.95, 0.05]),  # 5% documents
            'has_double_extension': np.random.choice([0, 1], p=[0.4, 0.6]),  # 60% double extensions
            'path_length': np.random.normal(75, 25),
            'filename_length': np.random.normal(25, 10),
            'entropy': np.random.normal(7.8, 0.6),  # Very high entropy
            'has_high_entropy': np.random.choice([0, 1], p=[0.05, 0.95]),  # 95% high entropy
            'hash_known_malware': np.random.choice([0, 1], p=[0.3, 0.7]),  # 70% known malware
            'cpu_usage': np.random.normal(70, 20),  # High CPU usage
            'memory_usage': np.random.normal(80, 15),  # High memory usage
            'active_processes': np.random.normal(150, 30),  # Many processes
            'network_connections': np.random.normal(35, 15),  # High network activity
            'has_crypto_strings': np.random.choice([0, 1], p=[0.1, 0.9]),  # 90% crypto strings
            'has_ransom_strings': np.random.choice([0, 1], p=[0.05, 0.95]),  # 95% ransom strings
            'string_entropy': np.random.normal(7.2, 0.8),  # High string entropy
            'encryption_ratio': np.random.uniform(0.7, 0.95),  # High encryption ratio
            'file_modification_rate': np.random.uniform(10, 50),  # Files per second
            'api_calls_count': np.random.normal(200, 50),  # High API calls
            'registry_changes': np.random.normal(15, 5),  # Many registry changes
            'process_injection': np.random.choice([0, 1], p=[0.3, 0.7]),  # 70% process injection
            'file_extension_spoofing': np.random.choice([0, 1], p=[0.2, 0.8]),  # 80% spoofing
            'obfuscation_score': np.random.uniform(0.6, 1.0)  # High obfuscation
        }

        # Add family-specific characteristics
        self.add_family_characteristics(features, family)

        return features

    def add_family_characteristics(self, features, family):
        """Add specific characteristics based on ransomware family"""
        family_traits = {
            'LockBit': {'file_size': 1.2, 'encryption_ratio': 1.1, 'network_connections': 1.3},
            'BlackCat': {'obfuscation_score': 1.2, 'api_calls_count': 1.4, 'registry_changes': 1.5},
            'RansomHub': {'file_modification_rate': 1.3, 'process_injection': 1.2, 'string_entropy': 1.1},
            'Play': {'cpu_usage': 1.2, 'memory_usage': 1.1, 'active_processes': 1.2},
            'Cl0p': {'has_double_extension': 1.4, 'file_extension_spoofing': 1.5, 'is_script': 1.2}
        }

        if family in family_traits:
            traits = family_traits[family]
            for trait, multiplier in traits.items():
                if trait in features:
                    features[trait] *= multiplier

    def generate_benign_features_2025(self):
        """Generate updated benign features for 2025"""
        return {
            'file_size': np.random.lognormal(mean=11, sigma=2.2),
            'file_age': np.random.exponential(scale=60),  # Older files
            'is_executable': np.random.choice([0, 1], p=[0.92, 0.08]),  # 8% executables
            'is_script': np.random.choice([0, 1], p=[0.96, 0.04]),  # 4% scripts
            'is_document': np.random.choice([0, 1], p=[0.65, 0.35]),  # 35% documents
            'has_double_extension': np.random.choice([0, 1], p=[0.99, 0.01]),  # 1% double extensions
            'path_length': np.random.normal(45, 12),
            'filename_length': np.random.normal(12, 4),
            'entropy': np.random.normal(5.2, 0.8),  # Lower entropy
            'has_high_entropy': np.random.choice([0, 1], p=[0.95, 0.05]),  # 5% high entropy
            'hash_known_malware': 0,  # Never matches
            'cpu_usage': np.random.normal(20, 8),  # Low CPU usage
            'memory_usage': np.random.normal(40, 12),  # Low memory usage
            'active_processes': np.random.normal(70, 15),  # Normal processes
            'network_connections': np.random.normal(8, 3),  # Low network activity
            'has_crypto_strings': np.random.choice([0, 1], p=[0.9, 0.1]),  # 10% crypto strings
            'has_ransom_strings': np.random.choice([0, 1], p=[0.995, 0.005]),  # 0.5% ransom strings
            'string_entropy': np.random.normal(4.2, 0.6),  # Low string entropy
            'encryption_ratio': np.random.uniform(0.0, 0.1),  # No encryption
            'file_modification_rate': np.random.uniform(0.1, 1.0),  # Normal rate
            'api_calls_count': np.random.normal(50, 15),  # Normal API calls
            'registry_changes': np.random.normal(2, 1),  # Few registry changes
            'process_injection': np.random.choice([0, 1], p=[0.98, 0.02]),  # 2% injection
            'file_extension_spoofing': np.random.choice([0, 1], p=[0.99, 0.01]),  # 1% spoofing
            'obfuscation_score': np.random.uniform(0.0, 0.2)  # Low obfuscation
        }

    def generate_malware_features_2025(self):
        """Generate 2025 malware features (non-ransomware)"""
        return {
            'file_size': np.random.lognormal(mean=13, sigma=1.8),
            'file_age': np.random.exponential(scale=15),
            'is_executable': np.random.choice([0, 1], p=[0.25, 0.75]),
            'is_script': np.random.choice([0, 1], p=[0.5, 0.5]),
            'is_document': np.random.choice([0, 1], p=[0.7, 0.3]),
            'has_double_extension': np.random.choice([0, 1], p=[0.6, 0.4]),
            'path_length': np.random.normal(65, 18),
            'filename_length': np.random.normal(18, 7),
            'entropy': np.random.normal(6.8, 0.9),
            'has_high_entropy': np.random.choice([0, 1], p=[0.3, 0.7]),
            'hash_known_malware': np.random.choice([0, 1], p=[0.8, 0.2]),
            'cpu_usage': np.random.normal(45, 18),
            'memory_usage': np.random.normal(60, 18),
            'active_processes': np.random.normal(110, 25),
            'network_connections': np.random.normal(20, 10),
            'has_crypto_strings': np.random.choice([0, 1], p=[0.4, 0.6]),
            'has_ransom_strings': np.random.choice([0, 1], p=[0.7, 0.3]),
            'string_entropy': np.random.normal(5.8, 1.0),
            'encryption_ratio': np.random.uniform(0.1, 0.4),
            'file_modification_rate': np.random.uniform(2, 8),
            'api_calls_count': np.random.normal(120, 35),
            'registry_changes': np.random.normal(8, 3),
            'process_injection': np.random.choice([0, 1], p=[0.4, 0.6]),
            'file_extension_spoofing': np.random.choice([0, 1], p=[0.3, 0.7]),
            'obfuscation_score': np.random.uniform(0.3, 0.7)
        }

    def generate_suspicious_features_2025(self):
        """Generate 2025 suspicious file features"""
        return {
            'file_size': np.random.lognormal(mean=12, sigma=2.0),
            'file_age': np.random.exponential(scale=20),
            'is_executable': np.random.choice([0, 1], p=[0.4, 0.6]),
            'is_script': np.random.choice([0, 1], p=[0.6, 0.4]),
            'is_document': np.random.choice([0, 1], p=[0.6, 0.4]),
            'has_double_extension': np.random.choice([0, 1], p=[0.5, 0.5]),
            'path_length': np.random.normal(55, 15),
            'filename_length': np.random.normal(16, 6),
            'entropy': np.random.normal(6.2, 1.2),
            'has_high_entropy': np.random.choice([0, 1], p=[0.5, 0.5]),
            'hash_known_malware': np.random.choice([0, 1], p=[0.9, 0.1]),
            'cpu_usage': np.random.normal(30, 12),
            'memory_usage': np.random.normal(50, 15),
            'active_processes': np.random.normal(90, 20),
            'network_connections': np.random.normal(12, 6),
            'has_crypto_strings': np.random.choice([0, 1], p=[0.6, 0.4]),
            'has_ransom_strings': np.random.choice([0, 1], p=[0.8, 0.2]),
            'string_entropy': np.random.normal(5.0, 1.2),
            'encryption_ratio': np.random.uniform(0.2, 0.5),
            'file_modification_rate': np.random.uniform(1, 5),
            'api_calls_count': np.random.normal(80, 25),
            'registry_changes': np.random.normal(5, 2),
            'process_injection': np.random.choice([0, 1], p=[0.6, 0.4]),
            'file_extension_spoofing': np.random.choice([0, 1], p=[0.4, 0.6]),
            'obfuscation_score': np.random.uniform(0.2, 0.6)
        }
