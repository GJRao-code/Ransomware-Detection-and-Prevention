import os
import logging
import json
import joblib
import math
import hashlib
import psutil
import re
from datetime import datetime
from app import app, db
from app.models import MLModelMetrics
from app.dataset_generator import DatasetGenerator

# Delay heavy ML imports
def import_ml_libs():
    global pd, StandardScaler, RandomForestClassifier, accuracy_score, precision_score, recall_score, f1_score, LabelEncoder, xgb, IsolationForest, train_test_split
    import pandas as pd
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.model_selection import train_test_split
    import xgboost as xgb
    return pd, StandardScaler, RandomForestClassifier, accuracy_score, precision_score, recall_score, f1_score, LabelEncoder, xgb, IsolationForest, train_test_split


class MLEngine:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.model_paths = {
            'random_forest': 'models/random_forest_model.pkl',
            'xgboost': 'models/xgboost_model.pkl',
            'isolation_forest': 'models/isolation_forest_model.pkl'
        }
        self.scaler_paths = {
            'random_forest': 'models/rf_scaler.pkl',
            'xgboost': 'models/xgb_scaler.pkl',
            'isolation_forest': 'models/if_scaler.pkl'
        }
        self.dataset_generator = DatasetGenerator()
        # Defer heavy model loading/training if models do not exist to keep import lightweight
        try:
            existing = any(os.path.exists(p) for p in self.model_paths.values())
        except Exception:
            existing = False

        if existing:
            # load only when model files are present
            self.load_models()
        else:
            logging.warning("No ML model files found; deferring heavy ML imports until needed")
    
    def load_models(self):
        import_ml_libs()
        """Load pre-trained models if they exist, otherwise train new ones"""
        try:
            for model_name, model_path in self.model_paths.items():
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
                    if os.path.exists(self.scaler_paths[model_name]):
                        self.scalers[model_name] = joblib.load(self.scaler_paths[model_name])
                    logging.info(f"Loaded {model_name} model successfully")
                else:
                    logging.info(f"{model_name} model not found, will train new model")
            
            # If no models exist, train them
            if not self.models:
                self.train_all_models()
        
        except Exception as e:
            logging.error(f"Error loading models: {e}")
            self.train_all_models()
    
    def generate_features(self, file_path, file_content=None):
        """Extract features from a file for ML prediction - Updated for 2025 ransomware detection"""
        try:
            features = {}

            # File-based features
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                features['file_size'] = stat.st_size
                features['file_age'] = (datetime.now().timestamp() - stat.st_mtime) / 86400  # days
                features['is_executable'] = 1 if file_path.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.com', '.pif', '.msi')) else 0
                features['is_script'] = 1 if file_path.lower().endswith(('.js', '.vbs', '.ps1', '.py', '.sh', '.pl', '.rb')) else 0
                features['is_document'] = 1 if file_path.lower().endswith(('.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf')) else 0
                features['has_double_extension'] = 1 if file_path.count('.') > 1 else 0
                features['path_length'] = len(file_path)
                features['filename_length'] = len(os.path.basename(file_path))
            else:
                # Default values for non-existent files
                features.update({
                    'file_size': 0, 'file_age': 0, 'is_executable': 0, 'is_script': 0,
                    'is_document': 0, 'has_double_extension': 0, 'path_length': 0, 'filename_length': 0
                })

            # Enhanced entropy calculation for 2025 ransomware detection
            if file_content or (os.path.exists(file_path) and os.path.getsize(file_path) < 10*1024*1024):  # Max 10MB
                try:
                    if not file_content:
                        with open(file_path, 'rb') as f:
                            file_content = f.read()

                    # Calculate entropy
                    entropy = self.calculate_entropy(file_content)
                    features['entropy'] = entropy
                    features['has_high_entropy'] = 1 if entropy > 7.0 else 0

                    # Enhanced string analysis for 2025 ransomware
                    content_str = file_content.decode('utf-8', errors='ignore') if isinstance(file_content, bytes) else str(file_content)

                    # Check for crypto-related strings (2025 ransomware signatures)
                    crypto_patterns = [
                        r'AES|RSA|DES|3DES|Blowfish|ChaCha|ECDH|PBKDF2',
                        r'encrypt|decrypt|cryptography|openssl|bcrypt',
                        r'key|iv|salt|hash|digest|signature',
                        r'random|secure|nonce|padding|blocksize'
                    ]

                    # Check for ransomware-specific strings
                    ransom_patterns = [
                        r'pay|bitcoin|monero|ether|wallet|address',
                        r'encrypted|locked|restore|recovery|decrypt',
                        r'ransom|payment|contact|email|tor|onion',
                        r'files|documents|photos|backup|important'
                    ]

                    features['has_crypto_strings'] = 1 if any(re.search(pattern, content_str, re.IGNORECASE) for pattern in crypto_patterns) else 0
                    features['has_ransom_strings'] = 1 if any(re.search(pattern, content_str, re.IGNORECASE) for pattern in ransom_patterns) else 0

                    # Calculate string entropy
                    features['string_entropy'] = self.calculate_string_entropy(content_str)

                    # 2025 ransomware-specific features
                    features['encryption_ratio'] = self.calculate_encryption_ratio(file_content)
                    features['file_modification_rate'] = self.calculate_modification_rate(file_path)
                    features['api_calls_count'] = self.count_api_calls(content_str)
                    features['registry_changes'] = self.detect_registry_changes(content_str)
                    features['process_injection'] = self.detect_process_injection(content_str)
                    features['file_extension_spoofing'] = self.detect_extension_spoofing(file_path)
                    features['obfuscation_score'] = self.calculate_obfuscation_score(content_str)

                except Exception as e:
                    logging.warning(f"Error calculating advanced features: {e}")
                    # Set default values
                    features.update({
                        'entropy': 5.0, 'has_high_entropy': 0, 'has_crypto_strings': 0,
                        'has_ransom_strings': 0, 'string_entropy': 4.0, 'encryption_ratio': 0.0,
                        'file_modification_rate': 0.0, 'api_calls_count': 0, 'registry_changes': 0,
                        'process_injection': 0, 'file_extension_spoofing': 0, 'obfuscation_score': 0.0
                    })
            else:
                # Default values for large files or missing content
                features.update({
                    'entropy': 5.0, 'has_high_entropy': 0, 'has_crypto_strings': 0,
                    'has_ransom_strings': 0, 'string_entropy': 4.0, 'encryption_ratio': 0.0,
                    'file_modification_rate': 0.0, 'api_calls_count': 0, 'registry_changes': 0,
                    'process_injection': 0, 'file_extension_spoofing': 0, 'obfuscation_score': 0.0
                })

            # System monitoring features (simulate for file analysis)
            features['hash_known_malware'] = self.check_malware_hash(file_path)
            features['cpu_usage'] = psutil.cpu_percent()
            features['memory_usage'] = psutil.virtual_memory().percent
            features['active_processes'] = len(psutil.pids())
            features['network_connections'] = len(psutil.net_connections())

            return features

        except Exception as e:
            logging.error(f"Error generating features: {e}")
            return self.get_default_features()

    def calculate_encryption_ratio(self, file_content):
        """Calculate encryption ratio based on entropy patterns"""
        try:
            if not file_content:
                return 0.0

            # High entropy regions suggest encryption
            entropy = self.calculate_entropy(file_content)
            return min(1.0, entropy / 8.0)  # Normalize to 0-1 range

        except Exception as e:
            logging.warning(f"Error calculating encryption ratio: {e}")
            return 0.0

    def calculate_modification_rate(self, file_path):
        """Calculate file modification rate (files per second)"""
        try:
            if not os.path.exists(file_path):
                return 0.0

            # Simulate modification rate based on file characteristics
            stat = os.stat(file_path)
            file_age_days = (datetime.now().timestamp() - stat.st_mtime) / 86400

            if file_age_days > 0:
                # Estimate based on file size and age
                modification_rate = stat.st_size / (file_age_days * 86400)
                return min(100.0, modification_rate)  # Cap at 100 files/sec
            return 0.0

        except Exception as e:
            logging.warning(f"Error calculating modification rate: {e}")
            return 0.0

    def count_api_calls(self, content_str):
        """Count potential API calls in content"""
        try:
            # Common API call patterns
            api_patterns = [
                r'\b(CreateFile|ReadFile|WriteFile|DeleteFile)\b',
                r'\b(CryptEncrypt|CryptDecrypt|CryptAcquireContext)\b',
                r'\b(RegCreateKey|RegSetValue|RegDeleteKey)\b',
                r'\b(CreateProcess|OpenProcess|TerminateProcess)\b',
                r'\b(FindFirstFile|FindNextFile|FindClose)\b'
            ]

            api_count = 0
            for pattern in api_patterns:
                matches = re.findall(pattern, content_str, re.IGNORECASE)
                api_count += len(matches)

            return min(1000, api_count)  # Cap at reasonable number

        except Exception as e:
            logging.warning(f"Error counting API calls: {e}")
            return 0

    def detect_registry_changes(self, content_str):
        """Detect potential registry modification patterns"""
        try:
            # Registry-related patterns
            registry_patterns = [
                r'HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT',
                r'RegCreateKey|RegSetValue|RegDeleteKey|RegOpenKey',
                r'SOFTWARE\\Microsoft\\Windows',
                r'System\\CurrentControlSet',
                r'SOFTWARE\\Classes'
            ]

            registry_changes = 0
            for pattern in registry_patterns:
                matches = re.findall(pattern, content_str, re.IGNORECASE)
                registry_changes += len(matches)

            return min(50, registry_changes)  # Cap at reasonable number

        except Exception as e:
            logging.warning(f"Error detecting registry changes: {e}")
            return 0

    def detect_process_injection(self, content_str):
        """Detect potential process injection patterns"""
        try:
            # Process injection patterns
            injection_patterns = [
                r'VirtualAlloc|VirtualProtect|WriteProcessMemory',
                r'CreateRemoteThread|QueueUserAPC|SetThreadContext',
                r'OpenProcess|CreateProcessWithToken|DuplicateHandle',
                r'NtMapViewOfSection|NtCreateSection|NtOpenSection'
            ]

            injection_score = 0
            for pattern in injection_patterns:
                matches = re.findall(pattern, content_str, re.IGNORECASE)
                injection_score += len(matches)

            return 1 if injection_score > 0 else 0

        except Exception as e:
            logging.warning(f"Error detecting process injection: {e}")
            return 0

    def detect_extension_spoofing(self, file_path):
        """Detect file extension spoofing"""
        try:
            if not os.path.exists(file_path):
                return 0

            filename = os.path.basename(file_path).lower()

            # Common spoofing patterns
            spoofing_patterns = [
                r'\.exe\.|\.scr\.|\.bat\.|\.cmd\.|\.com\.',  # Double extensions
                r'\.jpg\.exe|\.png\.exe|\.pdf\.exe|\.doc\.exe',  # Image/document + executable
                r'\.txt\.exe|\.log\.exe|\.ini\.exe',  # Text + executable
                r'\.zip\.exe|\.rar\.exe|\.7z\.exe'  # Archive + executable
            ]

            for pattern in spoofing_patterns:
                if re.search(pattern, filename):
                    return 1

            return 0

        except Exception as e:
            logging.warning(f"Error detecting extension spoofing: {e}")
            return 0

    def calculate_obfuscation_score(self, content_str):
        """Calculate code obfuscation score"""
        try:
            if not content_str:
                return 0.0

            obfuscation_indicators = 0
            total_indicators = 0

            # Check for common obfuscation techniques
            obfuscation_patterns = {
                'string_concatenation': r'["\'][\s]*\+[\s]*["\']',
                'variable_renaming': r'\b[a-zA-Z_][a-zA-Z0-9_]*\b',  # Generic variable pattern
                'control_flow_obfuscation': r'goto|jump|call|ret',
                'encoding_patterns': r'base64|hex|ascii|unicode|utf-?8',
                'compression_patterns': r'compress|zip|gzip|deflate',
                'dynamic_execution': r'eval|exec|function|invoke'
            }

            for indicator, pattern in obfuscation_patterns.items():
                total_indicators += 1
                if re.search(pattern, content_str, re.IGNORECASE):
                    obfuscation_indicators += 1

            # Also check for suspicious string patterns
            suspicious_strings = [
                'powershell', 'cmd.exe', 'regedit', 'taskkill', 'netstat',
                'cipher', 'vssadmin', 'wmic', 'sc', 'bcdedit'
            ]

            for suspicious in suspicious_strings:
                total_indicators += 1
                if suspicious.lower() in content_str.lower():
                    obfuscation_indicators += 1

            return obfuscation_indicators / max(total_indicators, 1)

        except Exception as e:
            logging.warning(f"Error calculating obfuscation score: {e}")
            return 0.0

    def check_malware_hash(self, file_path):
        """Check if file matches known malware hash (updated for 2025)"""
        try:
            if not os.path.exists(file_path):
                return 0

            # Calculate file hash
            hash_md5 = hashlib.md5()
            hash_sha256 = hashlib.sha256()

            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
                    hash_sha256.update(chunk)

            file_hash = hash_md5.hexdigest()

            # 2025 ransomware hashes (simulated - in real implementation, this would be a comprehensive database)
            known_ransomware_hashes = {
                # LockBit 3.0 samples
                'lockbit3_2025': 'a1b2c3d4e5f6789012345678901234567890abcd',
                # BlackCat/ALPHV samples
                'blackcat_2025': 'fedcba0987654321098765432109876543210fedc',
                # RansomHub samples
                'ransomhub_2025': '1234567890abcdef01234567890abcdef01234567'
            }

            return 1 if any(file_hash.lower().startswith(hash.lower()[:8]) for hash in known_ransomware_hashes.values()) else 0

        except Exception as e:
            logging.warning(f"Error checking malware hash: {e}")
            return 0
