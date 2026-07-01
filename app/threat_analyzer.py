import os
import logging
import hashlib
import re
import struct
import math
from datetime import datetime
import psutil
import subprocess

class ThreatAnalyzer:
    def __init__(self):
        self.known_signatures = self.load_threat_signatures()
        self.behavioral_patterns = self.load_behavioral_patterns()
        self.crypto_strings = self.load_crypto_strings()
        self.ransom_strings = self.load_ransom_strings()
    
    def load_threat_signatures(self):
        """Load known threat signatures"""
        return {
            # Known malware signatures (simplified examples)
            'ransomware_patterns': [
                b'\x4d\x5a',  # PE header
                b'encrypt',
                b'decrypt',
                b'ransom',
                b'bitcoin'
            ],
            'malware_patterns': [
                b'virus',
                b'trojan',
                b'backdoor',
                b'keylogger'
            ]
        }
    
    def load_behavioral_patterns(self):
        """Load behavioral analysis patterns"""
        return {
            'file_extensions': {
                'suspicious': ['.exe', '.scr', '.pif', '.bat', '.cmd', '.com'],
                'documents': ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx'],
                'encrypted': ['.encrypted', '.locked', '.crypto', '.aes']
            },
            'registry_keys': [
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            ],
            'network_behavior': {
                'suspicious_ports': [4444, 5555, 6666, 7777, 8888, 9999],
                'tor_ports': [9050, 9051, 9150, 9151],
                'bitcoin_ports': [8333, 18333]
            }
        }
    
    def load_crypto_strings(self):
        """Load cryptographic-related strings"""
        return [
            b'RSA', b'AES', b'DES', b'3DES', b'Blowfish', b'Twofish',
            b'CryptEncrypt', b'CryptDecrypt', b'CryptAcquireContext',
            b'CryptoAPI', b'BCrypt', b'NCrypt', b'advapi32',
            b'encrypt', b'decrypt', b'cipher', b'crypto', b'crypt'
        ]
    
    def load_ransom_strings(self):
        """Load ransomware-related strings"""
        return [
            b'ransom', b'decrypt', b'bitcoin', b'payment', b'unlock',
            b'files encrypted', b'pay', b'restore', b'money',
            b'tor browser', b'onion', b'wallet', b'cryptocurrency',
            b'your files have been encrypted', b'readme', b'howto',
            b'recovery', b'private key', b'public key'
        ]
    
    def signature_detection(self, file_path, file_content=None):
        """Perform signature-based threat detection"""
        try:
            if not file_content and os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read(10240)  # Read first 10KB
                except:
                    file_content = b''
            
            if not file_content:
                return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
            
            threat_score = 0
            detected_signatures = []
            
            # Check for known threat signatures
            for category, signatures in self.known_signatures.items():
                for signature in signatures:
                    if signature in file_content:
                        threat_score += 1
                        detected_signatures.append(f"{category}:{signature.decode('utf-8', errors='ignore')}")
            
            # Check for crypto strings
            crypto_matches = 0
            for crypto_string in self.crypto_strings:
                if crypto_string in file_content:
                    crypto_matches += 1
            
            if crypto_matches > 2:
                threat_score += 2
                detected_signatures.append(f"crypto_strings:{crypto_matches}")
            
            # Check for ransom strings
            ransom_matches = 0
            for ransom_string in self.ransom_strings:
                if ransom_string.lower() in file_content.lower():
                    ransom_matches += 1
            
            if ransom_matches > 0:
                threat_score += 3
                detected_signatures.append(f"ransom_strings:{ransom_matches}")
            
            # Determine threat level
            if threat_score >= 5:
                threat_type = 'ransomware' if ransom_matches > 0 else 'malware'
                confidence = min(0.9, threat_score / 10)
                threat_level = 'critical' if ransom_matches > 2 else 'high'
            elif threat_score >= 2:
                threat_type = 'suspicious'
                confidence = threat_score / 10
                threat_level = 'medium'
            else:
                return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
            
            return {
                'is_threat': True,
                'threat_type': threat_type,
                'threat_level': threat_level,
                'confidence': confidence,
                'detection_method': 'signature',
                'detected_signatures': detected_signatures
            }
        
        except Exception as e:
            logging.error(f"Error in signature detection for {file_path}: {e}")
            return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
    
    def behavioral_analysis(self, file_path, file_content=None):
        """Perform behavioral analysis of file"""
        try:
            behavioral_score = 0
            behavioral_indicators = []
            
            # File extension analysis
            file_ext = os.path.splitext(file_path)[1].lower()
            filename = os.path.basename(file_path).lower()
            
            # Check for suspicious extensions
            if file_ext in self.behavioral_patterns['file_extensions']['suspicious']:
                behavioral_score += 1
                behavioral_indicators.append(f"suspicious_extension:{file_ext}")
            
            # Check for double extensions
            if filename.count('.') > 1:
                behavioral_score += 2
                behavioral_indicators.append("double_extension")
            
            # Check for suspicious filename patterns
            suspicious_names = [
                'readme', 'decrypt', 'ransom', 'payment', 'unlock',
                'recovery', 'howto', 'instructions'
            ]
            
            for suspicious_name in suspicious_names:
                if suspicious_name in filename:
                    behavioral_score += 2
                    behavioral_indicators.append(f"suspicious_name:{suspicious_name}")
            
            # Check for file size anomalies
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                
                # Very small executable files are suspicious
                if file_ext in ['.exe', '.scr'] and file_size < 10240:  # Less than 10KB
                    behavioral_score += 1
                    behavioral_indicators.append("small_executable")
                
                # Very large text files might be encrypted
                if file_ext in ['.txt'] and file_size > 1024*1024:  # Larger than 1MB
                    behavioral_score += 1
                    behavioral_indicators.append("large_text_file")
            
            # Check for process behavior (if running)
            if self.check_suspicious_processes():
                behavioral_score += 2
                behavioral_indicators.append("suspicious_processes")
            
            # Check for network behavior
            if self.check_suspicious_network_activity():
                behavioral_score += 2
                behavioral_indicators.append("suspicious_network")
            
            # Check for registry modifications (Windows only)
            if os.name == 'nt' and self.check_registry_modifications():
                behavioral_score += 3
                behavioral_indicators.append("registry_modifications")
            
            # Determine threat level based on behavioral score
            if behavioral_score >= 6:
                threat_type = 'ransomware'
                confidence = min(0.85, behavioral_score / 10)
                threat_level = 'high'
            elif behavioral_score >= 3:
                threat_type = 'suspicious'
                confidence = behavioral_score / 10
                threat_level = 'medium'
            else:
                return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
            
            return {
                'is_threat': True,
                'threat_type': threat_type,
                'threat_level': threat_level,
                'confidence': confidence,
                'detection_method': 'behavioral',
                'behavioral_indicators': behavioral_indicators
            }
        
        except Exception as e:
            logging.error(f"Error in behavioral analysis for {file_path}: {e}")
            return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
    
    def entropy_analysis(self, file_path, file_content=None):
        """Analyze file entropy to detect encryption"""
        try:
            if not file_content and os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read()
                except:
                    return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
            
            if not file_content:
                return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
            
            # Calculate Shannon entropy
            entropy = self.calculate_shannon_entropy(file_content)
            
            # Analyze entropy patterns
            chunk_entropies = self.calculate_chunk_entropies(file_content)
            avg_chunk_entropy = sum(chunk_entropies) / len(chunk_entropies) if chunk_entropies else 0
            entropy_variance = self.calculate_entropy_variance(chunk_entropies)
            
            # Determine if file is likely encrypted
            is_encrypted = False
            threat_indicators = []
            
            # High entropy indicates encryption
            if entropy > 7.5:
                is_encrypted = True
                threat_indicators.append(f"high_entropy:{entropy:.2f}")
            
            # Low entropy variance in high-entropy file indicates encryption
            if entropy > 7.0 and entropy_variance < 0.5:
                is_encrypted = True
                threat_indicators.append(f"low_entropy_variance:{entropy_variance:.2f}")
            
            # Check for file type mismatch
            file_ext = os.path.splitext(file_path)[1].lower()
            expected_entropy = self.get_expected_entropy(file_ext)
            
            if entropy > expected_entropy + 2.0:
                is_encrypted = True
                threat_indicators.append(f"entropy_mismatch:expected_{expected_entropy:.1f}_actual_{entropy:.2f}")
            
            if is_encrypted:
                # High entropy files are suspicious, especially if they should be low entropy
                confidence = min(0.8, (entropy - 6.0) / 2.0)
                
                # Document files with high entropy are very suspicious
                if file_ext in ['.txt', '.doc', '.pdf', '.xls']:
                    threat_type = 'ransomware'
                    threat_level = 'high'
                    confidence = min(0.9, confidence + 0.2)
                else:
                    threat_type = 'suspicious'
                    threat_level = 'medium'
                
                return {
                    'is_threat': True,
                    'threat_type': threat_type,
                    'threat_level': threat_level,
                    'confidence': confidence,
                    'detection_method': 'entropy',
                    'entropy_score': entropy,
                    'threat_indicators': threat_indicators
                }
            
            return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0, 'entropy_score': entropy}
        
        except Exception as e:
            logging.error(f"Error in entropy analysis for {file_path}: {e}")
            return {'is_threat': False, 'threat_type': 'benign', 'confidence': 0.0}
    
    def calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count frequency of each byte
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def calculate_chunk_entropies(self, data, chunk_size=1024):
        """Calculate entropy for chunks of data"""
        entropies = []
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            if len(chunk) >= 256:  # Only analyze chunks with enough data
                entropy = self.calculate_shannon_entropy(chunk)
                entropies.append(entropy)
        
        return entropies
    
    def calculate_entropy_variance(self, entropies):
        """Calculate variance of entropy values"""
        if len(entropies) < 2:
            return 0.0
        
        mean_entropy = sum(entropies) / len(entropies)
        variance = sum((e - mean_entropy) ** 2 for e in entropies) / len(entropies)
        
        return variance
    
    def get_expected_entropy(self, file_ext):
        """Get expected entropy for different file types"""
        entropy_expectations = {
            '.txt': 4.5,
            '.doc': 5.0,
            '.docx': 6.0,
            '.pdf': 6.5,
            '.xls': 5.5,
            '.xlsx': 6.0,
            '.jpg': 7.5,
            '.png': 7.0,
            '.zip': 7.8,
            '.exe': 6.5,
            '.dll': 6.5
        }
        
        return entropy_expectations.get(file_ext, 6.0)
    
    def check_suspicious_processes(self):
        """Check for suspicious running processes"""
        try:
            suspicious_processes = [
                'encrypt', 'crypto', 'ransom', 'locker', 'cipher',
                'bitcoin', 'wallet', 'miner', 'keylogger'
            ]
            
            for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_name = process.info['name'].lower()
                    cmdline = ' '.join(process.info['cmdline'] or []).lower()
                    
                    for suspicious in suspicious_processes:
                        if suspicious in process_name or suspicious in cmdline:
                            logging.warning(f"Suspicious process detected: {process.info['name']}")
                            return True
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return False
        
        except Exception as e:
            logging.error(f"Error checking suspicious processes: {e}")
            return False
    
    def check_suspicious_network_activity(self):
        """Check for suspicious network activity"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.laddr and conn.raddr:
                    local_port = conn.laddr.port
                    remote_port = conn.raddr.port
                    
                    # Check for suspicious ports
                    suspicious_ports = self.behavioral_patterns['network_behavior']['suspicious_ports']
                    tor_ports = self.behavioral_patterns['network_behavior']['tor_ports']
                    bitcoin_ports = self.behavioral_patterns['network_behavior']['bitcoin_ports']
                    
                    if (local_port in suspicious_ports or remote_port in suspicious_ports or
                        local_port in tor_ports or remote_port in tor_ports or
                        local_port in bitcoin_ports or remote_port in bitcoin_ports):
                        logging.warning(f"Suspicious network activity: {conn}")
                        return True
            
            return False
        
        except Exception as e:
            logging.error(f"Error checking network activity: {e}")
            return False
    
    def check_registry_modifications(self):
        """Check for suspicious registry modifications (Windows only)"""
        try:
            if os.name != 'nt':
                return False
            
            import winreg
            
            # Check common autorun registry keys
            autorun_keys = [
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ]
            
            for hkey, key_path in autorun_keys:
                try:
                    with winreg.OpenKey(hkey, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                
                                # Check for suspicious entries
                                suspicious_patterns = [
                                    'encrypt', 'crypto', 'ransom', 'locker',
                                    'bitcoin', 'wallet', 'recover'
                                ]
                                
                                for pattern in suspicious_patterns:
                                    if pattern in name.lower() or pattern in str(value).lower():
                                        logging.warning(f"Suspicious registry entry: {name} = {value}")
                                        return True
                                
                                i += 1
                            
                            except WindowsError:
                                break
                
                except Exception as e:
                    continue
            
            return False
        
        except Exception as e:
            logging.error(f"Error checking registry modifications: {e}")
            return False
    
    def analyze_pe_file(self, file_path):
        """Analyze PE (Portable Executable) files for suspicious characteristics"""
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return {'is_pe': False}
                
                # Get PE header offset
                pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # Read PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return {'is_pe': False}
                
                # Read COFF header
                coff_header = f.read(20)
                machine, num_sections, timestamp = struct.unpack('<HHL', coff_header[:8])
                
                # Read optional header size
                opt_header_size = struct.unpack('<H', coff_header[16:18])[0]
                
                # Read optional header
                opt_header = f.read(opt_header_size)
                
                # Analyze PE characteristics
                analysis = {
                    'is_pe': True,
                    'machine_type': machine,
                    'num_sections': num_sections,
                    'timestamp': timestamp,
                    'suspicious_score': 0,
                    'indicators': []
                }
                
                # Check for suspicious characteristics
                # Very recent compilation (potential fresh malware)
                if timestamp > datetime.now().timestamp() - 86400:  # Last 24 hours
                    analysis['suspicious_score'] += 1
                    analysis['indicators'].append('recent_compilation')
                
                # Too many sections (might indicate packing)
                if num_sections > 8:
                    analysis['suspicious_score'] += 1
                    analysis['indicators'].append('many_sections')
                
                # Check for suspicious imports (would require more detailed parsing)
                # This is simplified - real implementation would parse import table
                
                return analysis
        
        except Exception as e:
            logging.error(f"Error analyzing PE file {file_path}: {e}")
            return {'is_pe': False, 'error': str(e)}
    
    def check_file_hash_reputation(self, file_hash):
        """Check file hash against threat intelligence databases"""
        # This would integrate with external threat intelligence APIs
        # For now, return a simple check
        
        known_malware_hashes = {
            # Add known malware hashes here
        }
        
        if file_hash.lower() in known_malware_hashes:
            return {
                'is_malicious': True,
                'threat_type': 'known_malware',
                'confidence': 1.0
            }
        
        return {'is_malicious': False}
