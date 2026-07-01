import os
import shutil
import logging
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

class QuarantineManager:
    def __init__(self):
        self.quarantine_dir = "quarantine"
        self.metadata_file = os.path.join(self.quarantine_dir, "quarantine_metadata.json")
        self.setup_quarantine_directory()
        self.metadata = self.load_metadata()
    
    def setup_quarantine_directory(self):
        """Setup quarantine directory structure"""
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            
            # Create subdirectories for different threat types
            subdirs = ['ransomware', 'malware', 'suspicious', 'restored']
            for subdir in subdirs:
                os.makedirs(os.path.join(self.quarantine_dir, subdir), exist_ok=True)
            
            logging.info(f"Quarantine directory setup completed: {self.quarantine_dir}")
        
        except Exception as e:
            logging.error(f"Error setting up quarantine directory: {e}")
    
    def load_metadata(self):
        """Load quarantine metadata"""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            return {}
        
        except Exception as e:
            logging.error(f"Error loading quarantine metadata: {e}")
            return {}
    
    def save_metadata(self):
        """Save quarantine metadata"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2, default=str)
        
        except Exception as e:
            logging.error(f"Error saving quarantine metadata: {e}")
    
    def quarantine_file(self, file_path, threat_record):
        """Quarantine a suspicious/malicious file"""
        try:
            if not os.path.exists(file_path):
                logging.warning(f"File to quarantine does not exist: {file_path}")
                return False
            
            # Generate unique quarantine filename
            file_hash = self.calculate_file_hash(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            original_name = os.path.basename(file_path)
            quarantine_name = f"{timestamp}_{file_hash[:8]}_{original_name}"
            
            # Determine quarantine subdirectory based on threat type
            threat_type = getattr(threat_record, 'threat_type', 'suspicious')
            subdir = threat_type if threat_type in ['ransomware', 'malware', 'suspicious'] else 'suspicious'
            quarantine_path = os.path.join(self.quarantine_dir, subdir, quarantine_name)
            
            # Copy file to quarantine (preserve original for forensics)
            shutil.copy2(file_path, quarantine_path)
            
            # Store metadata
            metadata = {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'threat_type': threat_type,
                'threat_level': getattr(threat_record, 'threat_level', 'unknown'),
                'confidence_score': getattr(threat_record, 'confidence_score', 0.0),
                'detection_method': getattr(threat_record, 'detection_method', 'unknown'),
                'file_hash': file_hash,
                'file_size': os.path.getsize(file_path),
                'quarantine_time': datetime.now().isoformat(),
                'status': 'quarantined'
            }
            
            self.metadata[file_hash] = metadata
            self.save_metadata()
            
            # Update threat record with file_hash and quarantine_path
            if hasattr(threat_record, 'file_hash'):
                threat_record.file_hash = file_hash
            if hasattr(threat_record, 'quarantine_path'):
                threat_record.quarantine_path = quarantine_path
            
            # Remove original file (optional - could be configured)
            try:
                os.remove(file_path)
                logging.info(f"Original file removed: {file_path}")
            except Exception as e:
                logging.warning(f"Could not remove original file {file_path}: {e}")
            
            logging.info(f"File quarantined successfully: {file_path} -> {quarantine_path}")
            return True
        
        except Exception as e:
            logging.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def restore_file(self, threat_record):
        """Restore a quarantined file to its original location"""
        try:
            file_hash = getattr(threat_record, 'file_hash', None)
            if not file_hash:
                logging.error(f"Threat record {threat_record.id} has no file_hash attribute")
                logging.error(f"Threat file_path: {threat_record.file_path}")
                logging.error(f"Threat is_quarantined: {threat_record.is_quarantined}")
                return False
            
            # Reload metadata in case it was cleared
            self.metadata = self.load_metadata()
            
            if file_hash not in self.metadata:
                logging.error(f"File hash not found in quarantine metadata: {file_hash}")
                logging.error(f"Available hashes: {list(self.metadata.keys())[:10]}")  # Show first 10
                logging.error(f"Total metadata entries: {len(self.metadata)}")
                return False
            
            metadata = self.metadata[file_hash]
            quarantine_path = metadata['quarantine_path']
            original_path = metadata['original_path']
            
            if not os.path.exists(quarantine_path):
                logging.error(f"Quarantined file not found: {quarantine_path}")
                return False
            
            # Create original directory if it doesn't exist
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Restore file
            shutil.copy2(quarantine_path, original_path)
            
            # Move quarantined file to restored directory
            restored_name = os.path.basename(quarantine_path)
            restored_path = os.path.join(self.quarantine_dir, 'restored', restored_name)
            shutil.move(quarantine_path, restored_path)
            
            # Update metadata
            metadata['status'] = 'restored'
            metadata['restore_time'] = datetime.now().isoformat()
            metadata['restored_path'] = restored_path
            self.save_metadata()
            
            logging.info(f"File restored successfully: {quarantine_path} -> {original_path}")
            return True
        
        except Exception as e:
            logging.error(f"Error restoring file: {e}")
            return False
    
    def delete_quarantined_file(self, threat_record):
        """Permanently delete a quarantined file"""
        try:
            file_hash = getattr(threat_record, 'file_hash', None)
            if not file_hash or file_hash not in self.metadata:
                logging.error(f"File hash not found in quarantine metadata: {file_hash}")
                return False
            
            metadata = self.metadata[file_hash]
            quarantine_path = metadata['quarantine_path']
            
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
            
            # Update metadata
            metadata['status'] = 'deleted'
            metadata['delete_time'] = datetime.now().isoformat()
            self.save_metadata()
            
            logging.info(f"Quarantined file deleted permanently: {quarantine_path}")
            return True
        
        except Exception as e:
            logging.error(f"Error deleting quarantined file: {e}")
            return False
    
    def get_quarantine_path(self, original_path):
        """Get quarantine path for a given original path"""
        file_hash = self.calculate_file_hash(original_path)
        if file_hash in self.metadata:
            return self.metadata[file_hash].get('quarantine_path', '')
        return ''
    
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        
        except Exception as e:
            logging.error(f"Error calculating file hash for {file_path}: {e}")
            return ""
    
    def get_quarantine_stats(self):
        """Get quarantine statistics"""
        try:
            stats = {
                'total_quarantined': 0,
                'by_threat_type': {},
                'by_status': {},
                'total_size': 0
            }
            
            for file_hash, metadata in self.metadata.items():
                stats['total_quarantined'] += 1
                
                # Count by threat type
                threat_type = metadata.get('threat_type', 'unknown')
                stats['by_threat_type'][threat_type] = stats['by_threat_type'].get(threat_type, 0) + 1
                
                # Count by status
                status = metadata.get('status', 'unknown')
                stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
                
                # Sum file sizes
                stats['total_size'] += metadata.get('file_size', 0)
            
            return stats
        
        except Exception as e:
            logging.error(f"Error getting quarantine stats: {e}")
            return {}
    
    def cleanup_old_quarantine_files(self, days_old=30):
        """Clean up quarantine files older than specified days"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            cleaned_count = 0
            
            for file_hash, metadata in list(self.metadata.items()):
                quarantine_time_str = metadata.get('quarantine_time', '')
                try:
                    quarantine_time = datetime.fromisoformat(quarantine_time_str)
                    
                    if quarantine_time < cutoff_date:
                        # Delete old quarantined file
                        quarantine_path = metadata.get('quarantine_path', '')
                        if os.path.exists(quarantine_path):
                            os.remove(quarantine_path)
                        
                        # Remove from metadata
                        del self.metadata[file_hash]
                        cleaned_count += 1
                
                except Exception as e:
                    logging.error(f"Error processing quarantine cleanup for {file_hash}: {e}")
            
            if cleaned_count > 0:
                self.save_metadata()
                logging.info(f"Cleaned up {cleaned_count} old quarantine files")
            
            return cleaned_count
        
        except Exception as e:
            logging.error(f"Error during quarantine cleanup: {e}")
            return 0
    
    def export_quarantine_report(self, output_path):
        """Export quarantine report to JSON file"""
        try:
            report = {
                'export_date': datetime.now().isoformat(),
                'stats': self.get_quarantine_stats(),
                'quarantined_files': self.metadata
            }
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logging.info(f"Quarantine report exported to: {output_path}")
            return True
        
        except Exception as e:
            logging.error(f"Error exporting quarantine report: {e}")
            return False
    
    def verify_quarantine_integrity(self):
        """Verify integrity of quarantined files"""
        try:
            integrity_issues = []
            
            for file_hash, metadata in self.metadata.items():
                quarantine_path = metadata.get('quarantine_path', '')
                expected_hash = file_hash
                
                if os.path.exists(quarantine_path):
                    actual_hash = self.calculate_file_hash(quarantine_path)
                    
                    if actual_hash != expected_hash:
                        integrity_issues.append({
                            'file': quarantine_path,
                            'expected_hash': expected_hash,
                            'actual_hash': actual_hash,
                            'issue': 'hash_mismatch'
                        })
                else:
                    integrity_issues.append({
                        'file': quarantine_path,
                        'issue': 'file_missing'
                    })
            
            if integrity_issues:
                logging.warning(f"Quarantine integrity issues found: {len(integrity_issues)}")
                for issue in integrity_issues:
                    logging.warning(f"Integrity issue: {issue}")
            else:
                logging.info("Quarantine integrity verification passed")
            
            return integrity_issues
        
        except Exception as e:
            logging.error(f"Error verifying quarantine integrity: {e}")
            return []
    
    def get_quarantined_files_by_type(self, threat_type):
        """Get list of quarantined files by threat type"""
        try:
            files = []
            
            for file_hash, metadata in self.metadata.items():
                if metadata.get('threat_type') == threat_type and metadata.get('status') == 'quarantined':
                    files.append({
                        'hash': file_hash,
                        'original_path': metadata.get('original_path'),
                        'quarantine_path': metadata.get('quarantine_path'),
                        'quarantine_time': metadata.get('quarantine_time'),
                        'threat_level': metadata.get('threat_level'),
                        'confidence': metadata.get('confidence_score'),
                        'file_size': metadata.get('file_size')
                    })
            
            return files
        
        except Exception as e:
            logging.error(f"Error getting quarantined files by type: {e}")
            return []
