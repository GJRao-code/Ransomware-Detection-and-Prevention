import os
import logging
import threading
import time
import concurrent.futures
import hashlib
import psutil
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from app import app, db
from app.models import ScanSession, DetectedThreat, ThreatAlert, HoneypotFile
from app.ml_engine import MLEngine
from app.threat_analyzer import ThreatAnalyzer
from app.quarantine_manager import QuarantineManager

class ScannerEngine:
    def __init__(self):
        self.ml_engine = MLEngine()
        self.threat_analyzer = ThreatAnalyzer()
        self.quarantine_manager = QuarantineManager()
        self.active_scans = {}
        self.file_monitor = None
        self.observer = None
        self.honeypot_monitor = HoneypotMonitor()
        self.setup_file_monitoring()
    
    def setup_file_monitoring(self):
        """Setup real-time file system monitoring"""
        try:
            self.file_monitor = FileMonitor(self)
            observer = Observer()
            
            # Monitor common directories
            monitor_paths = [
                os.path.expanduser("~"),  # User home directory
                "/tmp" if os.name != 'nt' else os.environ.get('TEMP', 'C:\\temp'),  # Temp directory
            ]
            
            for path in monitor_paths:
                if os.path.exists(path):
                    observer.schedule(self.file_monitor, path, recursive=True)
            
            # store observer so it can be stopped later on shutdown
            self.observer = observer
            observer.start()
            logging.info("File system monitoring started")
        
        except Exception as e:
            logging.error(f"Error setting up file monitoring: {e}")
    
    def start_scan(self, scan_id, scan_type, scan_path=None):
        """Start a new scan session"""
        try:
            with app.app_context():
                scan_session = ScanSession.query.get(scan_id)
                if not scan_session:
                    logging.error(f"Scan session {scan_id} not found")
                    return

                logging.info(f"Starting scan {scan_id}: type={scan_type}, path={scan_path}")

                # Mark scan as starting in database immediately so SSE can see it
                scan_session.status = 'running'
                scan_session.progress_percentage = 0.0
                scan_session.current_file = 'Initializing scan...'
                db.session.commit()
                logging.info(f"Scan {scan_id} marked as running in database")

                self.active_scans[scan_id] = {
                    'status': 'running',
                    'start_time': datetime.utcnow(),
                    'thread': threading.current_thread()
                }

                # Clean up existing honeypot files and disable deployment
                # Honeypots create false positives when scanned - they should only be monitored for changes
                try:
                    self.cleanup_honeypots()
                except Exception as e:
                    logging.warning(f"Failed to cleanup honeypots: {e}")
                logging.info("Honeypot deployment disabled to prevent false positives")

                # Determine scan paths
                if scan_type == 'quick':
                    paths = self.get_quick_scan_paths()
                elif scan_type == 'full':
                    paths = self.get_full_scan_paths()
                elif scan_type == 'custom' and scan_path:
                    paths = [scan_path]
                else:
                    paths = self.get_quick_scan_paths()

                logging.info(f"Scan paths determined: {len(paths)} paths")

                # Start scanning (pass scan_type for optimizations)
                self.perform_scan(scan_session, paths, scan_type)

        except Exception as e:
            logging.error(f"Error starting scan {scan_id}: {e}")
            import traceback
            logging.error(f"Traceback: {traceback.format_exc()}")

            with app.app_context():
                scan_session = ScanSession.query.get(scan_id)
                if scan_session:
                    scan_session.status = 'error'
                    scan_session.end_time = datetime.utcnow()
                    db.session.commit()
    
    def get_quick_scan_paths(self):
        """Get paths for quick scan"""
        paths = []
        
        # User directories
        home = os.path.expanduser("~")
        paths.extend([
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Downloads"),
        ])
        
        # System directories
        if os.name == 'nt':  # Windows
            paths.extend([
                "C:\\Users\\Public",
                "C:\\temp",
                os.environ.get('TEMP', 'C:\\temp')
            ])
        else:  # Unix-like
            paths.extend([
                "/tmp",
                "/var/tmp",
                "/home"
            ])
        
        return [path for path in paths if os.path.exists(path)]
    
    def get_full_scan_paths(self):
        """Get paths for full system scan"""
        if os.name == 'nt':  # Windows
            return ["C:\\"]
        else:  # Unix-like
            return ["/"]
    
    def perform_scan(self, scan_session, paths, scan_type='quick'):
        """Perform the actual scanning"""
        scan_id = scan_session.id
        try:
            logging.info(f"Starting scan performance: session={scan_id}, paths={len(paths)}, type={scan_type}")

            total_files = 0
            scanned_files = 0
            detected_threats = 0

            # Update progress during file counting so UI shows activity
            with app.app_context():
                scan_session = ScanSession.query.get(scan_id)
                if scan_session:
                    scan_session.current_file = 'Counting files to scan...'
                    db.session.commit()

            # Count total files first (but cap for quick scans to avoid long counting)
            # For quick scans, use a faster approximate count
            if scan_type == 'quick':
                # Quick scan: count files as we walk (don't pre-count, just start scanning)
                # This makes quick scans start immediately
                total_files = 1000  # Estimated, will update as we scan
                logging.info(f"Quick scan mode: Using estimated file count of {total_files}")
            else:
                # Full scan: count all files first
                logging.info("Counting all files before scanning...")
                for path in paths:
                    if scan_id not in self.active_scans:
                        logging.info(f"Scan {scan_id} was stopped during file counting")
                        break

                    try:
                        count = self.count_files(path)
                        total_files += count
                        logging.info(f"Path {path}: {count} files counted")
                    except Exception as e:
                        logging.warning(f"Error counting files in {path}: {e}")

            logging.info(f"Total files to scan: {total_files}")

            # If no files found, still mark as running but log it
            if total_files == 0:
                logging.warning(f"No files found to scan in paths: {paths}")
                with app.app_context():
                    scan_session = ScanSession.query.get(scan_id)
                    if scan_session:
                        scan_session.status = 'completed'
                        scan_session.progress_percentage = 100.0
                        scan_session.end_time = datetime.utcnow()
                        scan_session.current_file = None
                        db.session.commit()
                return

            # Update scan session - refresh from DB to ensure we have the latest
            with app.app_context():
                scan_session = ScanSession.query.get(scan_id)
                if not scan_session:
                    logging.error(f"Scan session {scan_id} not found")
                    return
                scan_session.status = 'running'
                scan_session.progress_percentage = 0.0
                scan_session.current_file = f'Found {total_files} files to scan. Starting...'
                db.session.commit()
                logging.info(f"Scan {scan_id} marked as running with {total_files} files")

            # Scan using a thread pool for concurrency and higher throughput
            max_workers = min(32, (os.cpu_count() or 4) * 2)
            futures = []
            lock = threading.Lock()
            batch_commit_threshold = 200  # commit DB changes in larger batches

            logging.info(f"Starting thread pool with {max_workers} workers")

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit scan tasks while walking files
                for path in paths:
                    if scan_id not in self.active_scans:
                        logging.info(f"Scan {scan_id} stopped before file walking")
                        break

                    try:
                        for root, dirs, files in os.walk(path):
                            # Filter directories to avoid system folders
                            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['System32', 'Windows', 'Program Files', 'ProgramData']]

                            for file in files:
                                if scan_id not in self.active_scans:
                                    logging.info(f"Scan {scan_id} stopped during file walking")
                                    break

                                file_path = os.path.join(root, file)

                                # Update counters
                                scanned_files += 1
                                
                                # For quick scans, update total_files estimate as we go
                                if scan_type == 'quick' and scanned_files > total_files * 0.9:
                                    total_files = int(scanned_files * 1.2)  # Increase estimate
                                
                                current_file = file_path
                                progress = (scanned_files / total_files) * 100 if total_files > 0 else 0

                                # Update scan session in DB more frequently for fast UI updates
                                # Update every file for first 20 files (instant feedback), then every 3 files
                                update_interval = 3 if scanned_files > 20 else 1
                                if scanned_files % update_interval == 0 or scanned_files == 1:
                                    try:
                                        with app.app_context():
                                            session = ScanSession.query.get(scan_id)
                                            if session:
                                                session.current_file = current_file
                                                session.files_scanned = scanned_files
                                                # Ensure progress only increases (monotonic)
                                                session.progress_percentage = max(session.progress_percentage or 0, progress)
                                                db.session.commit()
                                    except Exception as e:
                                        logging.warning(f"Error updating scan progress: {e}")
                                        try:
                                            db.session.rollback()
                                        except:
                                            pass

                                # Submit file for scanning (worker returns threat dict or None)
                                try:
                                    fut = executor.submit(self.scan_file, file_path, scan_type)
                                    futures.append(fut)
                                except Exception as e:
                                    logging.error(f"Error submitting file {file_path} for scanning: {e}")

                                # Process completed futures in batches to update DB and stats
                                # To avoid unbounded memory, periodically process futures
                                if len(futures) >= max_workers * 4:
                                    processed = self.process_futures_batch(futures, scan_id, lock, scanned_files, detected_threats, total_files, batch_commit_threshold)
                                    scanned_files, detected_threats, futures = processed

                    except Exception as e:
                        logging.error(f"Error walking path {path}: {e}")

                # Process any remaining futures
                if futures:
                    processed = self.process_futures_batch(futures, scan_id, lock, scanned_files, detected_threats, total_files, 1)  # Commit immediately for final batch
                    scanned_files, detected_threats, futures = processed

            # Auto-quarantine ALL threats after scan completes (not just high/critical)
            auto_quarantine_count = 0
            if detected_threats > 0:
                try:
                    with app.app_context():
                        from app.quarantine_manager import QuarantineManager
                        qm = QuarantineManager()
                        # Get ALL threats for this scan (excluding honeypot files)
                        all_threats = DetectedThreat.query.filter_by(scan_session_id=scan_id).all()
                        honeypot_names = ['important_documents.txt', 'financial_data.xlsx', 'passwords.txt', 
                                         'backup_keys.pem', 'database_backup.sql']
                        
                        total_threats = len(all_threats)
                        processed_threats = 0
                        
                        # Update progress: quarantine phase is 91-99%
                        scan_session = ScanSession.query.get(scan_id)
                        if scan_session:
                            scan_session.current_file = f'Quarantining threats... (0/{total_threats})'
                            scan_session.progress_percentage = 91.0
                            db.session.commit()
                        
                        for threat in all_threats:
                            processed_threats += 1
                            
                            # Skip honeypot files - don't quarantine our own honeypot files
                            is_honeypot = any(hp_name.lower() in threat.file_path.lower() for hp_name in honeypot_names)
                            if is_honeypot:
                                # Mark honeypot threats as false positives and don't quarantine them
                                threat.status = 'false_positive'
                                logging.debug(f"Skipping honeypot file from quarantine: {threat.file_path}")
                                continue
                            
                            if not threat.is_quarantined:
                                try:
                                    logging.info(f"Attempting to quarantine threat {threat.id}: {threat.file_path}")
                                    quarantine_result = qm.quarantine_file(threat.file_path, threat)
                                    if quarantine_result:
                                        threat.is_quarantined = True
                                        threat.status = 'quarantined'
                                        auto_quarantine_count += 1
                                        logging.info(f"Successfully quarantined threat {threat.id}")
                                    else:
                                        logging.warning(f"Quarantine returned False for threat {threat.id}: {threat.file_path}")
                                        threat.status = 'quarantine_failed'
                                except Exception as e:
                                    logging.error(f"Failed to auto-quarantine threat {threat.id} ({threat.file_path}): {e}", exc_info=True)
                                    threat.status = 'quarantine_failed'
                            
                            # Update progress during quarantine (91% to 99%)
                            if processed_threats % 5 == 0 or processed_threats == total_threats:
                                quarantine_progress = 91 + (processed_threats / total_threats) * 8  # 91% to 99%
                                scan_session = ScanSession.query.get(scan_id)
                                if scan_session:
                                    scan_session.current_file = f'Quarantining threats... ({processed_threats}/{total_threats})'
                                    scan_session.progress_percentage = min(99.0, quarantine_progress)
                                    # Commit threat status updates along with progress
                                    db.session.commit()
                        
                        # Final commit for all threat status updates
                        db.session.commit()
                        logging.info(f"Auto-quarantined {auto_quarantine_count} out of {total_threats} threats from scan {scan_id}")
                except Exception as e:
                    logging.warning(f"Error during auto-quarantine: {e}")
            
            # Complete the scan - refresh session from DB
            with app.app_context():
                scan_session = ScanSession.query.get(scan_id)
                if scan_session:
                    scan_session.status = 'completed'
                    scan_session.end_time = datetime.utcnow()
                    scan_session.progress_percentage = 100.0
                    scan_session.current_file = None
                    scan_session.files_scanned = scanned_files
                    scan_session.threats_detected = detected_threats

                    try:
                        db.session.commit()
                        logging.info(f"Scan {scan_id} completed: {scanned_files} files scanned, {detected_threats} threats detected, {auto_quarantine_count} auto-quarantined")
                    except Exception as e:
                        logging.error(f"Error updating scan completion: {e}")
                        db.session.rollback()

            # Check honeypot files after scan
            try:
                with app.app_context():
                    scan_session = ScanSession.query.get(scan_id)
                    if scan_session:
                        self.check_honeypots(scan_session)
            except Exception as e:
                logging.warning(f"Error checking honeypots: {e}")

        except Exception as e:
            logging.error(f"Error performing scan {scan_id}: {e}")
            import traceback
            logging.error(f"Scan error traceback: {traceback.format_exc()}")

            # Update scan status to error - use app context for DB operations
            try:
                with app.app_context():
                    scan_session = ScanSession.query.get(scan_id)
                    if scan_session:
                        scan_session.status = 'error'
                        scan_session.end_time = datetime.utcnow()
                        db.session.commit()
                    else:
                        logging.warning(f"Scan session {scan_id} not found when trying to mark as error")
            except Exception as commit_e:
                logging.error(f"Error committing scan error status: {commit_e}")
                try:
                    db.session.rollback()
                except:
                    pass

        finally:
            # Clean up
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]

    def process_futures_batch(self, futures, scan_id, lock, scanned_files, detected_threats, total_files, batch_commit_threshold):
        """Process a batch of completed futures"""
        new_scanned = scanned_files
        new_threats = detected_threats
        remaining_futures = []
        threats_to_add = []

        for completed in concurrent.futures.as_completed(futures):
            try:
                result = completed.result()
            except Exception as e:
                logging.debug(f"Worker error: {e}")
                result = None

            # Update counters
            new_scanned += 1

            # If a threat dict returned, collect it for batch DB insert
            if result:
                new_threats += 1
                threats_to_add.append(result)

            # Commit in larger batches to reduce DB overhead
            if new_scanned % batch_commit_threshold == 0:
                # Update scan session and commit threats in a single DB transaction
                try:
                    with app.app_context():
                        scan_session = ScanSession.query.get(scan_id)
                        if scan_session:
                            scan_session.files_scanned = new_scanned
                            # Ensure progress only increases (monotonic)
                            new_progress = (new_scanned / total_files) * 100 if total_files > 0 else 0
                            scan_session.progress_percentage = max(scan_session.progress_percentage or 0, new_progress)
                            scan_session.threats_detected = new_threats
                            
                            # Add all collected threats - check for duplicates first
                            seen_file_paths = set()
                            for threat_data in threats_to_add:
                                try:
                                    file_path = threat_data['file_path']
                                    # Skip if we've already added this file as a threat in this batch
                                    if file_path in seen_file_paths:
                                        logging.debug(f"Skipping duplicate threat: {file_path}")
                                        continue
                                    
                                    # Check if this threat already exists in DB for this scan
                                    existing = DetectedThreat.query.filter_by(
                                        scan_session_id=scan_id,
                                        file_path=file_path
                                    ).first()
                                    if existing:
                                        logging.debug(f"Threat already exists in DB: {file_path}")
                                        continue
                                    
                                    seen_file_paths.add(file_path)
                                    th = DetectedThreat(
                                        scan_session_id=scan_id,
                                        file_path=file_path,
                                        threat_type=threat_data['threat_type'],
                                        threat_level=threat_data['threat_level'],
                                        confidence_score=threat_data['confidence'],
                                        detection_method=threat_data['detection_method'],
                                        file_hash=threat_data.get('file_hash'),
                                        file_size=threat_data.get('file_size', 0),
                                        entropy_score=threat_data.get('entropy_score', 0.0)
                                    )
                                    db.session.add(th)
                                except Exception as e:
                                    logging.debug(f"Failed to add threat to DB: {e}")
                            
                            db.session.commit()
                            threats_to_add = []  # Clear after commit
                except Exception as e:
                    logging.warning(f"Error in batch commit: {e}")
                    try:
                        db.session.rollback()
                    except:
                        pass
            else:
                # Keep futures that weren't processed
                remaining_futures.append(completed)

        # Commit any remaining threats
        if threats_to_add:
            try:
                with app.app_context():
                    scan_session = ScanSession.query.get(scan_id)
                    if scan_session:
                        threats_detected = new_threats
                        # Check for duplicates before adding
                        seen_file_paths = set()
                        for threat_data in threats_to_add:
                            try:
                                file_path = threat_data['file_path']
                                # Skip duplicates in this batch
                                if file_path in seen_file_paths:
                                    logging.debug(f"Skipping duplicate threat in final batch: {file_path}")
                                    continue
                                
                                # Check if already in DB
                                existing = DetectedThreat.query.filter_by(
                                    scan_session_id=scan_id,
                                    file_path=file_path
                                ).first()
                                if existing:
                                    logging.debug(f"Threat already exists in DB (final batch): {file_path}")
                                    continue
                                
                                seen_file_paths.add(file_path)
                                th = DetectedThreat(
                                    scan_session_id=scan_id,
                                    file_path=file_path,
                                    threat_type=threat_data['threat_type'],
                                    threat_level=threat_data['threat_level'],
                                    confidence_score=threat_data['confidence'],
                                    detection_method=threat_data['detection_method'],
                                    file_hash=threat_data.get('file_hash'),
                                    file_size=threat_data.get('file_size', 0),
                                    entropy_score=threat_data.get('entropy_score', 0.0)
                                )
                                db.session.add(th)
                                new_alert = ThreatAlert(
                                    user_id=scan_session.user_id if hasattr(scan_session, 'user_id') else 1,  # fallback if needed
                                    alert_type="Ransomware Detection",
                                    severity=th.threat_level,
                                    title=f"Threat detected: {os.path.basename(file_path)}",
                                    description=f"A {th.threat_level}-level ransomware threat was detected in {file_path}.",
                                    file_path=file_path,
                                    process_name="Scanner Engine",
                                    is_read=False,
                                    is_resolved=False
                                )

                                db.session.add(new_alert)
                                db.session.commit()
                            except Exception as e:
                                logging.debug(f"Failed to add threat to DB: {e}")
                        db.session.commit()
            except Exception as e:
                logging.warning(f"Error committing remaining threats: {e}")
                try:
                    db.session.rollback()
                except:
                    pass

        return new_scanned, new_threats, remaining_futures
    
    def count_files(self, path, cap=None):
        """Count total files in a path"""
        try:
            count = 0
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['System32', 'Windows', 'Program Files']]
                count += len(files)
                if cap and count >= cap:
                    return cap
            return count
        except:
            return 0
    
    def scan_file(self, file_path, scan_type='quick'):
        """Scan a single file for threats"""
        try:
            # Skip certain file types and system files
            if self.should_skip_file(file_path):
                return None
            
            # Get file info
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # Skip files larger than 100MB
                return None
            
            # Read a small sample of file content to keep scanning fast
            file_content = b''
            sample_size = 64 * 1024 if scan_type == 'quick' else 2 * 1024 * 1024
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read(sample_size)
            except Exception:
                file_content = None
            
            # Calculate a quick file hash (sample-based) to reduce IO
            file_hash = None
            try:
                if file_content:
                    file_hash = hashlib.md5(file_content).hexdigest()
                else:
                    # fallback to stat-based pseudo-hash
                    st = os.stat(file_path)
                    file_hash = hashlib.md5(f"{st.st_size}-{st.st_mtime}".encode()).hexdigest()
            except Exception:
                file_hash = None
            
            # Perform multiple detection methods
            detection_results = []
            
            # ML-based detection (for quick scans use sample-based prediction)
            try:
                ml_result = self.ml_engine.predict_threat(file_path, file_content)
            except Exception as e:
                logging.debug(f"ML engine prediction failed for {file_path}: {e}")
                ml_result = {'is_threat': False, 'confidence': 0.0}
            if ml_result.get('is_threat'):
                detection_results.append(ml_result)
            
            # Signature-based detection (lightweight sample)
            try:
                sig_result = self.threat_analyzer.signature_detection(file_path, file_content)
            except Exception as e:
                logging.debug(f"Signature detection error for {file_path}: {e}")
                sig_result = {'is_threat': False, 'confidence': 0.0}
            if sig_result.get('is_threat'):
                detection_results.append(sig_result)
            
            # Behavioral analysis - skip or keep lightweight for quick scans
            behavior_result = {'is_threat': False, 'confidence': 0.0}
            if scan_type != 'quick':
                try:
                    behavior_result = self.threat_analyzer.behavioral_analysis(file_path, file_content)
                except Exception as e:
                    logging.debug(f"Behavioral analysis error for {file_path}: {e}")
                    behavior_result = {'is_threat': False, 'confidence': 0.0}
            if behavior_result.get('is_threat'):
                detection_results.append(behavior_result)
            
            # Entropy analysis - lightweight check (only for non-quick)
            entropy_result = {'is_threat': False, 'confidence': 0.0}
            if scan_type != 'quick':
                try:
                    entropy_result = self.threat_analyzer.entropy_analysis(file_path, file_content)
                except Exception as e:
                    logging.debug(f"Entropy analysis error for {file_path}: {e}")
                    entropy_result = {'is_threat': False, 'confidence': 0.0}
            if entropy_result.get('is_threat'):
                detection_results.append(entropy_result)
            
            # If any detection method found a threat
            if detection_results:
                # Use the highest confidence result
                best_result = max(detection_results, key=lambda x: x.get('confidence', 0.0))
                # Return a lightweight threat dict for main thread to persist
                return {
                    'file_path': file_path,
                    'threat_type': best_result.get('threat_type', 'unknown'),
                    'threat_level': best_result.get('threat_level', 'medium'),
                    'confidence': best_result.get('confidence', 0.0),
                    'detection_method': best_result.get('detection_method', 'mixed'),
                    'file_hash': file_hash,
                    'file_size': file_size,
                    'entropy_score': best_result.get('entropy_score', 0.0)
                }

            return None
        
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return None
    
    def should_skip_file(self, file_path):
        """Determine if a file should be skipped during scanning"""
        # Skip honeypot files created by this application
        honeypot_names = ['important_documents.txt', 'financial_data.xlsx', 'passwords.txt', 
                         'backup_keys.pem', 'database_backup.sql']
        file_name = os.path.basename(file_path).lower()
        if any(hp_name.lower() in file_name for hp_name in honeypot_names):
            return True
        # Skip system files and directories
        skip_patterns = [
            '/.git/', '/.svn/', '/node_modules/', '/.vscode/',
            'System32', 'Windows', 'Program Files', 'AppData',
            '.tmp', '.log', '.cache'
        ]
        
        for pattern in skip_patterns:
            if pattern in file_path:
                return True
        
        # Skip large files and certain extensions
        try:
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB
                return True
        except:
            return True
        
        # Skip certain file extensions
        skip_extensions = [
            '.iso', '.img', '.vmdk', '.vdi', '.ova',
            '.mp4', '.avi', '.mkv', '.mov',
            '.zip', '.rar', '.7z', '.tar', '.gz'
        ]
        
        ext = os.path.splitext(file_path)[1].lower()
        return ext in skip_extensions
    
    def cleanup_honeypots(self):
        """Remove existing honeypot files that were created by this app"""
        try:
            honeypot_files = [
                "important_documents.txt",
                "financial_data.xlsx",
                "passwords.txt",
                "backup_keys.pem",
                "database_backup.sql"
            ]
            
            # Clean up from user directories
            user_dirs = [
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Downloads")
            ]
            
            removed_count = 0
            for dir_path in user_dirs:
                if os.path.exists(dir_path):
                    for filename in honeypot_files:
                        honeypot_path = os.path.join(dir_path, filename)
                        if os.path.exists(honeypot_path):
                            try:
                                os.remove(honeypot_path)
                                removed_count += 1
                                logging.info(f"Removed honeypot file: {honeypot_path}")
                            except Exception as e:
                                logging.warning(f"Could not remove honeypot file {honeypot_path}: {e}")
            
            if removed_count > 0:
                logging.info(f"Cleaned up {removed_count} honeypot files")
        
        except Exception as e:
            logging.warning(f"Error cleaning up honeypots: {e}")

    def deploy_honeypots(self):
        """Deploy honeypot files - DISABLED to prevent false positives"""
        # Honeypots are disabled because they create false positives when scanned
        # They should only be used for monitoring file changes, not for threat detection
        return
        try:
            honeypot_files = [
                "important_documents.txt",
                "financial_data.xlsx",
                "passwords.txt",
                "backup_keys.pem",
                "database_backup.sql"
            ]
            
            # Deploy in user directories
            user_dirs = [
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Downloads")
            ]
            
            for dir_path in user_dirs:
                if os.path.exists(dir_path):
                    for filename in honeypot_files:
                        honeypot_path = os.path.join(dir_path, filename)
                        
                        if not os.path.exists(honeypot_path):
                            # Create honeypot file with dummy content
                            content = f"This is a honeypot file created on {datetime.now()}\n"
                            content += "If this file is modified, it indicates potential ransomware activity.\n"
                            content += "Do not delete or modify this file.\n"
                            
                            try:
                                with open(honeypot_path, 'w') as f:
                                    f.write(content)
                                
                                # Calculate hash
                                file_hash = hashlib.md5(content.encode()).hexdigest()
                                
                                # Record in database
                                honeypot = HoneypotFile(
                                    file_path=honeypot_path,
                                    file_name=filename,
                                    file_type='honeypot',
                                    original_hash=file_hash,
                                    current_hash=file_hash
                                )
                                db.session.add(honeypot)
                            
                            except Exception as e:
                                logging.error(f"Error creating honeypot {honeypot_path}: {e}")
            
            db.session.commit()
            logging.info("Honeypot files deployed successfully")
        
        except Exception as e:
            logging.error(f"Error deploying honeypots: {e}")
    
    def check_honeypots(self, scan_session):
        """Check if honeypot files have been compromised"""
        try:
            honeypots = HoneypotFile.query.all()
            
            for honeypot in honeypots:
                if os.path.exists(honeypot.file_path):
                    # Check if file has been modified
                    try:
                        with open(honeypot.file_path, 'rb') as f:
                            current_content = f.read()
                        
                        current_hash = hashlib.md5(current_content).hexdigest()
                        
                        if current_hash != honeypot.original_hash:
                            # Honeypot has been compromised!
                            honeypot.is_compromised = True
                            honeypot.current_hash = current_hash
                            honeypot.access_count += 1
                            honeypot.last_accessed = datetime.utcnow()
                            
                            # Create high-priority alert
                            alert = ThreatAlert(
                                user_id=scan_session.user_id,
                                alert_type='honeypot_compromised',
                                severity='critical',
                                title='Honeypot File Compromised',
                                description=f'Honeypot file {honeypot.file_name} has been modified, indicating possible ransomware activity',
                                file_path=honeypot.file_path
                            )
                            db.session.add(alert)
                            
                            logging.critical(f"Honeypot compromised: {honeypot.file_path}")
                    
                    except Exception as e:
                        logging.error(f"Error checking honeypot {honeypot.file_path}: {e}")
                else:
                    # Honeypot file was deleted
                    honeypot.is_compromised = True
                    honeypot.last_accessed = datetime.utcnow()
                    
                    alert = ThreatAlert(
                        user_id=scan_session.user_id,
                        alert_type='honeypot_deleted',
                        severity='critical',
                        title='Honeypot File Deleted',
                        description=f'Honeypot file {honeypot.file_name} has been deleted, indicating possible ransomware activity',
                        file_path=honeypot.file_path
                    )
                    db.session.add(alert)
                    
                    logging.critical(f"Honeypot deleted: {honeypot.file_path}")
            
            db.session.commit()
        
        except Exception as e:
            logging.error(f"Error checking honeypots: {e}")
    
    def stop_scan(self, scan_id):
        """Stop an active scan"""
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
            
            with app.app_context():
                scan_session = ScanSession.query.get(scan_id)
                if scan_session:
                    scan_session.status = 'stopped'
                    scan_session.end_time = datetime.utcnow()
                    db.session.commit()
            
            logging.info(f"Scan {scan_id} stopped")

    def shutdown(self):
        """Gracefully shutdown background monitors and mark active scans stopped."""
        logging.info("Shutting down ScannerEngine monitors and active scans")
        try:
            # Stop the filesystem observer
            if getattr(self, 'observer', None):
                try:
                    self.observer.stop()
                    self.observer.join(timeout=3)
                    logging.info("File system observer stopped")
                except Exception as e:
                    logging.debug(f"Error stopping observer: {e}")
                finally:
                    self.observer = None

            # Mark any active scans as stopped in DB
            if self.active_scans:
                with app.app_context():
                    for scan_id in list(self.active_scans.keys()):
                        try:
                            scan_session = ScanSession.query.get(scan_id)
                            if scan_session:
                                scan_session.status = 'stopped'
                                scan_session.end_time = datetime.utcnow()
                                db.session.commit()
                        except Exception as e:
                            db.session.rollback()
                            logging.debug(f"Failed to update scan {scan_id} during shutdown: {e}")
                        finally:
                            if scan_id in self.active_scans:
                                del self.active_scans[scan_id]

        except Exception as e:
            logging.error(f"Error during ScannerEngine.shutdown: {e}")


class FileMonitor(FileSystemEventHandler):
    """Real-time file system monitor for detecting suspicious activity"""
    
    def __init__(self, scanner_engine):
        self.scanner_engine = scanner_engine
        self.ml_engine = scanner_engine.ml_engine
        self.threat_analyzer = scanner_engine.threat_analyzer
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self.analyze_file_event(event.src_path, 'created')
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self.analyze_file_event(event.src_path, 'modified')
    
    def analyze_file_event(self, file_path, event_type):
        """Analyze file events for suspicious activity"""
        try:
            # Skip analysis for system files and temporary files
            if self.scanner_engine.should_skip_file(file_path):
                return
            
            # Quick threat assessment for real-time monitoring
            try:
                # Check file extension and name patterns
                suspicious_patterns = [
                    '.encrypted', '.locked', '.crypto', '.ransom',
                    'decrypt_instruction', 'ransom_note', 'payment'
                ]
                
                filename = os.path.basename(file_path).lower()
                if any(pattern in filename for pattern in suspicious_patterns):
                    self.create_realtime_alert(file_path, 'suspicious_file', 'high')
                
                # Check for rapid file modifications (potential encryption)
                if event_type == 'modified':
                    # This would be enhanced with proper file change tracking
                    pass
            
            except Exception as e:
                logging.error(f"Error analyzing file event {file_path}: {e}")
        
        except Exception as e:
            logging.error(f"Error in file event analysis: {e}")
    
    def create_realtime_alert(self, file_path, alert_type, severity):
        """Create real-time threat alert"""
        try:
            with app.app_context():
                # Create alert for all users (in a real system, this would be more targeted)
                from models import User
                users = User.query.all()
                
                for user in users:
                    alert = ThreatAlert(
                        user_id=user.id,
                        alert_type=alert_type,
                        severity=severity,
                        title='Real-time Threat Detection',
                        description=f'Suspicious file activity detected: {file_path}',
                        file_path=file_path
                    )
                    db.session.add(alert)
                
                db.session.commit()
                logging.warning(f"Real-time alert created for {file_path}")
        
        except Exception as e:
            logging.error(f"Error creating real-time alert: {e}")


class HoneypotMonitor:
    """Monitor honeypot files for unauthorized access"""
    
    def __init__(self):
        self.last_check = datetime.utcnow()
    
    def check_honeypots(self):
        """Periodic check of honeypot file integrity"""
        try:
            with app.app_context():
                honeypots = HoneypotFile.query.filter_by(is_compromised=False).all()
                
                for honeypot in honeypots:
                    if os.path.exists(honeypot.file_path):
                        # Check file modification time
                        stat = os.stat(honeypot.file_path)
                        if datetime.fromtimestamp(stat.st_mtime) > self.last_check:
                            # File was modified since last check
                            self.verify_honeypot_integrity(honeypot)
                
                self.last_check = datetime.utcnow()
        
        except Exception as e:
            logging.error(f"Error in honeypot monitoring: {e}")
    
    def verify_honeypot_integrity(self, honeypot):
        """Verify if a honeypot file has been compromised"""
        try:
            with open(honeypot.file_path, 'rb') as f:
                current_content = f.read()
            
            current_hash = hashlib.md5(current_content).hexdigest()
            
            if current_hash != honeypot.original_hash:
                # Honeypot compromised!
                honeypot.is_compromised = True
                honeypot.current_hash = current_hash
                honeypot.last_accessed = datetime.utcnow()
                honeypot.access_count += 1
                
                # Create critical alert
                from models import User
                users = User.query.all()
                
                for user in users:
                    alert = ThreatAlert(
                        user_id=user.id,
                        alert_type='honeypot_compromised',
                        severity='critical',
                        title='CRITICAL: Honeypot Compromised',
                        description=f'Honeypot file {honeypot.file_name} has been compromised, indicating active ransomware!',
                        file_path=honeypot.file_path
                    )
                    db.session.add(alert)
                
                db.session.commit()
                logging.critical(f"HONEYPOT COMPROMISED: {honeypot.file_path}")
        
        except Exception as e:
            logging.error(f"Error verifying honeypot {honeypot.file_path}: {e}")
