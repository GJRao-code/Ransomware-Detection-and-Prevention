import psutil
import logging
import threading
import time
import os
from datetime import datetime
from collections import deque

class SystemMonitor:
    def __init__(self):
        self.cpu_history = deque(maxlen=60)  # Keep last 60 readings
        self.memory_history = deque(maxlen=60)
        self.disk_history = deque(maxlen=60)
        self.network_history = deque(maxlen=60)
        self.process_history = deque(maxlen=60)
        self.threat_level_history = deque(maxlen=60)
        
        self.monitoring = False
        self.monitor_thread = None
        
        # Alert thresholds
        self.cpu_threshold = 85.0
        self.memory_threshold = 90.0
        self.disk_threshold = 95.0
        self.process_threshold = 500
    
    def get_system_health(self):
        """Get current system health metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Process count
            process_count = len(psutil.pids())
            
            # Network connections
            try:
                connections = psutil.net_connections(kind='inet')
                connection_count = len(connections)
            except (psutil.AccessDenied, OSError):
                connection_count = 0
            
            # Determine overall threat level
            threat_level = self.calculate_threat_level(
                cpu_percent, memory_percent, disk_percent, process_count
            )
            
            health_data = {
                'timestamp': datetime.utcnow(),
                'cpu_usage': cpu_percent,
                'memory_usage': memory_percent,
                'disk_usage': disk_percent,
                'active_processes': process_count,
                'network_connections': connection_count,
                'threat_level': threat_level
            }
            
            # Store in history
            self.cpu_history.append(cpu_percent)
            self.memory_history.append(memory_percent)
            self.disk_history.append(disk_percent)
            self.process_history.append(process_count)
            self.network_history.append(connection_count)
            self.threat_level_history.append(threat_level)
            
            return health_data
        
        except Exception as e:
            logging.error(f"Error getting system health: {e}")
            return {
                'timestamp': datetime.utcnow(),
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0,
                'active_processes': 0,
                'network_connections': 0,
                'threat_level': 'unknown'
            }
    
    def calculate_threat_level(self, cpu_percent, memory_percent, disk_percent, process_count):
        """Calculate overall system threat level"""
        try:
            threat_score = 0
            
            # CPU usage scoring
            if cpu_percent > 90:
                threat_score += 3
            elif cpu_percent > 75:
                threat_score += 2
            elif cpu_percent > 50:
                threat_score += 1
            
            # Memory usage scoring
            if memory_percent > 95:
                threat_score += 3
            elif memory_percent > 85:
                threat_score += 2
            elif memory_percent > 70:
                threat_score += 1
            
            # Disk usage scoring
            if disk_percent > 98:
                threat_score += 2
            elif disk_percent > 90:
                threat_score += 1
            
            # Process count scoring
            if process_count > 400:
                threat_score += 2
            elif process_count > 300:
                threat_score += 1
            
            # Determine threat level
            if threat_score >= 6:
                return 'critical'
            elif threat_score >= 4:
                return 'high'
            elif threat_score >= 2:
                return 'medium'
            else:
                return 'low'
        
        except Exception as e:
            logging.error(f"Error calculating threat level: {e}")
            return 'unknown'
    
    def get_cpu_info(self):
        """Get detailed CPU information"""
        try:
            cpu_info = {
                'cpu_count_physical': psutil.cpu_count(logical=False),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'cpu_percent_per_core': psutil.cpu_percent(percpu=True),
                'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                'cpu_times': psutil.cpu_times()._asdict(),
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None
            }
            return cpu_info
        
        except Exception as e:
            logging.error(f"Error getting CPU info: {e}")
            return {}
    
    def get_memory_info(self):
        """Get detailed memory information"""
        try:
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            memory_info = {
                'virtual_memory': {
                    'total': virtual_memory.total,
                    'available': virtual_memory.available,
                    'used': virtual_memory.used,
                    'free': virtual_memory.free,
                    'percent': virtual_memory.percent,
                    'buffers': getattr(virtual_memory, 'buffers', 0),
                    'cached': getattr(virtual_memory, 'cached', 0)
                },
                'swap_memory': {
                    'total': swap_memory.total,
                    'used': swap_memory.used,
                    'free': swap_memory.free,
                    'percent': swap_memory.percent
                }
            }
            return memory_info
        
        except Exception as e:
            logging.error(f"Error getting memory info: {e}")
            return {}
    
    def get_disk_info(self):
        """Get detailed disk information"""
        try:
            disk_partitions = psutil.disk_partitions()
            disk_info = []
            
            for partition in disk_partitions:
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    partition_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': disk_usage.total,
                        'used': disk_usage.used,
                        'free': disk_usage.free,
                        'percent': disk_usage.percent
                    }
                    disk_info.append(partition_info)
                
                except (PermissionError, OSError):
                    continue
            
            # Disk I/O statistics
            try:
                disk_io = psutil.disk_io_counters()
                disk_io_info = disk_io._asdict() if disk_io else {}
            except:
                disk_io_info = {}
            
            return {
                'partitions': disk_info,
                'io_counters': disk_io_info
            }
        
        except Exception as e:
            logging.error(f"Error getting disk info: {e}")
            return {}
    
    def get_network_info(self):
        """Get detailed network information"""
        try:
            # Network I/O statistics
            net_io = psutil.net_io_counters()
            net_io_info = net_io._asdict() if net_io else {}
            
            # Network interfaces
            net_interfaces = {}
            for interface, addrs in psutil.net_if_addrs().items():
                net_interfaces[interface] = []
                for addr in addrs:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    net_interfaces[interface].append(addr_info)
            
            # Active connections
            try:
                connections = psutil.net_connections(kind='inet')
                connection_info = []
                for conn in connections[:50]:  # Limit to first 50
                    conn_info = {
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    connection_info.append(conn_info)
            except (psutil.AccessDenied, OSError):
                connection_info = []
            
            return {
                'io_counters': net_io_info,
                'interfaces': net_interfaces,
                'connections': connection_info
            }
        
        except Exception as e:
            logging.error(f"Error getting network info: {e}")
            return {}
    
    def get_process_info(self, limit=20):
        """Get information about running processes"""
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time', 'cmdline']):
                try:
                    process_info = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent'],
                        'status': proc.info['status'],
                        'create_time': proc.info['create_time'],
                        'cmdline': ' '.join(proc.info['cmdline'] or [])[:100]  # Limit command line length
                    }
                    processes.append(process_info)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Sort by CPU usage and return top processes
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            return processes[:limit]
        
        except Exception as e:
            logging.error(f"Error getting process info: {e}")
            return []
    
    def detect_suspicious_processes(self):
        """Detect potentially suspicious processes"""
        try:
            suspicious_processes = []
            suspicious_names = [
                'encrypt', 'crypto', 'ransom', 'locker', 'cipher',
                'bitcoin', 'wallet', 'miner', 'keylogger', 'backdoor'
            ]
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    process_name = proc.info['name'].lower()
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    
                    # Check for suspicious names
                    is_suspicious = False
                    matched_pattern = None
                    
                    for suspicious in suspicious_names:
                        if suspicious in process_name or suspicious in cmdline:
                            is_suspicious = True
                            matched_pattern = suspicious
                            break
                    
                    # Check for high resource usage
                    cpu_percent = proc.info['cpu_percent'] or 0
                    memory_percent = proc.info['memory_percent'] or 0
                    
                    if cpu_percent > 80 or memory_percent > 20:
                        if not is_suspicious:
                            is_suspicious = True
                            matched_pattern = 'high_resource_usage'
                    
                    if is_suspicious:
                        suspicious_info = {
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': ' '.join(proc.info['cmdline'] or [])[:200],
                            'cpu_percent': cpu_percent,
                            'memory_percent': memory_percent,
                            'reason': matched_pattern,
                            'detected_at': datetime.utcnow().isoformat()
                        }
                        suspicious_processes.append(suspicious_info)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            return suspicious_processes
        
        except Exception as e:
            logging.error(f"Error detecting suspicious processes: {e}")
            return []
    
    def get_system_alerts(self):
        """Get system alerts based on current metrics"""
        try:
            alerts = []
            health_data = self.get_system_health()
            
            # CPU alerts
            if health_data['cpu_usage'] > self.cpu_threshold:
                alerts.append({
                    'type': 'cpu_high',
                    'severity': 'high' if health_data['cpu_usage'] > 95 else 'medium',
                    'message': f"High CPU usage: {health_data['cpu_usage']:.1f}%",
                    'value': health_data['cpu_usage'],
                    'threshold': self.cpu_threshold
                })
            
            # Memory alerts
            if health_data['memory_usage'] > self.memory_threshold:
                alerts.append({
                    'type': 'memory_high',
                    'severity': 'high' if health_data['memory_usage'] > 95 else 'medium',
                    'message': f"High memory usage: {health_data['memory_usage']:.1f}%",
                    'value': health_data['memory_usage'],
                    'threshold': self.memory_threshold
                })
            
            # Disk alerts
            if health_data['disk_usage'] > self.disk_threshold:
                alerts.append({
                    'type': 'disk_full',
                    'severity': 'high',
                    'message': f"Disk space low: {health_data['disk_usage']:.1f}% used",
                    'value': health_data['disk_usage'],
                    'threshold': self.disk_threshold
                })
            
            # Process count alerts
            if health_data['active_processes'] > self.process_threshold:
                alerts.append({
                    'type': 'process_count_high',
                    'severity': 'medium',
                    'message': f"High process count: {health_data['active_processes']}",
                    'value': health_data['active_processes'],
                    'threshold': self.process_threshold
                })
            
            # Suspicious process alerts
            suspicious_processes = self.detect_suspicious_processes()
            for proc in suspicious_processes:
                alerts.append({
                    'type': 'suspicious_process',
                    'severity': 'high',
                    'message': f"Suspicious process detected: {proc['name']} (PID: {proc['pid']})",
                    'process_info': proc
                })
            
            return alerts
        
        except Exception as e:
            logging.error(f"Error getting system alerts: {e}")
            return []
    
    def start_monitoring(self, interval=60):
        """Start continuous system monitoring"""
        try:
            if self.monitoring:
                return False
            
            self.monitoring = True
            
            def monitor_loop():
                while self.monitoring:
                    try:
                        # Get system health
                        health_data = self.get_system_health()
                        
                        # Check for alerts
                        alerts = self.get_system_alerts()
                        
                        if alerts:
                            logging.warning(f"System alerts: {len(alerts)} alerts detected")
                            for alert in alerts:
                                logging.warning(f"Alert: {alert['message']}")
                    
                    except Exception as e:
                        logging.error(f"Error in monitoring loop: {e}")
                    
                    time.sleep(interval)
            
            self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            logging.info("System monitoring started")
            return True
        
        except Exception as e:
            logging.error(f"Error starting system monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        try:
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            logging.info("System monitoring stopped")
            return True
        
        except Exception as e:
            logging.error(f"Error stopping system monitoring: {e}")
            return False
    
    def get_history_data(self, metric='cpu', limit=60):
        """Get historical data for a specific metric"""
        try:
            history_map = {
                'cpu': list(self.cpu_history),
                'memory': list(self.memory_history),
                'disk': list(self.disk_history),
                'network': list(self.network_history),
                'processes': list(self.process_history),
                'threat_level': list(self.threat_level_history)
            }
            
            if metric in history_map:
                data = history_map[metric][-limit:]
                return data
            else:
                return []
        
        except Exception as e:
            logging.error(f"Error getting history data: {e}")
            return []
    
    def export_system_report(self):
        """Export comprehensive system report"""
        try:
            report = {
                'timestamp': datetime.utcnow().isoformat(),
                'system_health': self.get_system_health(),
                'cpu_info': self.get_cpu_info(),
                'memory_info': self.get_memory_info(),
                'disk_info': self.get_disk_info(),
                'network_info': self.get_network_info(),
                'process_info': self.get_process_info(50),
                'suspicious_processes': self.detect_suspicious_processes(),
                'system_alerts': self.get_system_alerts(),
                'history': {
                    'cpu': self.get_history_data('cpu'),
                    'memory': self.get_history_data('memory'),
                    'disk': self.get_history_data('disk'),
                    'threat_level': self.get_history_data('threat_level')
                }
            }
            
            return report
        
        except Exception as e:
            logging.error(f"Error exporting system report: {e}")
            return {}
