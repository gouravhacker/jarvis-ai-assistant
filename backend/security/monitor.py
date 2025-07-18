import asyncio
import logging
import psutil
import socket
import subprocess
import hashlib
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import sqlite3
import threading
import time

logger = logging.getLogger(__name__)

class SecurityMonitor:
    """Advanced security monitoring and threat detection for JARVIS"""
    
    def __init__(self):
        self.monitoring_active = False
        self.threat_db_path = Path("security_threats.db")
        self.known_threats = set()
        self.network_baseline = {}
        self.process_baseline = set()
        self.file_integrity_hashes = {}
        
        # Security thresholds
        self.thresholds = {
            "max_failed_logins": 5,
            "max_network_connections": 1000,
            "suspicious_cpu_usage": 90,
            "max_new_processes_per_minute": 50,
            "max_file_changes_per_minute": 100
        }
        
        # Initialize threat database
        self.init_threat_db()
        
        # Load known threat signatures
        self.load_threat_signatures()
        
        logger.info("Security Monitor initialized")

        # Import nmap and yara here to avoid import errors if not installed
        try:
            import nmap
            self.nmap = nmap.PortScanner()
        except ImportError:
            self.nmap = None
            logger.warning("nmap module not found, network scanning disabled")

        try:
            import yara
            self.yara = yara
        except ImportError:
            self.yara = None
            logger.warning("yara module not found, yara scanning disabled")
    
    def init_threat_db(self):
        """Initialize SQLite database for threat tracking"""
        try:
            conn = sqlite3.connect(self.threat_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source_ip TEXT,
                    process_name TEXT,
                    file_path TEXT,
                    action_taken TEXT,
                    resolved BOOLEAN DEFAULT FALSE
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    port INTEGER,
                    protocol TEXT,
                    suspicious BOOLEAN DEFAULT FALSE
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_integrity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    hash_value TEXT NOT NULL,
                    last_modified TEXT NOT NULL,
                    monitored BOOLEAN DEFAULT TRUE
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("Security threat database initialized")
            
        except Exception as e:
            logger.error(f"Error initializing threat database: {e}")
            raise
    
    def load_threat_signatures(self):
        """Load known threat signatures and patterns"""
        try:
            # Common malware process names
            malware_processes = [
                "cryptolocker", "wannacry", "petya", "notpetya", "ryuk",
                "maze", "sodinokibi", "revil", "darkside", "conti",
                "keylogger", "trojan", "backdoor", "rootkit"
            ]
            
            # Suspicious network patterns
            suspicious_domains = [
                "tempuri.org", "bit.ly", "tinyurl.com", "pastebin.com"
            ]
            
            # Suspicious file extensions
            suspicious_extensions = [
                ".scr", ".pif", ".bat", ".cmd", ".com", ".exe", ".vbs", ".js"
            ]
            
            self.threat_signatures = {
                "malware_processes": malware_processes,
                "suspicious_domains": suspicious_domains,
                "suspicious_extensions": suspicious_extensions
            }
            
            logger.info("Threat signatures loaded")
            
        except Exception as e:
            logger.error(f"Error loading threat signatures: {e}")
    
    async def check_threats(self) -> List[Dict[str, Any]]:
        """Comprehensive threat detection check"""
        threats = []
        
        try:
            # Check for suspicious processes
            process_threats = await self.check_suspicious_processes()
            threats.extend(process_threats)
            
            # Check network connections
            network_threats = await self.check_network_threats()
            threats.extend(network_threats)
            
            # Check file system integrity
            file_threats = await self.check_file_integrity()
            threats.extend(file_threats)
            
            # Check system resources for anomalies
            resource_threats = await self.check_resource_anomalies()
            threats.extend(resource_threats)
            
            # Check for USB/external device connections
            usb_threats = await self.check_usb_devices()
            threats.extend(usb_threats)

            # Run YARA scan on critical system directory (example)
            if self.yara:
                yara_result = self.run_yara_scan("/etc")
                if yara_result and "matches" in yara_result.lower():
                    threats.append({
                        "type": "yara_scan",
                        "severity": "high",
                        "description": f"YARA scan detected threats: {yara_result}",
                        "timestamp": datetime.now().isoformat()
                    })

            # Run Nmap scan on localhost (example)
            if self.nmap:
                try:
                    self.nmap.scan('127.0.0.1', arguments='-sS -T4')
                    nmap_report = self.nmap.csv()
                    threats.append({
                        "type": "nmap_scan",
                        "severity": "medium",
                        "description": f"Nmap scan results:\n{nmap_report}",
                        "timestamp": datetime.now().isoformat()
                    })
                except Exception as e:
                    logger.error(f"Error running Nmap scan: {e}")

            # Store threats in database
            for threat in threats:
                self.store_threat(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            return [{
                "type": "system_error",
                "severity": "medium",
                "description": f"Error in threat detection: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }]
    
    async def check_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Check for suspicious running processes"""
        threats = []
        
        try:
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
                try:
                    proc_info = proc.info
                    process_name = proc_info['name'].lower()
                    current_processes.add(proc_info['pid'])
                    
                    # Check against known malware signatures
                    for malware in self.threat_signatures["malware_processes"]:
                        if malware in process_name:
                            threats.append({
                                "type": "malware_process",
                                "severity": "critical",
                                "description": f"Potential malware process detected: {proc_info['name']}",
                                "process_name": proc_info['name'],
                                "pid": proc_info['pid'],
                                "cpu_usage": proc_info['cpu_percent'],
                                "memory_usage": proc_info['memory_percent'],
                                "timestamp": datetime.now().isoformat()
                            })
                    
                    # Check for high resource usage
                    if proc_info['cpu_percent'] and proc_info['cpu_percent'] > self.thresholds["suspicious_cpu_usage"]:
                        threats.append({
                            "type": "high_cpu_usage",
                            "severity": "medium",
                            "description": f"Process {proc_info['name']} using {proc_info['cpu_percent']}% CPU",
                            "process_name": proc_info['name'],
                            "pid": proc_info['pid'],
                            "cpu_usage": proc_info['cpu_percent'],
                            "timestamp": datetime.now().isoformat()
                        })
                    
                    # Check for suspicious command line arguments
                    if proc_info['cmdline']:
                        cmdline = ' '.join(proc_info['cmdline']).lower()
                        suspicious_args = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'regsvr32']
                        for arg in suspicious_args:
                            if arg in cmdline and 'hidden' in cmdline:
                                threats.append({
                                    "type": "suspicious_command",
                                    "severity": "high",
                                    "description": f"Suspicious command line detected: {' '.join(proc_info['cmdline'])}",
                                    "process_name": proc_info['name'],
                                    "pid": proc_info['pid'],
                                    "command_line": ' '.join(proc_info['cmdline']),
                                    "timestamp": datetime.now().isoformat()
                                })
                                break
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for rapid process creation
            new_processes = current_processes - self.process_baseline
            if len(new_processes) > self.thresholds["max_new_processes_per_minute"]:
                threats.append({
                    "type": "rapid_process_creation",
                    "severity": "high",
                    "description": f"{len(new_processes)} new processes created in the last minute",
                    "new_process_count": len(new_processes),
                    "timestamp": datetime.now().isoformat()
                })
            
            self.process_baseline = current_processes
            
        except Exception as e:
            logger.error(f"Error checking suspicious processes: {e}")
        
        return threats
    
    async def check_network_threats(self) -> List[Dict[str, Any]]:
        """Check for suspicious network activity"""
        threats = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            # Count connections by type
            connection_counts = {"tcp": 0, "udp": 0}
            suspicious_connections = []
            
            for conn in connections:
                if conn.family == socket.AF_INET:
                    if conn.type == socket.SOCK_STREAM:
                        connection_counts["tcp"] += 1
                    elif conn.type == socket.SOCK_DGRAM:
                        connection_counts["udp"] += 1
                    
                    # Check for suspicious ports
                    if conn.laddr and conn.laddr.port in [4444, 5555, 6666, 7777, 8888, 9999]:
                        suspicious_connections.append({
                            "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            "status": conn.status,
                            "pid": conn.pid
                        })
            
            # Check for too many connections
            total_connections = sum(connection_counts.values())
            if total_connections > self.thresholds["max_network_connections"]:
                threats.append({
                    "type": "excessive_connections",
                    "severity": "medium",
                    "description": f"Excessive network connections detected: {total_connections}",
                    "connection_count": total_connections,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Report suspicious connections
            for conn in suspicious_connections:
                threats.append({
                    "type": "suspicious_connection",
                    "severity": "high",
                    "description": f"Suspicious network connection on port {conn['local_addr']}",
                    "connection_details": conn,
                    "timestamp": datetime.now().isoformat()
                })
            
        except Exception as e:
            logger.error(f"Error checking network threats: {e}")
        
        return threats
    
    async def check_file_integrity(self) -> List[Dict[str, Any]]:
        """Check file system integrity for critical files"""
        threats = []
        
        try:
            # Critical system files to monitor (adjust based on OS)
            critical_files = [
                "/etc/passwd", "/etc/shadow", "/etc/hosts",  # Linux
                "C:\\Windows\\System32\\drivers\\etc\\hosts",  # Windows
                "C:\\Windows\\System32\\config\\SAM"  # Windows
            ]
            
            for file_path in critical_files:
                if os.path.exists(file_path):
                    try:
                        # Calculate current hash
                        current_hash = self.calculate_file_hash(file_path)
                        
                        # Check against stored hash
                        stored_hash = self.file_integrity_hashes.get(file_path)
                        
                        if stored_hash and stored_hash != current_hash:
                            threats.append({
                                "type": "file_integrity_violation",
                                "severity": "critical",
                                "description": f"Critical file modified: {file_path}",
                                "file_path": file_path,
                                "old_hash": stored_hash,
                                "new_hash": current_hash,
                                "timestamp": datetime.now().isoformat()
                            })
                        
                        # Update stored hash
                        self.file_integrity_hashes[file_path] = current_hash
                        
                    except Exception as e:
                        logger.error(f"Error checking file {file_path}: {e}")
            
        except Exception as e:
            logger.error(f"Error in file integrity check: {e}")
        
        return threats
    
    async def check_resource_anomalies(self) -> List[Dict[str, Any]]:
        """Check for resource usage anomalies"""
        threats = []
        
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 95:
                threats.append({
                    "type": "cpu_anomaly",
                    "severity": "medium",
                    "description": f"Extremely high CPU usage: {cpu_percent}%",
                    "cpu_usage": cpu_percent,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Check memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 95:
                threats.append({
                    "type": "memory_anomaly",
                    "severity": "medium",
                    "description": f"Extremely high memory usage: {memory.percent}%",
                    "memory_usage": memory.percent,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Check disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                # This would need baseline comparison in production
                pass
            
        except Exception as e:
            logger.error(f"Error checking resource anomalies: {e}")
        
        return threats
    
    async def check_usb_devices(self) -> List[Dict[str, Any]]:
        """Check for new USB/external device connections"""
        threats = []
        
        try:
            # Get current disk partitions
            current_partitions = set()
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts or 'usb' in partition.opts.lower():
                    current_partitions.add(partition.device)
            
            # Compare with baseline (this would need persistent storage in production)
            if hasattr(self, 'usb_baseline'):
                new_devices = current_partitions - self.usb_baseline
                for device in new_devices:
                    threats.append({
                        "type": "usb_device_connected",
                        "severity": "low",
                        "description": f"New USB device connected: {device}",
                        "device": device,
                        "timestamp": datetime.now().isoformat()
                    })
            
            self.usb_baseline = current_partitions
            
        except Exception as e:
            logger.error(f"Error checking USB devices: {e}")
        
        return threats
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def store_threat(self, threat: Dict[str, Any]):
        """Store threat information in database"""
        try:
            conn = sqlite3.connect(self.threat_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO threats (timestamp, threat_type, severity, description, 
                                   source_ip, process_name, file_path, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat.get("timestamp", datetime.now().isoformat()),
                threat.get("type", "unknown"),
                threat.get("severity", "low"),
                threat.get("description", ""),
                threat.get("source_ip"),
                threat.get("process_name"),
                threat.get("file_path"),
                threat.get("action_taken", "logged")
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing threat: {e}")
    
    async def run_full_scan(self) -> Dict[str, Any]:
        """Run comprehensive security scan"""
        try:
            logger.info("Starting full security scan...")
            start_time = datetime.now()
            
            # Run all threat checks
            all_threats = await self.check_threats()
            
            # Additional deep scans
            port_scan_results = await self.scan_open_ports()
            vulnerability_scan = await self.check_vulnerabilities()
            
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()
            
            results = {
                "scan_start": start_time.isoformat(),
                "scan_end": end_time.isoformat(),
                "scan_duration_seconds": scan_duration,
                "threats_found": len(all_threats),
                "threats": all_threats,
                "open_ports": port_scan_results,
                "vulnerabilities": vulnerability_scan,
                "status": "completed"
            }
            
            logger.info(f"Security scan completed in {scan_duration:.2f} seconds. Found {len(all_threats)} threats.")
            
            return results
            
        except Exception as e:
            logger.error(f"Error in full security scan: {e}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def scan_open_ports(self) -> List[Dict[str, Any]]:
        """Scan for open ports on localhost"""
        open_ports = []
        
        try:
            # Common ports to check
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "status": "open",
                        "service": self.get_service_name(port)
                    })
                
                sock.close()
            
        except Exception as e:
            logger.error(f"Error scanning ports: {e}")
        
        return open_ports
    
    def get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 3389: "RDP", 5432: "PostgreSQL",
            3306: "MySQL"
        }
        return services.get(port, "Unknown")
    
    async def check_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for common system vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for outdated software (simplified)
            # In production, this would integrate with vulnerability databases
            
            # Check Windows updates (if on Windows)
            if os.name == 'nt':
                try:
                    result = subprocess.run(['powershell', 'Get-WUList'], 
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0 and result.stdout:
                        vulnerabilities.append({
                            "type": "missing_updates",
                            "severity": "medium",
                            "description": "Windows updates available",
                            "details": "System may have missing security updates"
                        })
                except:
                    pass
            
            # Check for weak passwords (placeholder)
            vulnerabilities.append({
                "type": "password_policy",
                "severity": "low",
                "description": "Password policy check needed",
                "details": "Manual verification of password policies recommended"
            })
            
        except Exception as e:
            logger.error(f"Error checking vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def quarantine_threat(self, threat_id: str, action: str) -> Dict[str, Any]:
        """Take action against identified threats"""
        try:
            # This would implement actual threat response
            # For now, just log the action
            
            logger.warning(f"Threat response action: {action} for threat {threat_id}")
            
            return {
                "success": True,
                "action": action,
                "threat_id": threat_id,
                "timestamp": datetime.now().isoformat(),
                "message": f"Action {action} taken against threat {threat_id}"
            }
            
        except Exception as e:
            logger.error(f"Error in threat response: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def start_monitoring(self):
        """Start continuous security monitoring"""
        self.monitoring_active = True
        logger.info("Security monitoring started")
    
    def stop_monitoring(self):
        """Stop continuous security monitoring"""
        self.monitoring_active = False
        logger.info("Security monitoring stopped")
