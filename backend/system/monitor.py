import psutil
import platform
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any
import json
import subprocess
import os
import sys

logger = logging.getLogger(__name__)

class SystemMonitor:
    """System monitoring and control module for JARVIS"""
    
    def __init__(self):
        self.monitoring_active = False
        self.alert_thresholds = {
            "cpu_percent": 80,
            "memory_percent": 85,
            "disk_percent": 90,
            "temperature": 70  # Celsius
        }
        logger.info("System Monitor initialized")
    
    async def get_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        try:
            # Basic system info
            system_info = {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "processor": platform.processor(),
                "timestamp": datetime.now().isoformat()
            }
            
            # CPU information
            cpu_info = {
                "physical_cores": psutil.cpu_count(logical=False),
                "total_cores": psutil.cpu_count(logical=True),
                "max_frequency": psutil.cpu_freq().max if psutil.cpu_freq() else "N/A",
                "min_frequency": psutil.cpu_freq().min if psutil.cpu_freq() else "N/A",
                "current_frequency": psutil.cpu_freq().current if psutil.cpu_freq() else "N/A",
                "cpu_usage": psutil.cpu_percent(interval=1),
                "cpu_usage_per_core": psutil.cpu_percent(interval=1, percpu=True)
            }
            
            # Memory information
            memory = psutil.virtual_memory()
            memory_info = {
                "total": self.bytes_to_gb(memory.total),
                "available": self.bytes_to_gb(memory.available),
                "used": self.bytes_to_gb(memory.used),
                "percentage": memory.percent,
                "free": self.bytes_to_gb(memory.free)
            }
            
            # Disk information
            disk_info = []
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    # On Windows, skip CD-ROM drives to avoid errors
                    if platform.system() == "Windows" and 'cdrom' in partition.opts:
                        continue
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "file_system": partition.fstype,
                        "total_size": self.bytes_to_gb(partition_usage.total),
                        "used": self.bytes_to_gb(partition_usage.used),
                        "free": self.bytes_to_gb(partition_usage.free),
                        "percentage": (partition_usage.used / partition_usage.total) * 100
                    })
                except PermissionError:
                    continue
            
            # Network information
            network_info = self.get_network_info()
            
            # Running processes (top 10 by CPU usage)
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage and get top 10
            processes = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:10]
            
            # Battery information (if available)
            battery_info = self.get_battery_info()
            
            # Temperature information (if available)
            temperature_info = self.get_temperature_info()
            
            # System alerts
            alerts = self.check_system_alerts(cpu_info, memory_info, disk_info)
            
            return {
                "system": system_info,
                "cpu": cpu_info,
                "memory": memory_info,
                "disk": disk_info,
                "network": network_info,
                "processes": processes,
                "battery": battery_info,
                "temperature": temperature_info,
                "alerts": alerts,
                "status": "healthy" if not alerts else "warning"
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "status": "error"
            }
    
    def bytes_to_gb(self, bytes_value: int) -> float:
        """Convert bytes to gigabytes"""
        return round(bytes_value / (1024**3), 2)
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get network interface information"""
        try:
            network_stats = psutil.net_io_counters()
            network_interfaces = psutil.net_if_addrs()
            
            interfaces = []
            for interface_name, interface_addresses in network_interfaces.items():
                for address in interface_addresses:
                    if str(address.family) == 'AddressFamily.AF_INET':
                        interfaces.append({
                            "interface": interface_name,
                            "ip": address.address,
                            "netmask": address.netmask,
                            "broadcast": address.broadcast
                        })
            
            return {
                "bytes_sent": network_stats.bytes_sent,
                "bytes_received": network_stats.bytes_recv,
                "packets_sent": network_stats.packets_sent,
                "packets_received": network_stats.packets_recv,
                "interfaces": interfaces
            }
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return {"error": str(e)}
    
    def get_battery_info(self) -> Dict[str, Any]:
        """Get battery information if available"""
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    "percent": battery.percent,
                    "power_plugged": battery.power_plugged,
                    "time_left": battery.secsleft if battery.secsleft != psutil.POWER_TIME_UNLIMITED else "unlimited"
                }
            else:
                return {"status": "No battery detected"}
        except Exception as e:
            logger.error(f"Error getting battery info: {e}")
            return {"error": str(e)}
    
    def get_temperature_info(self) -> Dict[str, Any]:
        """Get system temperature information if available"""
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                temperature_data = {}
                for name, entries in temps.items():
                    temperature_data[name] = []
                    for entry in entries:
                        temperature_data[name].append({
                            "label": entry.label or name,
                            "current": entry.current,
                            "high": entry.high,
                            "critical": entry.critical
                        })
                return temperature_data
            else:
                return {"status": "No temperature sensors detected"}
        except Exception as e:
            logger.error(f"Error getting temperature info: {e}")
            return {"error": str(e)}
    
    def check_system_alerts(self, cpu_info: Dict, memory_info: Dict, disk_info: List) -> List[Dict[str, Any]]:
        """Check for system alerts based on thresholds"""
        alerts = []
        
        # CPU usage alert
        if cpu_info.get("cpu_usage", 0) > self.alert_thresholds["cpu_percent"]:
            alerts.append({
                "type": "cpu_high",
                "severity": "warning",
                "message": f"High CPU usage: {cpu_info['cpu_usage']}%",
                "threshold": self.alert_thresholds["cpu_percent"],
                "current_value": cpu_info["cpu_usage"],
                "timestamp": datetime.now().isoformat()
            })
        
        # Memory usage alert
        if memory_info.get("percentage", 0) > self.alert_thresholds["memory_percent"]:
            alerts.append({
                "type": "memory_high",
                "severity": "warning",
                "message": f"High memory usage: {memory_info['percentage']}%",
                "threshold": self.alert_thresholds["memory_percent"],
                "current_value": memory_info["percentage"],
                "timestamp": datetime.now().isoformat()
            })
        
        # Disk usage alerts
        for disk in disk_info:
            if disk.get("percentage", 0) > self.alert_thresholds["disk_percent"]:
                alerts.append({
                    "type": "disk_high",
                    "severity": "critical",
                    "message": f"High disk usage on {disk['device']}: {disk['percentage']:.1f}%",
                    "threshold": self.alert_thresholds["disk_percent"],
                    "current_value": disk["percentage"],
                    "device": disk["device"],
                    "timestamp": datetime.now().isoformat()
                })
        
        return alerts
    
    async def control_system(self, action: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Control system functions safely"""
        try:
            if parameters is None:
                parameters = {}
            
            result = {"success": False, "message": "", "timestamp": datetime.now().isoformat()}
            
            if action == "shutdown":
                # Safety check - require confirmation
                if not parameters.get("confirmed", False):
                    result["message"] = "Shutdown requires confirmation"
                    result["requires_confirmation"] = True
                    return result
                
                logger.warning("System shutdown initiated by JARVIS")
                # In production, implement actual shutdown
                result["message"] = "System shutdown initiated (simulation mode)"
                result["success"] = True
                
            elif action == "restart":
                if not parameters.get("confirmed", False):
                    result["message"] = "Restart requires confirmation"
                    result["requires_confirmation"] = True
                    return result
                
                logger.warning("System restart initiated by JARVIS")
                result["message"] = "System restart initiated (simulation mode)"
                result["success"] = True
                
            elif action == "sleep":
                logger.info("System sleep initiated by JARVIS")
                result["message"] = "System sleep initiated (simulation mode)"
                result["success"] = True
                
            elif action == "kill_process":
                pid = parameters.get("pid")
                if not pid:
                    result["message"] = "Process ID required"
                    return result
                
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    
                    # Safety check - don't kill critical processes
                    critical_processes = ["init", "kernel", "systemd", "explorer.exe", "winlogon.exe"]
                    if process_name.lower() in [p.lower() for p in critical_processes]:
                        result["message"] = f"Cannot kill critical process: {process_name}"
                        return result
                    
                    process.terminate()
                    result["message"] = f"Process {process_name} (PID: {pid}) terminated"
                    result["success"] = True
                    
                except psutil.NoSuchProcess:
                    result["message"] = f"Process with PID {pid} not found"
                except psutil.AccessDenied:
                    result["message"] = f"Access denied to terminate process PID {pid}"
                
            elif action == "set_alert_threshold":
                threshold_type = parameters.get("type")
                value = parameters.get("value")
                
                if threshold_type in self.alert_thresholds and isinstance(value, (int, float)):
                    self.alert_thresholds[threshold_type] = value
                    result["message"] = f"Alert threshold for {threshold_type} set to {value}"
                    result["success"] = True
                else:
                    result["message"] = "Invalid threshold type or value"
            
            else:
                result["message"] = f"Unknown system action: {action}"
            
            return result
            
        except Exception as e:
            logger.error(f"Error in system control: {e}")
            return {
                "success": False,
                "message": f"Error executing system control: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    async def get_process_list(self, filter_by: str = None) -> List[Dict[str, Any]]:
        """Get detailed process list with optional filtering"""
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
                try:
                    proc_info = proc.info
                    proc_info['create_time'] = datetime.fromtimestamp(proc_info['create_time']).isoformat()
                    
                    # Apply filter if specified
                    if filter_by:
                        if filter_by.lower() not in proc_info['name'].lower():
                            continue
                    
                    processes.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage
            processes = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)
            
            return processes
            
        except Exception as e:
            logger.error(f"Error getting process list: {e}")
            return []
    
    async def monitor_file_system(self, path: str) -> Dict[str, Any]:
        """Monitor file system changes in specified path"""
        try:
            if not os.path.exists(path):
                return {"error": f"Path {path} does not exist"}
            
            # Get directory statistics
            total_files = 0
            total_dirs = 0
            total_size = 0
            
            for root, dirs, files in os.walk(path):
                total_dirs += len(dirs)
                total_files += len(files)
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        total_size += os.path.getsize(file_path)
                    except (OSError, IOError):
                        pass
            
            return {
                "path": path,
                "total_files": total_files,
                "total_directories": total_dirs,
                "total_size_gb": self.bytes_to_gb(total_size),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error monitoring file system: {e}")
            return {"error": str(e)}
    
    def start_monitoring(self):
        """Start continuous system monitoring"""
        self.monitoring_active = True
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop continuous system monitoring"""
        self.monitoring_active = False
        logger.info("System monitoring stopped")
