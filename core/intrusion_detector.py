"""
Intrusion Detector Module
Handles detection of intrusions and security events
"""

import re
import os
import time
import json
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

class IntrusionDetector:
    """
    Intrusion Detector for monitoring and analyzing security events
    """
    
    def __init__(self):
        """Initialize the Intrusion Detector"""
        self.logger = get_logger("intrusion_detector")
        self.last_check_time = time.time()
        self.known_events = []
    
    def monitor(self) -> Dict[str, Any]:
        """
        Monitor the system for security events
        
        Returns:
            Dictionary containing monitoring results
        """
        self.logger.info("Monitoring system for security events")
        
        current_time = time.time()
        results = {
            "start_time": self.last_check_time,
            "end_time": current_time,
            "events": []
        }
        
        # Check various log sources
        auth_events = self._check_auth_logs()
        firewall_events = self._check_firewall_logs()
        ids_events = self._check_ids_logs()
        
        # Combine all events
        all_events = auth_events + firewall_events + ids_events
        
        # Filter out events we've already seen
        new_events = [event for event in all_events if event not in self.known_events]
        
        # Update known events
        self.known_events.extend(new_events)
        
        # Update last check time
        self.last_check_time = current_time
        
        # Add events to results
        results["events"] = new_events
        results["total_events"] = len(new_events)
        
        return results
    
    def _check_auth_logs(self) -> List[Dict[str, Any]]:
        """Check authentication logs for security events"""
        events = []
        
        # Common auth log paths
        auth_log_paths = [
            "/var/log/auth.log",
            "/var/log/secure"
        ]
        
        for log_path in auth_log_paths:
            if os.path.exists(log_path):
                try:
                    # Get file modification time
                    mod_time = os.path.getmtime(log_path)
                    
                    # Only check if file has been modified since last check
                    if mod_time > self.last_check_time:
                        with open(log_path, 'r') as f:
                            # Read the last 100 lines (adjust as needed)
                            lines = f.readlines()[-100:]
                            
                            for line in lines:
                                # Look for failed login attempts
                                if "Failed password" in line or "authentication failure" in line:
                                    # Extract timestamp
                                    timestamp_match = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                                    timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
                                    
                                    # Extract username if available
                                    user_match = re.search(r'user\s+(\w+)', line)
                                    username = user_match.group(1) if user_match else "Unknown"
                                    
                                    # Extract IP if available
                                    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                                    ip = ip_match.group(1) if ip_match else "Unknown"
                                    
                                    events.append({
                                        "type": "auth",
                                        "subtype": "failed_login",
                                        "timestamp": timestamp,
                                        "username": username,
                                        "source_ip": ip,
                                        "raw_log": line.strip()
                                    })
                                
                                # Look for successful logins
                                elif "Accepted password" in line or "session opened" in line:
                                    # Extract timestamp
                                    timestamp_match = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                                    timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
                                    
                                    # Extract username if available
                                    user_match = re.search(r'user\s+(\w+)', line)
                                    username = user_match.group(1) if user_match else "Unknown"
                                    
                                    # Extract IP if available
                                    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                                    ip = ip_match.group(1) if ip_match else "Unknown"
                                    
                                    events.append({
                                        "type": "auth",
                                        "subtype": "successful_login",
                                        "timestamp": timestamp,
                                        "username": username,
                                        "source_ip": ip,
                                        "raw_log": line.strip()
                                    })
                except Exception as e:
                    self.logger.error(f"Error checking auth log {log_path}: {e}")
        
        return events
    
    def _check_firewall_logs(self) -> List[Dict[str, Any]]:
        """Check firewall logs for security events"""
        events = []
        
        # Common firewall log paths
        firewall_log_paths = [
            "/var/log/ufw.log",
            "/var/log/iptables.log",
            "/var/log/firewall.log"
        ]
        
        for log_path in firewall_log_paths:
            if os.path.exists(log_path):
                try:
                    # Get file modification time
                    mod_time = os.path.getmtime(log_path)
                    
                    # Only check if file has been modified since last check
                    if mod_time > self.last_check_time:
                        with open(log_path, 'r') as f:
                            # Read the last 100 lines (adjust as needed)
                            lines = f.readlines()[-100:]
                            
                            for line in lines:
                                # Look for blocked connections
                                if "BLOCK" in line or "DROP" in line:
                                    # Extract timestamp
                                    timestamp_match = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                                    timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
                                    
                                    # Extract source IP
                                    src_ip_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
                                    src_ip = src_ip_match.group(1) if src_ip_match else "Unknown"
                                    
                                    # Extract destination IP
                                    dst_ip_match = re.search(r'DST=(\d+\.\d+\.\d+\.\d+)', line)
                                    dst_ip = dst_ip_match.group(1) if dst_ip_match else "Unknown"
                                    
                                    # Extract ports
                                    src_port_match = re.search(r'SPT=(\d+)', line)
                                    src_port = src_port_match.group(1) if src_port_match else "Unknown"
                                    
                                    dst_port_match = re.search(r'DPT=(\d+)', line)
                                    dst_port = dst_port_match.group(1) if dst_port_match else "Unknown"
                                    
                                    # Extract protocol
                                    proto_match = re.search(r'PROTO=(\w+)', line)
                                    proto = proto_match.group(1) if proto_match else "Unknown"
                                    
                                    events.append({
                                        "type": "firewall",
                                        "subtype": "blocked_connection",
                                        "timestamp": timestamp,
                                        "source_ip": src_ip,
                                        "source_port": src_port,
                                        "destination_ip": dst_ip,
                                        "destination_port": dst_port,
                                        "protocol": proto,
                                        "raw_log": line.strip()
                                    })
                except Exception as e:
                    self.logger.error(f"Error checking firewall log {log_path}: {e}")
        
        return events
    
    def _check_ids_logs(self) -> List[Dict[str, Any]]:
        """Check IDS logs for security events"""
        events = []
        
        # Common IDS log paths
        ids_log_paths = [
            "/var/log/snort/alert",
            "/var/log/suricata/fast.log",
            "/var/log/ids.log"
        ]
        
        for log_path in ids_log_paths:
            if os.path.exists(log_path):
                try:
                    # Get file modification time
                    mod_time = os.path.getmtime(log_path)
                    
                    # Only check if file has been modified since last check
                    if mod_time > self.last_check_time:
                        with open(log_path, 'r') as f:
                            # Read the last 100 lines (adjust as needed)
                            lines = f.readlines()[-100:]
                            
                            for line in lines:
                                # Extract timestamp
                                timestamp_match = re.search(r'^(\d+/\d+/\d+-\d+:\d+:\d+\.\d+)', line)
                                timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
                                
                                # Extract alert message
                                msg_match = re.search(r'\[\*\*\] \[(.*?)\] (.*?) \[\*\*\]', line)
                                alert_id = msg_match.group(1) if msg_match else "Unknown"
                                alert_msg = msg_match.group(2) if msg_match else "Unknown"
                                
                                # Extract IPs
                                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):?(\d*) -> (\d+\.\d+\.\d+\.\d+):?(\d*)', line)
                                if ip_match:
                                    src_ip = ip_match.group(1)
                                    src_port = ip_match.group(2) if ip_match.group(2) else "Unknown"
                                    dst_ip = ip_match.group(3)
                                    dst_port = ip_match.group(4) if ip_match.group(4) else "Unknown"
                                else:
                                    src_ip = "Unknown"
                                    src_port = "Unknown"
                                    dst_ip = "Unknown"
                                    dst_port = "Unknown"
                                
                                events.append({
                                    "type": "ids",
                                    "subtype": "alert",
                                    "timestamp": timestamp,
                                    "alert_id": alert_id,
                                    "alert_message": alert_msg,
                                    "source_ip": src_ip,
                                    "source_port": src_port,
                                    "destination_ip": dst_ip,
                                    "destination_port": dst_port,
                                    "raw_log": line.strip()
                                })
                except Exception as e:
                    self.logger.error(f"Error checking IDS log {log_path}: {e}")
        
        return events
    
    def parse_assessment(self, llm_response: str) -> Dict[str, Any]:
        """
        Parse a vulnerability assessment from LLM response
        
        Args:
            llm_response: Response from LLM containing vulnerability assessment
            
        Returns:
            Dictionary containing the parsed assessment
        """
        self.logger.info("Parsing vulnerability assessment from LLM response")
        
        assessment = {
            "verification": "Unknown",
            "severity": "Unknown",
            "impact": "",
            "affected_components": [],
            "cvss_score": 0.0
        }
        
        # Extract verification status
        verification_pattern = r'(?i)verification:?\s*(Confirmed|Possible|False Positive)'
        verification_match = re.search(verification_pattern, llm_response)
        if verification_match:
            assessment["verification"] = verification_match.group(1)
        
        # Extract severity
        severity_pattern = r'(?i)severity:?\s*(Critical|High|Medium|Low)'
        severity_match = re.search(severity_pattern, llm_response)
        if severity_match:
            assessment["severity"] = severity_match.group(1)
        
        # Extract impact
        impact_pattern = r'(?i)(?:potential )?impact:?\s*(.*?)(?:(?:\d+\.)|(?:affected)|(?:cvss)|$)'
        impact_match = re.search(impact_pattern, llm_response, re.DOTALL)
        if impact_match:
            assessment["impact"] = impact_match.group(1).strip()
        
        # Extract affected components
        components_pattern = r'(?i)affected components:?\s*(.*?)(?:(?:\d+\.)|(?:cvss)|$)'
        components_match = re.search(components_pattern, llm_response, re.DOTALL)
        if components_match:
            components_text = components_match.group(1).strip()
            # Split by newlines or commas
            components = re.split(r'[\n,]', components_text)
            assessment["affected_components"] = [comp.strip() for comp in components if comp.strip()]
        
        # Extract CVSS score
        cvss_pattern = r'(?i)cvss(?:\s+score)?:?\s*(\d+(?:\.\d+)?)'
        cvss_match = re.search(cvss_pattern, llm_response)
        if cvss_match:
            try:
                assessment["cvss_score"] = float(cvss_match.group(1))
            except ValueError:
                pass
        
        return assessment
