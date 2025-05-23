"""
Network Analyzer Module
Handles network scanning and vulnerability analysis
"""

import re
import json
import subprocess
import socket
import ipaddress
import os
from typing import Dict, List, Any, Optional, Union

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from utils.logger import get_logger
from utils.api_clients import get_shodan_client, get_virustotal_client

# Check if Shodan API key is available
SHODAN_AVAILABLE = bool(os.environ.get("SHODAN_API_KEY"))

# Check if VirusTotal API key is available
VIRUSTOTAL_AVAILABLE = bool(os.environ.get("VIRUSTOTAL_API_KEY"))

class NetworkAnalyzer:
    """
    Network Analyzer for scanning and analyzing network targets
    """

    def __init__(self):
        """Initialize the Network Analyzer"""
        self.logger = get_logger("network_analyzer")

        # Check if nmap is available
        if not NMAP_AVAILABLE:
            self.logger.warning("python-nmap not installed. Some functionality will be limited.")

        # Initialize nmap scanner if available
        self.nmap_scanner = nmap.PortScanner() if NMAP_AVAILABLE else None

    def scan_network(self, target: str) -> Dict[str, Any]:
        """
        Scan a network target for information gathering

        Args:
            target: IP address, hostname, or CIDR range

        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Scanning target: {target}")

        results = {
            "target": target,
            "system_info": {},
            "network_info": {},
            "ports_and_services": {},
            "vulnerabilities": []
        }

        # Validate target
        try:
            if '/' in target:  # CIDR notation
                ipaddress.ip_network(target)
            else:
                ipaddress.ip_address(target)
        except ValueError:
            # Not an IP address, try to resolve hostname
            try:
                socket.gethostbyname(target)
            except socket.gaierror:
                self.logger.error(f"Invalid target: {target}")
                results["error"] = f"Invalid target: {target}"
                return results

        # Perform basic host discovery
        results["network_info"] = self._perform_host_discovery(target)

        # Perform port scanning
        results["ports_and_services"] = self._perform_port_scan(target)

        # Gather system information
        results["system_info"] = self._gather_system_info(target)

        return results

    def _perform_host_discovery(self, target: str) -> Dict[str, Any]:
        """Perform host discovery on the target"""
        self.logger.info(f"Performing host discovery on {target}")

        result = {
            "hosts_up": [],
            "hosts_down": [],
            "total_hosts": 0
        }

        if NMAP_AVAILABLE:
            try:
                # Use nmap for host discovery
                self.nmap_scanner.scan(hosts=target, arguments='-sn')

                for host in self.nmap_scanner.all_hosts():
                    if self.nmap_scanner[host].state() == 'up':
                        result["hosts_up"].append(host)
                    else:
                        result["hosts_down"].append(host)

                result["total_hosts"] = len(result["hosts_up"]) + len(result["hosts_down"])
            except Exception as e:
                self.logger.error(f"Error during host discovery: {e}")
                result["error"] = str(e)
        else:
            # Fallback to ping
            try:
                if '/' in target:  # CIDR notation
                    network = ipaddress.ip_network(target)
                    result["total_hosts"] = network.num_addresses
                    # For CIDR, just report the network info without scanning all hosts
                    result["hosts_up"] = [target]
                else:
                    # Simple ping
                    ping_param = "-n 1" if subprocess.call("ping") == 1 else "-c 1"
                    ping_cmd = f"ping {ping_param} {target}"
                    ping_result = subprocess.run(ping_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                    if ping_result.returncode == 0:
                        result["hosts_up"].append(target)
                    else:
                        result["hosts_down"].append(target)

                    result["total_hosts"] = 1
            except Exception as e:
                self.logger.error(f"Error during host discovery: {e}")
                result["error"] = str(e)

        return result

    def _perform_port_scan(self, target: str) -> Dict[str, Any]:
        """Perform port scanning on the target"""
        self.logger.info(f"Performing port scan on {target}")

        result = {
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {}
        }

        if NMAP_AVAILABLE:
            try:
                # Use nmap for port scanning
                # -sV: Service/version detection
                # -F: Fast mode - scan fewer ports
                self.nmap_scanner.scan(hosts=target, arguments='-sV -F')

                for host in self.nmap_scanner.all_hosts():
                    if self.nmap_scanner[host].state() == 'up':
                        for proto in self.nmap_scanner[host].all_protocols():
                            ports = sorted(self.nmap_scanner[host][proto].keys())

                            for port in ports:
                                port_info = self.nmap_scanner[host][proto][port]
                                port_state = port_info['state']

                                if port_state == 'open':
                                    result["open_ports"].append(port)
                                    result["services"][port] = {
                                        "name": port_info.get('name', 'unknown'),
                                        "product": port_info.get('product', ''),
                                        "version": port_info.get('version', ''),
                                        "extrainfo": port_info.get('extrainfo', '')
                                    }
                                elif port_state == 'closed':
                                    result["closed_ports"].append(port)
                                elif port_state == 'filtered':
                                    result["filtered_ports"].append(port)
            except Exception as e:
                self.logger.error(f"Error during port scanning: {e}")
                result["error"] = str(e)
        else:
            # Fallback to basic socket connection for common ports
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)

                    if '/' in target:  # CIDR notation
                        # Just check the network address for CIDR
                        network = ipaddress.ip_network(target)
                        host = str(network.network_address)
                    else:
                        host = target

                    result_code = sock.connect_ex((host, port))

                    if result_code == 0:
                        result["open_ports"].append(port)
                        service_name = socket.getservbyport(port) if port < 1024 else "unknown"
                        result["services"][port] = {
                            "name": service_name,
                            "product": "",
                            "version": "",
                            "extrainfo": "detected by basic socket scan"
                        }
                    else:
                        result["closed_ports"].append(port)

                    sock.close()
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {e}")
                    result["filtered_ports"].append(port)

        return result

    def _gather_system_info(self, target: str) -> Dict[str, Any]:
        """Gather system information about the target"""
        self.logger.info(f"Gathering system information for {target}")

        result = {
            "os": "unknown",
            "hostname": "unknown",
            "mac_address": "unknown",
            "uptime": "unknown",
            "last_boot": "unknown",
            "shodan_info": {},
            "virustotal_info": {}
        }

        # Use nmap for OS detection if available
        if NMAP_AVAILABLE:
            try:
                # -O: OS detection
                self.nmap_scanner.scan(hosts=target, arguments='-O')

                for host in self.nmap_scanner.all_hosts():
                    if 'osmatch' in self.nmap_scanner[host]:
                        os_matches = self.nmap_scanner[host]['osmatch']
                        if os_matches and len(os_matches) > 0:
                            result["os"] = os_matches[0].get('name', 'unknown')

                    if 'hostnames' in self.nmap_scanner[host]:
                        hostnames = self.nmap_scanner[host]['hostnames']
                        if hostnames and len(hostnames) > 0:
                            result["hostname"] = hostnames[0].get('name', 'unknown')

                    if 'addresses' in self.nmap_scanner[host]:
                        addresses = self.nmap_scanner[host]['addresses']
                        if 'mac' in addresses:
                            result["mac_address"] = addresses['mac']
            except Exception as e:
                self.logger.error(f"Error gathering system information with nmap: {e}")
                result["nmap_error"] = str(e)

        # Use Shodan for additional information if available
        if SHODAN_AVAILABLE and self._is_public_ip(target):
            try:
                shodan_client = get_shodan_client()
                shodan_info = shodan_client.host_lookup(target)

                if "error" not in shodan_info:
                    result["shodan_info"] = shodan_info

                    # Update OS info if not already known
                    if result["os"] == "unknown" and "os" in shodan_info:
                        result["os"] = shodan_info["os"]

                    # Update hostname if not already known
                    if result["hostname"] == "unknown" and "hostnames" in shodan_info and shodan_info["hostnames"]:
                        result["hostname"] = shodan_info["hostnames"][0]
                else:
                    self.logger.warning(f"Shodan lookup error: {shodan_info.get('error')}")
            except Exception as e:
                self.logger.error(f"Error gathering information from Shodan: {e}")
                result["shodan_error"] = str(e)

        # Use VirusTotal for additional information if available
        if VIRUSTOTAL_AVAILABLE and self._is_public_ip(target):
            try:
                vt_client = get_virustotal_client()
                vt_info = vt_client.get_ip_report(target)

                if "error" not in vt_info:
                    result["virustotal_info"] = vt_info
                else:
                    self.logger.warning(f"VirusTotal lookup error: {vt_info.get('error')}")
            except Exception as e:
                self.logger.error(f"Error gathering information from VirusTotal: {e}")
                result["virustotal_error"] = str(e)

        return result

    def _is_public_ip(self, ip: str) -> bool:
        """Check if an IP address is public"""
        try:
            # Handle CIDR notation
            if '/' in ip:
                ip = ip.split('/')[0]

            # Convert to IP address object
            ip_obj = ipaddress.ip_address(ip)

            # Check if it's a private or loopback address
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
        except ValueError:
            # If it's not a valid IP (e.g., a hostname), assume it's public
            return True

    def parse_vulnerabilities(self, llm_response: str) -> List[Dict[str, Any]]:
        """
        Parse vulnerabilities from LLM response

        Args:
            llm_response: Response from LLM containing vulnerability information

        Returns:
            List of parsed vulnerabilities
        """
        self.logger.info("Parsing vulnerabilities from LLM response")

        vulnerabilities = []

        # Simple parsing based on common patterns in the response
        # This is a basic implementation and can be improved

        # Look for numbered vulnerabilities
        vuln_pattern = r'(\d+\.\s*.*?(?=\d+\.\s*|\Z))'
        matches = re.findall(vuln_pattern, llm_response, re.DOTALL)

        if matches:
            for i, match in enumerate(matches):
                vuln = {
                    "id": i + 1,
                    "description": match.strip(),
                    "severity": self._extract_severity(match),
                    "cve": self._extract_cve(match),
                    "exploitation_difficulty": self._extract_difficulty(match)
                }
                vulnerabilities.append(vuln)
        else:
            # Alternative parsing if numbered format not found
            # Split by common headers
            sections = re.split(r'Vulnerability|CVE|Impact|Severity|Exploitation', llm_response)
            if len(sections) > 1:
                # Reconstruct vulnerabilities from sections
                current_vuln = {}
                for i, section in enumerate(sections):
                    if i == 0:  # Skip the first split which is usually empty
                        continue

                    if "description" not in current_vuln:
                        current_vuln["id"] = len(vulnerabilities) + 1
                        current_vuln["description"] = section.strip()
                    elif "severity" not in current_vuln:
                        current_vuln["severity"] = self._extract_severity(section)
                    elif "cve" not in current_vuln:
                        current_vuln["cve"] = self._extract_cve(section)
                    elif "exploitation_difficulty" not in current_vuln:
                        current_vuln["exploitation_difficulty"] = self._extract_difficulty(section)
                        vulnerabilities.append(current_vuln)
                        current_vuln = {}
            else:
                # If all else fails, just return the whole response as one vulnerability
                vulnerabilities.append({
                    "id": 1,
                    "description": llm_response.strip(),
                    "severity": self._extract_severity(llm_response),
                    "cve": self._extract_cve(llm_response),
                    "exploitation_difficulty": self._extract_difficulty(llm_response)
                })

        return vulnerabilities

    def _extract_severity(self, text: str) -> str:
        """Extract severity from text"""
        severity_pattern = r'(?i)(critical|high|medium|low|informational)'
        match = re.search(severity_pattern, text)
        return match.group(1).capitalize() if match else "Unknown"

    def _extract_cve(self, text: str) -> str:
        """Extract CVE from text"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        match = re.search(cve_pattern, text)
        return match.group(0) if match else "N/A"

    def _extract_difficulty(self, text: str) -> str:
        """Extract exploitation difficulty from text"""
        difficulty_pattern = r'(?i)(easy|medium|hard|difficult)'
        match = re.search(difficulty_pattern, text)
        return match.group(1).capitalize() if match else "Unknown"
