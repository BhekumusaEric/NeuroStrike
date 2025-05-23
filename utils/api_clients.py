"""
API Clients Module
Provides clients for various security APIs
"""

import os
import json
import requests
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

class ShodanClient:
    """
    Client for interacting with the Shodan API
    """
    
    def __init__(self):
        """Initialize the Shodan client"""
        self.logger = get_logger("shodan_client")
        self.api_key = os.environ.get("SHODAN_API_KEY")
        
        if not self.api_key:
            self.logger.warning("Shodan API key not found in environment variables")
        else:
            self.logger.info("Shodan client initialized")
    
    def host_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Look up information about a host
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            Dictionary containing host information
        """
        if not self.api_key:
            self.logger.error("Shodan API key not available")
            return {"error": "API key not available"}
        
        try:
            url = f"https://api.shodan.io/shodan/host/{ip_address}?key={self.api_key}"
            response = requests.get(url)
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Shodan API error: {response.status_code} - {response.text}")
                return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            self.logger.error(f"Error querying Shodan API: {e}")
            return {"error": str(e)}
    
    def search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """
        Search Shodan for hosts matching a query
        
        Args:
            query: Shodan search query
            limit: Maximum number of results to return
            
        Returns:
            Dictionary containing search results
        """
        if not self.api_key:
            self.logger.error("Shodan API key not available")
            return {"error": "API key not available"}
        
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={self.api_key}&query={query}&limit={limit}"
            response = requests.get(url)
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Shodan API error: {response.status_code} - {response.text}")
                return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            self.logger.error(f"Error querying Shodan API: {e}")
            return {"error": str(e)}

class VirusTotalClient:
    """
    Client for interacting with the VirusTotal API
    """
    
    def __init__(self):
        """Initialize the VirusTotal client"""
        self.logger = get_logger("virustotal_client")
        self.api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        
        if not self.api_key:
            self.logger.warning("VirusTotal API key not found in environment variables")
        else:
            self.logger.info("VirusTotal client initialized")
    
    def _make_request(self, endpoint: str, method: str = "GET", data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the VirusTotal API"""
        if not self.api_key:
            self.logger.error("VirusTotal API key not available")
            return {"error": "API key not available"}
        
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return {"error": f"Unsupported HTTP method: {method}"}
            
            if response.status_code in [200, 201]:
                return response.json()
            else:
                self.logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            self.logger.error(f"Error querying VirusTotal API: {e}")
            return {"error": str(e)}
    
    def get_ip_report(self, ip_address: str) -> Dict[str, Any]:
        """
        Get a report for an IP address
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            Dictionary containing IP report
        """
        endpoint = f"ip_addresses/{ip_address}"
        return self._make_request(endpoint)
    
    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Get a report for a domain
        
        Args:
            domain: Domain to look up
            
        Returns:
            Dictionary containing domain report
        """
        endpoint = f"domains/{domain}"
        return self._make_request(endpoint)
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get a report for a file hash
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of the file
            
        Returns:
            Dictionary containing file report
        """
        endpoint = f"files/{file_hash}"
        return self._make_request(endpoint)

def get_shodan_client() -> ShodanClient:
    """Get a Shodan client instance"""
    return ShodanClient()

def get_virustotal_client() -> VirusTotalClient:
    """Get a VirusTotal client instance"""
    return VirusTotalClient()
