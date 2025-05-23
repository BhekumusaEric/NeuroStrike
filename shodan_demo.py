#!/usr/bin/env python3
"""
Shodan API Demo Script
Shows how the Shodan API integration enhances NeuroStrike's capabilities
"""

import os
import json
import requests
from dotenv import load_dotenv

def main():
    """Main function to demonstrate Shodan API integration"""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get Shodan API key from environment
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        print("Error: Shodan API key not found in environment variables")
        return
    
    # Target to analyze (Cloudflare DNS)
    target = "1.1.1.1"
    
    print(f"Analyzing target: {target} using Shodan API")
    print("-" * 50)
    
    # Query Shodan API for host information
    url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
    
    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            
            # Print basic information
            print(f"IP: {data.get('ip_str', 'N/A')}")
            print(f"Organization: {data.get('org', 'N/A')}")
            print(f"ISP: {data.get('isp', 'N/A')}")
            print(f"Country: {data.get('country_name', 'N/A')}")
            print(f"City: {data.get('city', 'N/A')}")
            print(f"Last Update: {data.get('last_update', 'N/A')}")
            
            # Print open ports
            ports = data.get('ports', [])
            print(f"\nOpen Ports: {', '.join(map(str, ports))}")
            
            # Print hostnames
            hostnames = data.get('hostnames', [])
            if hostnames:
                print(f"\nHostnames:")
                for hostname in hostnames:
                    print(f"  - {hostname}")
            
            # Print vulnerabilities if any
            vulns = data.get('vulns', {})
            if vulns:
                print(f"\nVulnerabilities:")
                for vuln_id in vulns:
                    print(f"  - {vuln_id}")
            
            # Print services
            print(f"\nServices:")
            for service in data.get('data', [])[:5]:  # Limit to 5 services
                port = service.get('port', 'N/A')
                transport = service.get('transport', 'N/A')
                product = service.get('product', 'N/A')
                version = service.get('version', 'N/A')
                
                print(f"  - {port}/{transport}: {product} {version}")
                
                # Print banner sample (truncated)
                banner = service.get('data', '')
                if banner:
                    banner_sample = banner[:100] + "..." if len(banner) > 100 else banner
                    print(f"    Banner: {banner_sample}")
            
            print("\nThis information would be used by NeuroStrike to enhance vulnerability analysis")
            print("and generate more accurate exploitation and mitigation strategies.")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error querying Shodan API: {e}")

if __name__ == "__main__":
    main()
