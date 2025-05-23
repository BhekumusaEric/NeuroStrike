#!/usr/bin/env python3
"""
VirusTotal API Demo Script
Shows how the VirusTotal API integration enhances NeuroStrike's capabilities
"""

import os
import json
import requests
from dotenv import load_dotenv

def main():
    """Main function to demonstrate VirusTotal API integration"""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get VirusTotal API key from environment
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("Error: VirusTotal API key not found in environment variables")
        return
    
    # Target to analyze (Cloudflare DNS)
    target = "1.1.1.1"
    
    print(f"Analyzing target: {target} using VirusTotal API")
    print("-" * 50)
    
    # Query VirusTotal API for IP information
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Print basic information
            print(f"IP: {target}")
            print(f"AS Owner: {attributes.get('as_owner', 'N/A')}")
            print(f"Country: {attributes.get('country', 'N/A')}")
            print(f"Continent: {attributes.get('continent', 'N/A')}")
            
            # Print reputation information
            reputation = attributes.get('reputation', 0)
            print(f"\nReputation: {reputation}")
            
            # Print security categories
            last_analysis = attributes.get('last_analysis_results', {})
            if last_analysis:
                print(f"\nSecurity Vendor Results:")
                
                # Count results by category
                categories = {}
                for vendor, result in last_analysis.items():
                    category = result.get('category', 'unknown')
                    if category not in categories:
                        categories[category] = 0
                    categories[category] += 1
                
                for category, count in categories.items():
                    print(f"  - {category}: {count} vendors")
                
                # Print some specific vendor results
                print(f"\nSample Vendor Results:")
                vendors_sample = list(last_analysis.items())[:5]  # Take 5 vendors as sample
                for vendor, result in vendors_sample:
                    category = result.get('category', 'unknown')
                    method = result.get('method', 'unknown')
                    print(f"  - {vendor}: {category} (method: {method})")
            
            # Print recent URLs associated with this IP
            urls = attributes.get('last_https_certificate', {}).get('extensions', {}).get('subject_alternative_name', [])
            if urls:
                print(f"\nAssociated Domains:")
                for url in urls[:5]:  # Limit to 5 domains
                    print(f"  - {url}")
            
            print("\nThis information would be used by NeuroStrike to enhance threat intelligence")
            print("and identify potential security risks associated with the target.")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error querying VirusTotal API: {e}")

if __name__ == "__main__":
    main()
