#!/usr/bin/env python3
"""
Enhanced CLI Demo Script for NeuroStrike
Demonstrates the new enhanced CLI features and functionality
"""

import os
import sys
import argparse
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from interface.cli import start_cli
from agents.red_agent import RedAgent
from agents.blue_agent import BlueAgent
from utils.logger import get_logger

def create_demo_config():
    """Create a demo configuration with enhanced settings"""
    return {
        'safe_mode': True,
        'auto_remediate': False,
        'verbose': True,
        'log_level': 'INFO',
        'demo_mode': True,
        'enhanced_features': {
            'colored_output': True,
            'auto_save': True,
            'command_history': True,
            'interactive_tutorials': True,
            'advanced_scanning': True,
            'detailed_reporting': True
        }
    }

def print_banner():
    """Print the enhanced CLI banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║    ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ███████╗████████╗██████╗     ║
    ║    ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗    ║
    ║    ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║███████╗   ██║   ██████╔╝    ║
    ║    ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══██╗    ║
    ║    ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║    ║
    ║    ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝    ║
    ║                                                                              ║
    ║                        🚀 ENHANCED CLI DEMO 🚀                              ║
    ║                                                                              ║
    ║    Welcome to the NeuroStrike Enhanced Command Line Interface!              ║
    ║                                                                              ║
    ║    🔥 NEW FEATURES:                                                          ║
    ║    • Colored output and improved UX                                          ║
    ║    • Advanced command parsing with options                                   ║
    ║    • Interactive tutorials and workflows                                     ║
    ║    • Session management and auto-save                                        ║
    ║    • Enhanced error handling and suggestions                                 ║
    ║    • Detailed status monitoring                                              ║
    ║    • Command history and session replay                                      ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_quick_start():
    """Print quick start guide"""
    print("\n🚀 QUICK START GUIDE:")
    print("=" * 60)
    print("1. Type 'status' to see current system state")
    print("2. Type 'tutorial' for an interactive walkthrough")
    print("3. Type 'workflow' to see suggested command sequences")
    print("4. Type 'set target 127.0.0.1' to set a safe target")
    print("5. Type 'help' to see all available commands")
    print("=" * 60)

def main():
    """Main function to start the enhanced CLI demo"""
    parser = argparse.ArgumentParser(
        description="NeuroStrike Enhanced CLI Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enhanced_cli_demo.py --mode both
  python enhanced_cli_demo.py --mode red --safe-mode
  python enhanced_cli_demo.py --mode blue --auto-remediate
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['red', 'blue', 'both'],
        default='both',
        help='Agent mode to run (default: both)'
    )
    
    parser.add_argument(
        '--safe-mode',
        action='store_true',
        default=True,
        help='Enable safe mode (default: enabled)'
    )
    
    parser.add_argument(
        '--auto-remediate',
        action='store_true',
        help='Enable auto-remediation for Blue Agent'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Skip the banner display'
    )
    
    parser.add_argument(
        '--demo-data',
        action='store_true',
        help='Load demo data for testing'
    )
    
    args = parser.parse_args()
    
    # Print banner unless disabled
    if not args.no_banner:
        print_banner()
        print_quick_start()
    
    # Setup logging
    logger = get_logger("enhanced_cli_demo")
    logger.info("Starting NeuroStrike Enhanced CLI Demo")
    
    # Create configuration
    config = create_demo_config()
    config['safe_mode'] = args.safe_mode
    config['auto_remediate'] = args.auto_remediate
    
    # Initialize agents based on mode
    red_agent = None
    blue_agent = None
    
    try:
        if args.mode in ['red', 'both']:
            print("🔴 Initializing Red Agent...")
            red_agent = RedAgent(config)
            red_agent.safe_mode = args.safe_mode
            print(f"   Safe Mode: {'ON' if args.safe_mode else 'OFF'}")
        
        if args.mode in ['blue', 'both']:
            print("🔵 Initializing Blue Agent...")
            blue_agent = BlueAgent(config)
            blue_agent.auto_remediate = args.auto_remediate
            print(f"   Auto-Remediate: {'ON' if args.auto_remediate else 'OFF'}")
        
        # Load demo data if requested
        if args.demo_data:
            print("📊 Loading demo data...")
            load_demo_data(red_agent, blue_agent)
        
        print("\n✅ Initialization complete!")
        print("🎯 Starting Enhanced CLI...")
        
        # Start the enhanced CLI
        start_cli(red_agent=red_agent, blue_agent=blue_agent, config=config)
        
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye! Thanks for using NeuroStrike Enhanced CLI!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start Enhanced CLI: {e}")
        print(f"❌ Error: {e}")
        print("\n💡 Troubleshooting:")
        print("• Check that all dependencies are installed")
        print("• Verify your Python environment")
        print("• Run 'pip install -r requirements.txt'")
        sys.exit(1)

def load_demo_data(red_agent, blue_agent):
    """Load demo data for testing purposes"""
    # This would load sample scan results, vulnerabilities, etc.
    # for demonstration purposes
    demo_scan_results = {
        "network_info": {
            "hosts_up": ["127.0.0.1", "192.168.1.1"]
        },
        "ports_and_services": {
            "open_ports": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
                {"port": 80, "service": "http", "version": "Apache 2.4"},
                {"port": 443, "service": "https", "version": "Apache 2.4"}
            ]
        }
    }
    
    demo_vulnerabilities = [
        {
            "description": "Outdated SSH version with known vulnerabilities",
            "severity": "Medium",
            "cve": "CVE-2023-1234",
            "exploitation_difficulty": "Medium"
        },
        {
            "description": "Apache server information disclosure",
            "severity": "Low",
            "cve": "CVE-2023-5678",
            "exploitation_difficulty": "Easy"
        }
    ]
    
    if red_agent:
        red_agent.scan_results = demo_scan_results
        red_agent.vulnerabilities = demo_vulnerabilities
    
    print("   Demo scan results loaded")
    print("   Demo vulnerabilities loaded")

if __name__ == "__main__":
    main()
