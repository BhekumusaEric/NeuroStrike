#!/usr/bin/env python3
"""
NeuroStrike: AI Red vs Blue Cyber War Game
Main entry point for the application
"""

import os
import sys
import argparse
import yaml
from dotenv import load_dotenv

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import NeuroStrike modules
from utils.logger import setup_logger
from agents.red_agent import RedAgent
from agents.blue_agent import BlueAgent
from interface.cli import CLI
from interface.app_ui import WebUI

def load_config(config_path="config/settings.yaml"):
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="NeuroStrike: AI Red vs Blue Cyber War Game")
    
    parser.add_argument("--mode", choices=["red", "blue", "both"], default="both",
                        help="Operation mode: red (offensive), blue (defensive), or both")
    
    parser.add_argument("--target", type=str, help="Target IP address or network range (CIDR notation)")
    
    parser.add_argument("--config", type=str, default="config/settings.yaml",
                        help="Path to configuration file")
    
    parser.add_argument("--ui", choices=["cli", "web"], default="cli",
                        help="User interface: cli (command line) or web (browser-based)")
    
    parser.add_argument("--scan-only", action="store_true",
                        help="Perform scanning only, no exploitation")
    
    parser.add_argument("--verbose", "-v", action="count", default=0,
                        help="Increase verbosity (can be used multiple times)")
    
    return parser.parse_args()

def main():
    """Main entry point for NeuroStrike"""
    # Load environment variables from .env file
    load_dotenv()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config)
    
    # Set up logging
    log_level = "DEBUG" if args.verbose > 0 else config["logging"]["level"]
    logger = setup_logger("neurostrike", log_level)
    logger.info("Starting NeuroStrike")
    
    # Initialize agents based on mode
    red_agent = None
    blue_agent = None
    
    if args.mode in ["red", "both"]:
        logger.info("Initializing Red Agent")
        red_config = config["red_agent"]
        red_config["scan_only"] = args.scan_only
        red_agent = RedAgent(red_config)
    
    if args.mode in ["blue", "both"]:
        logger.info("Initializing Blue Agent")
        blue_agent = BlueAgent(config["blue_agent"])
    
    # Start the appropriate UI
    if args.ui == "cli":
        ui = CLI(red_agent, blue_agent, config)
        ui.start()
    else:
        ui = WebUI(red_agent, blue_agent, config)
        ui.start()

if __name__ == "__main__":
    main()
