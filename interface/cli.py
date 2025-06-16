"""
Enhanced Command Line Interface Module
Provides a comprehensive CLI for interacting with NeuroStrike
"""

import os
import sys
import cmd
import json
import time
import shlex
import subprocess
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
import ipaddress
import re

from utils.logger import get_logger

class EnhancedCLI(cmd.Cmd):
    """
    Enhanced Command Line Interface for NeuroStrike
    Provides comprehensive cybersecurity operations with improved UX
    """

    intro = """
    ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
    ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
    ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

    🔴 Enhanced AI Red vs Blue Cyber War Game 🔵

    Welcome to NeuroStrike Enhanced CLI!

    🚀 Quick Start:
    • Type 'status' to see current system state
    • Type 'workflow' to see suggested command sequences
    • Type 'help' or '?' to list all commands
    • Type 'tutorial' for an interactive tutorial

    💡 Pro Tips:
    • Use 'set target <ip>' to set a default target
    • Use 'history' to see command history
    • Use 'save session' to save your current session
    """

    def __init__(self, red_agent=None, blue_agent=None, config=None):
        """Initialize the Enhanced CLI"""
        super().__init__()
        self.logger = get_logger("enhanced_cli")
        self.red_agent = red_agent
        self.blue_agent = blue_agent
        self.config = config or {}

        # Enhanced state tracking
        self.current_target = None
        self.scan_results = None
        self.vulnerabilities = None
        self.exploit_plans = []
        self.exploitation_results = []
        self.mitigation_plans = []
        self.applied_mitigations = []
        self.command_history = []
        self.session_start_time = datetime.now()
        self.auto_save = True

        # Color codes for better UX
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'end': '\033[0m'
        }

        # Update prompt with colors and status
        self._update_prompt()

        self.logger.info("Enhanced CLI initialized")

    def _update_prompt(self):
        """Update the prompt with current status"""
        status_color = self.colors['green'] if self.current_target else self.colors['yellow']
        target_info = f"[{self.current_target}]" if self.current_target else "[no target]"

        agent_status = ""
        if self.red_agent and self.blue_agent:
            agent_status = f"{self.colors['red']}R{self.colors['end']}/{self.colors['blue']}B{self.colors['end']}"
        elif self.red_agent:
            agent_status = f"{self.colors['red']}R{self.colors['end']}"
        elif self.blue_agent:
            agent_status = f"{self.colors['blue']}B{self.colors['end']}"

        self.prompt = f"{self.colors['bold']}NeuroStrike{self.colors['end']} {agent_status} {status_color}{target_info}{self.colors['end']}> "

    def _print_colored(self, text, color='white', bold=False):
        """Print colored text"""
        color_code = self.colors.get(color, self.colors['white'])
        bold_code = self.colors['bold'] if bold else ''
        print(f"{bold_code}{color_code}{text}{self.colors['end']}")

    def _print_success(self, text):
        """Print success message"""
        self._print_colored(f"✅ {text}", 'green', bold=True)

    def _print_error(self, text):
        """Print error message"""
        self._print_colored(f"❌ {text}", 'red', bold=True)

    def _print_warning(self, text):
        """Print warning message"""
        self._print_colored(f"⚠️  {text}", 'yellow', bold=True)

    def _print_info(self, text):
        """Print info message"""
        self._print_colored(f"ℹ️  {text}", 'cyan')

    def _print_header(self, text):
        """Print section header"""
        self._print_colored(f"\n{'='*60}", 'blue')
        self._print_colored(f"{text.center(60)}", 'blue', bold=True)
        self._print_colored(f"{'='*60}", 'blue')

    def _validate_ip(self, ip_str):
        """Validate IP address or CIDR notation"""
        try:
            ipaddress.ip_network(ip_str, strict=False)
            return True
        except ValueError:
            try:
                ipaddress.ip_address(ip_str)
                return True
            except ValueError:
                return False

    def _save_command_history(self, command):
        """Save command to history"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.command_history.append({
            'timestamp': timestamp,
            'command': command,
            'target': self.current_target
        })

        if self.auto_save and len(self.command_history) % 10 == 0:
            self._auto_save_session()

    def _auto_save_session(self):
        """Auto-save session data"""
        try:
            os.makedirs("data/sessions", exist_ok=True)
            session_file = f"data/sessions/session_{int(time.time())}.json"

            session_data = {
                'start_time': self.session_start_time.isoformat(),
                'current_time': datetime.now().isoformat(),
                'target': self.current_target,
                'command_history': self.command_history[-50:],  # Last 50 commands
                'vulnerabilities_count': len(self.vulnerabilities) if self.vulnerabilities else 0,
                'exploit_plans_count': len(self.exploit_plans),
                'mitigation_plans_count': len(self.mitigation_plans)
            }

            with open(session_file, 'w') as f:
                json.dump(session_data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to auto-save session: {e}")

    def precmd(self, line):
        """Pre-process commands"""
        if line.strip():
            self._save_command_history(line.strip())
        return line

    def postcmd(self, stop, line):
        """Post-process commands"""
        self._update_prompt()
        return stop

    def start(self):
        """Start the Enhanced CLI"""
        self._print_info("Starting NeuroStrike Enhanced CLI...")
        self._print_info(f"Session started at: {self.session_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.cmdloop()

    def emptyline(self):
        """Do nothing on empty line"""
        pass

    def do_exit(self, arg):
        """Exit the program"""
        self._print_info("Saving session data...")
        self._auto_save_session()
        self._print_success("Session saved successfully!")
        self._print_info("Exiting NeuroStrike...")
        return True

    def do_quit(self, arg):
        """Exit the program (alias for exit)"""
        return self.do_exit(arg)

    def do_clear(self, arg):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(self.intro)

    def do_status(self, arg):
        """Show current system status and configuration"""
        self._print_header("SYSTEM STATUS")

        # Agent status
        self._print_colored("\n🤖 Agent Status:", 'blue', bold=True)
        if self.red_agent:
            self._print_colored("  🔴 Red Agent: ACTIVE", 'green')
            safe_mode = getattr(self.red_agent, 'safe_mode', True)
            self._print_colored(f"     Safe Mode: {'ON' if safe_mode else 'OFF'}", 'yellow' if safe_mode else 'red')
        else:
            self._print_colored("  🔴 Red Agent: INACTIVE", 'red')

        if self.blue_agent:
            self._print_colored("  🔵 Blue Agent: ACTIVE", 'green')
            auto_remediate = getattr(self.blue_agent, 'auto_remediate', False)
            self._print_colored(f"     Auto-Remediate: {'ON' if auto_remediate else 'OFF'}", 'red' if auto_remediate else 'yellow')
        else:
            self._print_colored("  🔵 Blue Agent: INACTIVE", 'red')

        # Target status
        self._print_colored("\n🎯 Target Information:", 'blue', bold=True)
        if self.current_target:
            self._print_colored(f"  Current Target: {self.current_target}", 'green')
            if self.scan_results:
                hosts_up = len(self.scan_results.get("network_info", {}).get("hosts_up", []))
                open_ports = len(self.scan_results.get("ports_and_services", {}).get("open_ports", []))
                self._print_colored(f"  Hosts Discovered: {hosts_up}", 'cyan')
                self._print_colored(f"  Open Ports: {open_ports}", 'cyan')
        else:
            self._print_colored("  No target set", 'yellow')

        # Vulnerability status
        self._print_colored("\n🔍 Vulnerability Status:", 'blue', bold=True)
        vuln_count = len(self.vulnerabilities) if self.vulnerabilities else 0
        exploit_count = len(self.exploit_plans)
        mitigation_count = len(self.mitigation_plans)

        self._print_colored(f"  Vulnerabilities Found: {vuln_count}", 'red' if vuln_count > 0 else 'green')
        self._print_colored(f"  Exploit Plans: {exploit_count}", 'yellow' if exploit_count > 0 else 'green')
        self._print_colored(f"  Mitigation Plans: {mitigation_count}", 'green' if mitigation_count > 0 else 'yellow')

        # Session info
        self._print_colored("\n📊 Session Information:", 'blue', bold=True)
        session_duration = datetime.now() - self.session_start_time
        self._print_colored(f"  Session Duration: {str(session_duration).split('.')[0]}", 'cyan')
        self._print_colored(f"  Commands Executed: {len(self.command_history)}", 'cyan')
        self._print_colored(f"  Auto-Save: {'ON' if self.auto_save else 'OFF'}", 'green' if self.auto_save else 'yellow')

    def do_set(self, arg):
        """Set configuration options
        Usage:
          set target <ip_address>     - Set default target
          set autosave <on|off>       - Enable/disable auto-save
        """
        if not arg:
            self._print_error("Missing arguments. Use 'help set' for usage.")
            return

        args = shlex.split(arg)
        if len(args) < 2:
            self._print_error("Invalid arguments. Use 'help set' for usage.")
            return

        option = args[0].lower()
        value = args[1]

        if option == 'target':
            if self._validate_ip(value):
                self.current_target = value
                self._print_success(f"Target set to: {value}")
                self._update_prompt()
            else:
                self._print_error(f"Invalid IP address or CIDR notation: {value}")
        elif option == 'autosave':
            if value.lower() in ['on', 'true', '1']:
                self.auto_save = True
                self._print_success("Auto-save enabled")
            elif value.lower() in ['off', 'false', '0']:
                self.auto_save = False
                self._print_success("Auto-save disabled")
            else:
                self._print_error("Invalid value. Use 'on' or 'off'")
        else:
            self._print_error(f"Unknown option: {option}")

    def do_workflow(self, arg):
        """Show suggested command workflows for different scenarios"""
        self._print_header("SUGGESTED WORKFLOWS")

        self._print_colored("\n🔴 Red Team (Offensive) Workflow:", 'red', bold=True)
        self._print_colored("  1. set target <ip_address>", 'white')
        self._print_colored("  2. scan <target>", 'white')
        self._print_colored("  3. analyze", 'white')
        self._print_colored("  4. exploit <vuln_id>", 'white')
        self._print_colored("  5. execute <plan_id>", 'white')
        self._print_colored("  6. report red", 'white')

        self._print_colored("\n🔵 Blue Team (Defensive) Workflow:", 'blue', bold=True)
        self._print_colored("  1. monitor", 'white')
        self._print_colored("  2. defend (after vulnerabilities found)", 'white')
        self._print_colored("  3. mitigate <plan_id>", 'white')
        self._print_colored("  4. rules <exploit_id>", 'white')
        self._print_colored("  5. report blue", 'white')

        self._print_colored("\n🔬 Binary Analysis Workflow:", 'purple', bold=True)
        self._print_colored("  1. analyze_binary <binary_path>", 'white')
        self._print_colored("  2. find_binary_vulns", 'white')
        self._print_colored("  3. binary_exploit <vuln_type> <vuln_index>", 'white')
        self._print_colored("  4. generate_yara <description>", 'white')

        self._print_colored("\n💾 Memory Analysis Workflow:", 'cyan', bold=True)
        self._print_colored("  1. analyze_memory <dump_path>", 'white')
        self._print_colored("  2. extract_artifacts", 'white')
        self._print_colored("  3. generate_iocs", 'white')

    def do_history(self, arg):
        """Show command history
        Usage:
          history           - Show last 20 commands
          history <n>       - Show last n commands
          history clear     - Clear command history
        """
        if arg == 'clear':
            self.command_history.clear()
            self._print_success("Command history cleared")
            return

        try:
            limit = int(arg) if arg else 20
        except ValueError:
            self._print_error("Invalid number. Use 'history <number>' or 'history clear'")
            return

        if not self.command_history:
            self._print_info("No command history available")
            return

        self._print_header("COMMAND HISTORY")

        recent_commands = self.command_history[-limit:]
        for i, cmd_info in enumerate(recent_commands, 1):
            timestamp = cmd_info['timestamp']
            command = cmd_info['command']
            target = cmd_info.get('target', 'N/A')

            self._print_colored(f"{i:2d}. [{timestamp}] {command}", 'cyan')
            if target != 'N/A':
                self._print_colored(f"     Target: {target}", 'yellow')

    def do_tutorial(self, arg):
        """Interactive tutorial for NeuroStrike"""
        self._print_header("NEUROSTRIKE TUTORIAL")

        self._print_colored("\n🎓 Welcome to the NeuroStrike Tutorial!", 'green', bold=True)
        self._print_info("This tutorial will guide you through basic operations.")

        if not input("\nWould you like to continue? (y/n): ").lower().startswith('y'):
            return

        # Tutorial steps
        steps = [
            {
                'title': 'Step 1: Check System Status',
                'command': 'status',
                'description': 'First, let\'s check the current system status'
            },
            {
                'title': 'Step 2: Set a Target',
                'command': 'set target 127.0.0.1',
                'description': 'Set a target IP address (using localhost for safety)'
            },
            {
                'title': 'Step 3: View Workflows',
                'command': 'workflow',
                'description': 'See suggested command workflows'
            }
        ]

        for step in steps:
            self._print_colored(f"\n{step['title']}", 'blue', bold=True)
            self._print_info(step['description'])

            if input(f"Execute '{step['command']}'? (y/n): ").lower().startswith('y'):
                self.onecmd(step['command'])

            input("\nPress Enter to continue...")

        self._print_success("Tutorial completed! Type 'help' to see all available commands.")

    def do_save(self, arg):
        """Save session data
        Usage:
          save session      - Save current session
          save config       - Save current configuration
        """
        if not arg:
            arg = 'session'

        if arg == 'session':
            try:
                os.makedirs("data/sessions", exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                session_file = f"data/sessions/manual_session_{timestamp}.json"

                session_data = {
                    'start_time': self.session_start_time.isoformat(),
                    'save_time': datetime.now().isoformat(),
                    'target': self.current_target,
                    'command_history': self.command_history,
                    'vulnerabilities_count': len(self.vulnerabilities) if self.vulnerabilities else 0,
                    'exploit_plans_count': len(self.exploit_plans),
                    'mitigation_plans_count': len(self.mitigation_plans),
                    'scan_results_available': self.scan_results is not None
                }

                with open(session_file, 'w') as f:
                    json.dump(session_data, f, indent=2)

                self._print_success(f"Session saved to: {session_file}")

            except Exception as e:
                self._print_error(f"Failed to save session: {e}")

        elif arg == 'config':
            try:
                os.makedirs("data/configs", exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                config_file = f"data/configs/config_{timestamp}.json"

                config_data = {
                    'target': self.current_target,
                    'auto_save': self.auto_save,
                    'red_agent_active': self.red_agent is not None,
                    'blue_agent_active': self.blue_agent is not None,
                    'safe_mode': getattr(self.red_agent, 'safe_mode', True) if self.red_agent else True,
                    'auto_remediate': getattr(self.blue_agent, 'auto_remediate', False) if self.blue_agent else False
                }

                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=2)

                self._print_success(f"Configuration saved to: {config_file}")

            except Exception as e:
                self._print_error(f"Failed to save configuration: {e}")
        else:
            self._print_error("Invalid save option. Use 'session' or 'config'")

    def do_load(self, arg):
        """Load session data
        Usage: load <session_file>
        """
        if not arg:
            self._print_error("Session file path required")
            return

        try:
            with open(arg, 'r') as f:
                session_data = json.load(f)

            # Restore session data
            self.current_target = session_data.get('target')
            self.command_history = session_data.get('command_history', [])

            self._update_prompt()
            self._print_success(f"Session loaded from: {arg}")
            self._print_info(f"Target: {self.current_target}")
            self._print_info(f"Commands in history: {len(self.command_history)}")

        except FileNotFoundError:
            self._print_error(f"Session file not found: {arg}")
        except json.JSONDecodeError:
            self._print_error(f"Invalid session file format: {arg}")
        except Exception as e:
            self._print_error(f"Failed to load session: {e}")

    def do_scan(self, arg):
        """Enhanced network scanning with detailed output
        Usage:
          scan <target>           - Scan specified target
          scan                    - Scan current target
          scan -p <ports> <target> - Scan specific ports
          scan -A <target>        - Aggressive scan (OS detection, version detection, script scanning)
        """
        # Parse arguments
        args = shlex.split(arg) if arg else []

        target = None
        port_range = None
        aggressive = False

        i = 0
        while i < len(args):
            if args[i] == '-p' and i + 1 < len(args):
                port_range = args[i + 1]
                i += 2
            elif args[i] == '-A':
                aggressive = True
                i += 1
            else:
                target = args[i]
                i += 1

        # Use current target if none specified
        if not target:
            if self.current_target:
                target = self.current_target
            else:
                self._print_error("No target specified and no current target set")
                self._print_info("Use 'set target <ip>' or 'scan <target>'")
                return

        if not self.red_agent:
            self._print_error("Red Agent not available")
            return

        try:
            self._print_header(f"SCANNING TARGET: {target}")

            # Show scan parameters
            self._print_colored("\n📋 Scan Parameters:", 'blue', bold=True)
            self._print_colored(f"  Target: {target}", 'cyan')
            if port_range:
                self._print_colored(f"  Ports: {port_range}", 'cyan')
            if aggressive:
                self._print_colored("  Mode: Aggressive (OS detection, version detection, scripts)", 'yellow')
            else:
                self._print_colored("  Mode: Standard", 'cyan')

            self._print_info("Starting scan... This may take a while.")

            # Perform the scan
            scan_options = {
                'port_range': port_range,
                'aggressive': aggressive
            }

            self.scan_results = self.red_agent.scan_target(target, **scan_options)
            self.current_target = target
            self._update_prompt()

            if self.scan_results:
                self._print_success("Scan completed successfully!")

                # Display detailed results
                self._print_colored("\n📊 Scan Results:", 'green', bold=True)

                network_info = self.scan_results.get('network_info', {})
                hosts_up = network_info.get('hosts_up', [])

                if hosts_up:
                    self._print_colored(f"  🖥️  Hosts Discovered: {len(hosts_up)}", 'green')
                    for host in hosts_up[:5]:  # Show first 5 hosts
                        self._print_colored(f"     • {host}", 'white')
                    if len(hosts_up) > 5:
                        self._print_colored(f"     ... and {len(hosts_up) - 5} more", 'yellow')

                ports_services = self.scan_results.get('ports_and_services', {})
                open_ports = ports_services.get('open_ports', [])

                if open_ports:
                    self._print_colored(f"  🔌 Open Ports: {len(open_ports)}", 'green')
                    for port in open_ports[:10]:  # Show first 10 ports
                        port_num = port.get('port', 'Unknown')
                        service = port.get('service', 'Unknown')
                        version = port.get('version', '')

                        port_info = f"     • {port_num}/{port.get('protocol', 'tcp')} - {service}"
                        if version:
                            port_info += f" ({version})"
                        self._print_colored(port_info, 'white')

                    if len(open_ports) > 10:
                        self._print_colored(f"     ... and {len(open_ports) - 10} more", 'yellow')

                # OS Detection results
                os_info = self.scan_results.get('os_detection', {})
                if os_info:
                    self._print_colored(f"  💻 OS Detection:", 'green')
                    for os_match in os_info.get('matches', [])[:3]:
                        accuracy = os_match.get('accuracy', 0)
                        name = os_match.get('name', 'Unknown')
                        self._print_colored(f"     • {name} ({accuracy}% accuracy)", 'white')

                self._print_info("\nUse 'analyze' to find vulnerabilities in the scan results")

            else:
                self._print_warning("Scan completed but no results returned")
                self._print_info("This might indicate:")
                self._print_info("  • Target is down or unreachable")
                self._print_info("  • Firewall is blocking the scan")
                self._print_info("  • Invalid target specification")

        except Exception as e:
            self._print_error(f"Scan failed: {e}")
            self.logger.error(f"Scan failed: {e}")

            # Provide helpful suggestions
            self._print_info("\n💡 Troubleshooting suggestions:")
            self._print_info("  • Check if target is reachable (ping)")
            self._print_info("  • Verify target IP address format")
            self._print_info("  • Check network connectivity")
            self._print_info("  • Try scanning a smaller port range")

    def do_analyze(self, arg):
        """
        Analyze scan results to identify vulnerabilities
        Usage: analyze
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not hasattr(self.red_agent, 'scan_results'):
            print("Error: No scan results available. Run 'scan' first.")
            return

        print("Analyzing vulnerabilities...")

        try:
            self.vulnerabilities = self.red_agent.analyze_vulnerabilities()

            if not self.vulnerabilities:
                print("No vulnerabilities found")
                return

            print(f"\nFound {len(self.vulnerabilities)} potential vulnerabilities:")

            for i, vuln in enumerate(self.vulnerabilities):
                print(f"\n[{i+1}] {vuln.get('description', 'Unknown vulnerability')[:100]}...")
                print(f"    Severity: {vuln.get('severity', 'Unknown')}")
                print(f"    CVE: {vuln.get('cve', 'N/A')}")
                print(f"    Difficulty: {vuln.get('exploitation_difficulty', 'Unknown')}")

            print("\nAnalysis completed successfully")
        except Exception as e:
            self.logger.error(f"Error during analysis: {e}")
            print(f"Error during analysis: {e}")

    def do_exploit(self, arg):
        """
        Generate an exploit plan for a vulnerability
        Usage: exploit <vulnerability_id>
        Example: exploit 1
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not self.vulnerabilities:
            print("Error: No vulnerabilities identified. Run 'analyze' first.")
            return

        try:
            vuln_id = int(arg) - 1  # Convert to 0-based index

            if vuln_id < 0 or vuln_id >= len(self.vulnerabilities):
                print(f"Error: Invalid vulnerability ID. Must be between 1 and {len(self.vulnerabilities)}")
                return

            print(f"Generating exploit plan for vulnerability {arg}...")

            exploit_plan = self.red_agent.generate_exploit_plan(vuln_id)
            self.exploit_plans.append(exploit_plan)

            print("\nExploit Plan:")
            print(f"Name: {exploit_plan.get('name', 'Unnamed exploit')}")
            print(f"Type: {exploit_plan.get('type', 'Unknown')}")

            print("\nSteps:")
            for i, step in enumerate(exploit_plan.get('steps', [])):
                print(f"  {i+1}. {step}")

            print("\nCommands:")
            for i, cmd in enumerate(exploit_plan.get('commands', [])):
                print(f"  {i+1}. {cmd}")

            print(f"\nExpected Outcome: {exploit_plan.get('expected_outcome', 'Unknown')}")

            print("\nExploit plan generated successfully")
        except ValueError:
            print("Error: Vulnerability ID must be a number")
        except Exception as e:
            self.logger.error(f"Error generating exploit plan: {e}")
            print(f"Error generating exploit plan: {e}")

    def do_execute(self, arg):
        """
        Execute an exploit plan
        Usage: execute <plan_id>
        Example: execute 1
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not self.exploit_plans:
            print("Error: No exploit plans generated. Run 'exploit' first.")
            return

        try:
            plan_id = int(arg) - 1  # Convert to 0-based index

            if plan_id < 0 or plan_id >= len(self.exploit_plans):
                print(f"Error: Invalid plan ID. Must be between 1 and {len(self.exploit_plans)}")
                return

            exploit_plan = self.exploit_plans[plan_id]

            print(f"Executing exploit plan: {exploit_plan.get('name', 'Unnamed exploit')}")

            if self.red_agent.safe_mode:
                print("WARNING: Safe mode is enabled. This will only simulate the exploit.")
                confirm = input("Continue? (y/n): ")
                if confirm.lower() != 'y':
                    print("Execution cancelled")
                    return
            else:
                print("WARNING: Safe mode is disabled. This will attempt to execute the exploit.")
                confirm = input("Continue? (y/n): ")
                if confirm.lower() != 'y':
                    print("Execution cancelled")
                    return

            result = self.red_agent.execute_exploit(exploit_plan)
            self.exploitation_results.append(result)

            print(f"\nExecution Status: {result.get('status', 'Unknown')}")

            if result.get('status') == 'simulated':
                print("\nSimulation Results:")
                for step in result.get('details', {}).get('steps_simulated', []):
                    if 'step' in step:
                        print(f"  Step {step['step']}: {step['description']}")
                        print(f"    Result: {step['simulated_result']}")
                    elif 'command' in step:
                        print(f"  Command: {step['command']}")
                        print(f"    Output: {step['simulated_output']}")
            else:
                print("\nExecution Results:")
                for output in result.get('output', []):
                    if 'command' in output:
                        print(f"  Command: {output['command']}")
                        if 'stdout' in output:
                            print(f"    Output: {output['stdout'][:200]}...")
                        if 'error' in output and output['error']:
                            print(f"    Error: {output['error']}")

            print("\nExploit execution completed")
        except ValueError:
            print("Error: Plan ID must be a number")
        except Exception as e:
            self.logger.error(f"Error executing exploit: {e}")
            print(f"Error executing exploit: {e}")

    def do_defend(self, arg):
        """
        Generate defense strategies for vulnerabilities
        Usage: defend
        """
        if not self.blue_agent:
            print("Error: Blue Agent not initialized")
            return

        if not self.vulnerabilities:
            print("Error: No vulnerabilities identified. Run 'analyze' first.")
            return

        print("Generating defense strategies...")

        try:
            # Create a vulnerability report
            vuln_report = {
                "target": self.current_target,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "vulnerabilities": self.vulnerabilities
            }

            # Create system info
            system_info = self.scan_results if self.scan_results else {}

            # Assess vulnerabilities
            assessments = self.blue_agent.assess_vulnerabilities(vuln_report, system_info)

            print(f"\nAssessed {len(assessments)} vulnerabilities:")
            for i, assessment in enumerate(assessments):
                print(f"\n[{i+1}] {assessment.get('original_vulnerability', {}).get('description', 'Unknown')[:100]}...")
                print(f"    Verification: {assessment.get('verification', 'Unknown')}")
                print(f"    Severity: {assessment.get('severity', 'Unknown')}")
                print(f"    CVSS Score: {assessment.get('cvss_score', 'N/A')}")

            # Generate mitigation plans
            self.mitigation_plans = self.blue_agent.generate_mitigations(assessments)

            print(f"\nGenerated {len(self.mitigation_plans)} mitigation plans:")
            for i, plan in enumerate(self.mitigation_plans):
                vuln_desc = plan.get('assessment', {}).get('original_vulnerability', {}).get('description', 'Unknown')
                print(f"\n[{i+1}] Mitigation for: {vuln_desc[:100]}...")

                print("    Immediate Steps:")
                for j, step in enumerate(plan.get('immediate_steps', [])[:3]):
                    print(f"      {j+1}. {step[:100]}...")
                if len(plan.get('immediate_steps', [])) > 3:
                    print(f"      ... and {len(plan.get('immediate_steps', [])) - 3} more")

                print("    Commands:")
                for j, cmd in enumerate(plan.get('commands', [])[:3]):
                    print(f"      {j+1}. {cmd[:100]}")
                if len(plan.get('commands', [])) > 3:
                    print(f"      ... and {len(plan.get('commands', [])) - 3} more")

            print("\nDefense strategies generated successfully")
        except Exception as e:
            self.logger.error(f"Error generating defense strategies: {e}")
            print(f"Error generating defense strategies: {e}")

    def do_mitigate(self, arg):
        """
        Apply a mitigation plan
        Usage: mitigate <plan_id>
        Example: mitigate 1
        """
        if not self.blue_agent:
            print("Error: Blue Agent not initialized")
            return

        if not self.mitigation_plans:
            print("Error: No mitigation plans generated. Run 'defend' first.")
            return

        try:
            plan_id = int(arg) - 1  # Convert to 0-based index

            if plan_id < 0 or plan_id >= len(self.mitigation_plans):
                print(f"Error: Invalid plan ID. Must be between 1 and {len(self.mitigation_plans)}")
                return

            mitigation_plan = self.mitigation_plans[plan_id]

            print(f"Applying mitigation plan {arg}...")

            if not self.blue_agent.auto_remediate:
                print("WARNING: Auto-remediation is disabled in configuration.")
                print("This will only simulate the mitigation.")
                confirm = input("Continue? (y/n): ")
                if confirm.lower() != 'y':
                    print("Mitigation cancelled")
                    return
            else:
                print("WARNING: Auto-remediation is enabled. This will attempt to apply the mitigation.")
                confirm = input("Continue? (y/n): ")
                if confirm.lower() != 'y':
                    print("Mitigation cancelled")
                    return

            results = self.blue_agent.apply_mitigations(plan_id)
            self.applied_mitigations.append({
                "plan": mitigation_plan,
                "results": results,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            })

            print(f"\nMitigation Status: {results[0].get('status', 'Unknown') if results else 'Unknown'}")

            if results:
                print("\nApplied Changes:")
                for change in results[0].get('applied_changes', []):
                    if change.get('type') == 'config':
                        print(f"  Config: {change.get('description', 'Unknown')[:100]}...")
                        print(f"    Status: {change.get('status', 'Unknown')}")
                    elif change.get('type') == 'command':
                        print(f"  Command: {change.get('command', 'Unknown')[:100]}")
                        print(f"    Status: {change.get('status', 'Unknown')}")

                print("\nFailed Changes:")
                for change in results[0].get('failed_changes', []):
                    if change.get('type') == 'config':
                        print(f"  Config: {change.get('description', 'Unknown')[:100]}...")
                        print(f"    Error: {change.get('error', 'Unknown')}")
                    elif change.get('type') == 'command':
                        print(f"  Command: {change.get('command', 'Unknown')[:100]}")
                        print(f"    Error: {change.get('error', 'Unknown')}")

                print("\nVerification Results:")
                for verify in results[0].get('verification_results', []):
                    print(f"  Step: {verify.get('step', 'Unknown')[:100]}...")
                    print(f"    Status: {verify.get('status', 'Unknown')}")

            print("\nMitigation completed")
        except ValueError:
            print("Error: Plan ID must be a number")
        except Exception as e:
            self.logger.error(f"Error applying mitigation: {e}")
            print(f"Error applying mitigation: {e}")

    def do_rules(self, arg):
        """
        Generate defense rules for a threat
        Usage: rules <exploit_id>
        Example: rules 1
        """
        if not self.blue_agent:
            print("Error: Blue Agent not initialized")
            return

        if not self.exploitation_results:
            print("Error: No exploitation results available. Run 'execute' first.")
            return

        try:
            exploit_id = int(arg) - 1  # Convert to 0-based index

            if exploit_id < 0 or exploit_id >= len(self.exploitation_results):
                print(f"Error: Invalid exploit ID. Must be between 1 and {len(self.exploitation_results)}")
                return

            exploit_result = self.exploitation_results[exploit_id]

            print(f"Generating defense rules for exploit {arg}...")

            rules = self.blue_agent.generate_defense_rules(exploit_result)

            print("\nGenerated Rules:")

            if rules.get('status') == 'skipped':
                print(f"  Skipped: {rules.get('reason', 'Unknown')}")
                return

            print("\nYARA Rules:")
            for i, rule in enumerate(rules.get('yara', [])):
                print(f"  [{i+1}] {rule[:100]}...")

            print("\nSnort/Suricata Rules:")
            for i, rule in enumerate(rules.get('snort', [])):
                print(f"  [{i+1}] {rule[:100]}...")

            print("\nSigma Rules:")
            for i, rule in enumerate(rules.get('sigma', [])):
                print(f"  [{i+1}] {rule[:100]}...")

            print("\nFirewall Rules:")
            for i, rule in enumerate(rules.get('firewall', [])):
                print(f"  [{i+1}] {rule[:100]}...")

            # Ask if user wants to deploy rules
            if rules.get('yara') or rules.get('snort') or rules.get('sigma') or rules.get('firewall'):
                deploy = input("\nDeploy these rules? (y/n): ")
                if deploy.lower() == 'y':
                    deploy_result = self.blue_agent.deploy_rules(rules)

                    print(f"\nDeployment Status: {deploy_result.get('status', 'Unknown')}")

                    print("\nDeployed Rules:")
                    for rule in deploy_result.get('deployed_rules', []):
                        print(f"  Type: {rule.get('type', 'Unknown')}")
                        if 'path' in rule:
                            print(f"    Path: {rule.get('path', 'Unknown')}")
                        if 'status' in rule:
                            print(f"    Status: {rule.get('status', 'Unknown')}")

                    print("\nFailed Rules:")
                    for rule in deploy_result.get('failed_rules', []):
                        print(f"  Type: {rule.get('type', 'Unknown')}")
                        print(f"    Error: {rule.get('error', 'Unknown')}")

            print("\nRule generation completed")
        except ValueError:
            print("Error: Exploit ID must be a number")
        except Exception as e:
            self.logger.error(f"Error generating rules: {e}")
            print(f"Error generating rules: {e}")

    def do_analyze_binary(self, arg):
        """
        Analyze a binary file
        Usage: analyze_binary <binary_path>
        Example: analyze_binary /path/to/binary
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not arg:
            print("Error: Binary path required")
            print("Usage: analyze_binary <binary_path>")
            return

        if not hasattr(self.red_agent, 'binary_analyzer'):
            print("Error: Binary analysis module not available")
            return

        print(f"Analyzing binary: {arg}")

        try:
            results = self.red_agent.analyze_binary(arg)

            if "error" in results:
                print(f"Error: {results['error']}")
                return

            # Display file information
            print("\nFile Information:")
            print(f"Type: {results['file_info']['type']}")
            print(f"Size: {results['file_info']['size']} bytes")

            # Display sections
            print("\nSections:")
            for section in results['sections'][:5]:  # Show first 5 sections
                print(f"  {section['name']} - {section['size']} bytes at {section['address']}")
            if len(results['sections']) > 5:
                print(f"  ... and {len(results['sections']) - 5} more sections")

            # Display functions
            print("\nFunctions:")
            for function in results['functions'][:5]:  # Show first 5 functions
                print(f"  {function['name']} at {function['address']}")
            if len(results['functions']) > 5:
                print(f"  ... and {len(results['functions']) - 5} more functions")

            # Display imports
            print("\nImports:")
            for imp in results['imports'][:5]:  # Show first 5 imports
                print(f"  {imp}")
            if len(results['imports']) > 5:
                print(f"  ... and {len(results['imports']) - 5} more imports")

            print("\nBinary analysis completed successfully")
        except Exception as e:
            self.logger.error(f"Error analyzing binary: {e}")
            print(f"Error analyzing binary: {e}")

    def do_find_binary_vulns(self, arg):
        """
        Find vulnerabilities in the current binary
        Usage: find_binary_vulns
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not hasattr(self.red_agent, 'exploit_pathfinder'):
            print("Error: Binary analysis module not available")
            return

        if not hasattr(self.red_agent, 'current_binary') or not self.red_agent.current_binary:
            print("Error: No binary selected. Run 'analyze_binary' first.")
            return

        print(f"Finding vulnerabilities in binary: {self.red_agent.current_binary}")

        try:
            vulnerabilities = self.red_agent.find_binary_vulnerabilities()

            if "error" in vulnerabilities:
                print(f"Error: {vulnerabilities['error']}")
                return

            # Display vulnerabilities
            print("\nPotential Vulnerabilities:")

            total_vulns = 0
            for vuln_type, vulns in vulnerabilities.items():
                if vulns:
                    total_vulns += len(vulns)
                    print(f"\n{vuln_type.upper()} ({len(vulns)}):")
                    for i, vuln in enumerate(vulns[:3]):  # Show first 3 vulnerabilities of each type
                        print(f"  [{i+1}] Function: {vuln['function']}")
                        print(f"      Match: {vuln['match']}")
                        print(f"      Confidence: {vuln['confidence']:.2f}")
                        if 'explanation' in vuln:
                            print(f"      Explanation: {vuln['explanation'][:100]}...")
                    if len(vulns) > 3:
                        print(f"      ... and {len(vulns) - 3} more")

            if total_vulns == 0:
                print("No vulnerabilities found")
            else:
                print(f"\nFound {total_vulns} potential vulnerabilities")

            print("\nVulnerability analysis completed successfully")
        except Exception as e:
            self.logger.error(f"Error finding binary vulnerabilities: {e}")
            print(f"Error finding binary vulnerabilities: {e}")

    def do_binary_exploit(self, arg):
        """
        Generate an exploit for a binary vulnerability
        Usage: binary_exploit <vulnerability_type> <vulnerability_index>
        Example: binary_exploit buffer_overflow 1
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not hasattr(self.red_agent, 'exploit_pathfinder'):
            print("Error: Binary analysis module not available")
            return

        if not hasattr(self.red_agent, 'current_binary') or not self.red_agent.current_binary:
            print("Error: No binary selected. Run 'analyze_binary' first.")
            return

        if not hasattr(self.red_agent, 'binary_analysis_results') or "vulnerabilities" not in self.red_agent.binary_analysis_results:
            print("Error: No vulnerabilities found. Run 'find_binary_vulns' first.")
            return

        args = arg.split()
        if len(args) < 2:
            print("Error: Vulnerability type and index required")
            print("Usage: binary_exploit <vulnerability_type> <vulnerability_index>")
            return

        vuln_type = args[0]
        try:
            vuln_index = int(args[1]) - 1  # Convert to 0-based index
        except ValueError:
            print("Error: Vulnerability index must be a number")
            return

        print(f"Generating exploit for {vuln_type} vulnerability {vuln_index+1}...")

        try:
            exploit_path = self.red_agent.generate_binary_exploit(vuln_type, vuln_index)

            if "error" in exploit_path:
                print(f"Error: {exploit_path['error']}")
                return

            # Display exploit path
            print("\nExploit Path:")
            print(exploit_path['exploit_path'])

            print("\nExploit generation completed successfully")
        except Exception as e:
            self.logger.error(f"Error generating binary exploit: {e}")
            print(f"Error generating binary exploit: {e}")

    def do_analyze_memory(self, arg):
        """
        Analyze a memory dump file
        Usage: analyze_memory <dump_path>
        Example: analyze_memory /path/to/memory.dump
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not arg:
            print("Error: Memory dump path required")
            print("Usage: analyze_memory <dump_path>")
            return

        if not hasattr(self.red_agent, 'memory_analyzer'):
            print("Error: Binary analysis module not available")
            return

        print(f"Analyzing memory dump: {arg}")

        try:
            results = self.red_agent.analyze_memory_dump(arg)

            if "error" in results:
                print(f"Error: {results['error']}")
                return

            # Display file information
            print("\nFile Information:")
            print(f"Size: {results['file_info']['size']} bytes")

            # Display detected patterns
            print("\nDetected Patterns:")
            for pattern_type, matches in results['patterns'].items():
                if matches:
                    print(f"  {pattern_type}: {len(matches)} matches")
                    for match in matches[:2]:  # Show first 2 matches
                        print(f"    Offset: {match['offset']}, Value: {match['value'][:30]}...")

            # Display entropy regions
            print("\nHigh Entropy Regions (potentially encrypted):")
            high_entropy_regions = [r for r in results['entropy_regions'] if r['entropy'] > 7.0]
            for region in high_entropy_regions[:5]:  # Show first 5 regions
                print(f"  Offset: {region['offset']}, Size: {region['size']} bytes, Entropy: {region['entropy']:.2f}")
            if len(high_entropy_regions) > 5:
                print(f"  ... and {len(high_entropy_regions) - 5} more regions")

            # Display structure candidates
            print("\nPotential Data Structures:")
            for structure in results['structure_candidates'][:5]:  # Show first 5 structures
                print(f"  Type: {structure['type']} at offset {structure['offset']}, Size: {structure['size']} bytes")
            if len(results['structure_candidates']) > 5:
                print(f"  ... and {len(results['structure_candidates']) - 5} more structures")

            print("\nMemory analysis completed successfully")
        except Exception as e:
            self.logger.error(f"Error analyzing memory dump: {e}")
            print(f"Error analyzing memory dump: {e}")

    def do_generate_yara(self, arg):
        """
        Generate a YARA rule for the current binary
        Usage: generate_yara <description>
        Example: generate_yara "Detect malicious behavior in this binary"
        """
        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        if not arg:
            print("Error: Description required")
            print("Usage: generate_yara <description>")
            return

        if not hasattr(self.red_agent, 'workflow_automation'):
            print("Error: Binary analysis module not available")
            return

        if not hasattr(self.red_agent, 'current_binary') or not self.red_agent.current_binary:
            print("Error: No binary selected. Run 'analyze_binary' first.")
            return

        print(f"Generating YARA rule for: {arg}")

        try:
            yara_rule = self.red_agent.generate_yara_rule(arg)

            if "error" in yara_rule:
                print(f"Error: {yara_rule['error']}")
                return

            # Display YARA rule
            print("\nYARA Rule:")
            print(yara_rule['rule'])

            print(f"\nYARA rule saved to: {yara_rule['rule_path']}")

            print("\nYARA rule generation completed successfully")
        except Exception as e:
            self.logger.error(f"Error generating YARA rule: {e}")
            print(f"Error generating YARA rule: {e}")

    def do_monitor(self, arg):
        """
        Monitor the system for security events
        Usage: monitor
        """
        if not self.blue_agent:
            print("Error: Blue Agent not initialized")
            return

        print("Monitoring system for security events...")

        try:
            results = self.blue_agent.monitor_system()

            print(f"\nMonitoring period: {time.ctime(results.get('start_time', 0))} to {time.ctime(results.get('end_time', 0))}")
            print(f"Total events: {results.get('total_events', 0)}")

            if results.get('events'):
                print("\nEvents:")
                for i, event in enumerate(results.get('events', [])[:10]):  # Limit to 10 events
                    print(f"\n[{i+1}] Type: {event.get('type', 'Unknown')}/{event.get('subtype', 'Unknown')}")
                    print(f"    Timestamp: {event.get('timestamp', 'Unknown')}")

                    if event.get('type') == 'auth':
                        print(f"    Username: {event.get('username', 'Unknown')}")
                        print(f"    Source IP: {event.get('source_ip', 'Unknown')}")
                    elif event.get('type') == 'firewall':
                        print(f"    Source: {event.get('source_ip', 'Unknown')}:{event.get('source_port', 'Unknown')}")
                        print(f"    Destination: {event.get('destination_ip', 'Unknown')}:{event.get('destination_port', 'Unknown')}")
                        print(f"    Protocol: {event.get('protocol', 'Unknown')}")
                    elif event.get('type') == 'ids':
                        print(f"    Alert: {event.get('alert_message', 'Unknown')}")
                        print(f"    Source: {event.get('source_ip', 'Unknown')}:{event.get('source_port', 'Unknown')}")
                        print(f"    Destination: {event.get('destination_ip', 'Unknown')}:{event.get('destination_port', 'Unknown')}")

                if len(results.get('events', [])) > 10:
                    print(f"\n... and {len(results.get('events', [])) - 10} more events")
            else:
                print("\nNo security events detected")

            print("\nMonitoring completed")
        except Exception as e:
            self.logger.error(f"Error monitoring system: {e}")
            print(f"Error monitoring system: {e}")

    def do_report(self, arg):
        """
        Generate a comprehensive report
        Usage: report [red|blue]
        Example: report red
        """
        if arg.lower() == 'red':
            if not self.red_agent:
                print("Error: Red Agent not initialized")
                return

            print("Generating Red Team report...")

            try:
                report = self.red_agent.get_report()

                print("\nRed Team Report:")
                print(f"Target: {report.get('target', 'Unknown')}")
                print(f"Scan Time: {report.get('scan_time', 'Unknown')}")

                print(f"\nVulnerabilities: {report.get('summary', {}).get('total_vulnerabilities', 0)}")
                print(f"Exploited: {report.get('summary', {}).get('exploited_vulnerabilities', 0)}")
                print(f"Failed Exploits: {report.get('summary', {}).get('failed_exploits', 0)}")

                # Save report to file
                os.makedirs("data/reports", exist_ok=True)
                report_path = f"data/reports/red_report_{int(time.time())}.json"

                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2)

                print(f"\nReport saved to: {report_path}")
            except Exception as e:
                self.logger.error(f"Error generating Red Team report: {e}")
                print(f"Error generating Red Team report: {e}")

        elif arg.lower() == 'blue':
            if not self.blue_agent:
                print("Error: Blue Agent not initialized")
                return

            print("Generating Blue Team report...")

            try:
                report = self.blue_agent.get_report()

                print("\nBlue Team Report:")
                print(f"Timestamp: {report.get('timestamp', 'Unknown')}")

                print(f"\nAssessed Vulnerabilities: {report.get('summary', {}).get('total_vulnerabilities', 0)}")
                print(f"Mitigated Vulnerabilities: {report.get('summary', {}).get('mitigated_vulnerabilities', 0)}")
                print(f"Rules Generated: {report.get('summary', {}).get('rules_generated', 0)}")

                # Save report to file
                os.makedirs("data/reports", exist_ok=True)
                report_path = f"data/reports/blue_report_{int(time.time())}.json"

                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2)

                print(f"\nReport saved to: {report_path}")
            except Exception as e:
                self.logger.error(f"Error generating Blue Team report: {e}")
                print(f"Error generating Blue Team report: {e}")

        else:
            print("Error: Invalid report type")
            print("Usage: report [red|blue]")

    def do_help(self, arg):
        """List available commands with help text"""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            # Show general help
            print("\nAvailable commands:")
            print("  scan <target>           - Scan a target network or host")
            print("  analyze                 - Analyze scan results to identify vulnerabilities")
            print("  exploit <vuln_id>       - Generate an exploit plan for a vulnerability")
            print("  execute <plan_id>       - Execute an exploit plan")
            print("  defend                  - Generate defense strategies for vulnerabilities")
            print("  mitigate <plan_id>      - Apply a mitigation plan")
            print("  rules <exploit_id>      - Generate defense rules for a threat")
            print("  monitor                 - Monitor the system for security events")
            print("  report [red|blue]       - Generate a comprehensive report")
            print("  help                    - Show this help message")
            print("  exit                    - Exit the program")
            print("\nType 'help <command>' for more information about a command.")


def start_cli(red_agent=None, blue_agent=None, config=None):
    """
    Start the Enhanced CLI interface

    Args:
        red_agent: Red Agent instance
        blue_agent: Blue Agent instance
        config: Configuration dictionary
    """
    cli = EnhancedCLI(red_agent, blue_agent, config)
    cli.start()

# Legacy support - keep the old CLI class name as an alias
CLI = EnhancedCLI
