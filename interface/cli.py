"""
Command Line Interface Module
Provides a CLI for interacting with NeuroStrike
"""

import os
import sys
import cmd
import json
import time
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

class CLI(cmd.Cmd):
    """
    Command Line Interface for NeuroStrike
    """

    intro = """
    ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
    ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
    ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

    AI Red vs Blue Cyber War Game
    Type 'help' or '?' to list commands.
    """
    prompt = "NeuroStrike> "

    def __init__(self, red_agent=None, blue_agent=None, config=None):
        """
        Initialize the CLI

        Args:
            red_agent: Red Agent instance
            blue_agent: Blue Agent instance
            config: Configuration dictionary
        """
        super().__init__()
        self.logger = get_logger("cli")
        self.red_agent = red_agent
        self.blue_agent = blue_agent
        self.config = config or {}

        # State tracking
        self.current_target = None
        self.scan_results = None
        self.vulnerabilities = None
        self.exploit_plans = []
        self.exploitation_results = []
        self.mitigation_plans = []
        self.applied_mitigations = []

        self.logger.info("CLI initialized")

    def start(self):
        """Start the CLI"""
        self.cmdloop()

    def emptyline(self):
        """Do nothing on empty line"""
        pass

    def do_exit(self, arg):
        """Exit the program"""
        print("Exiting NeuroStrike...")
        return True

    def do_quit(self, arg):
        """Exit the program"""
        return self.do_exit(arg)

    def do_scan(self, arg):
        """
        Scan a target network or host
        Usage: scan <target>
        Example: scan 192.168.1.0/24
        """
        if not arg:
            print("Error: Target required")
            print("Usage: scan <target>")
            return

        if not self.red_agent:
            print("Error: Red Agent not initialized")
            return

        print(f"Scanning target: {arg}")
        self.current_target = arg

        try:
            self.scan_results = self.red_agent.scan_target(arg)

            # Display summary
            hosts_up = self.scan_results.get("network_info", {}).get("hosts_up", [])
            open_ports = self.scan_results.get("ports_and_services", {}).get("open_ports", [])

            print("\nScan Results Summary:")
            print(f"Target: {arg}")
            print(f"Hosts up: {len(hosts_up)}")
            print(f"Open ports: {len(open_ports)}")

            # Display hosts
            if hosts_up:
                print("\nHosts:")
                for host in hosts_up[:10]:  # Limit to 10 hosts
                    print(f"  {host}")
                if len(hosts_up) > 10:
                    print(f"  ... and {len(hosts_up) - 10} more")

            # Display ports and services
            if open_ports:
                print("\nOpen Ports and Services:")
                services = self.scan_results.get("ports_and_services", {}).get("services", {})
                for port in sorted(open_ports)[:10]:  # Limit to 10 ports
                    service = services.get(port, {}).get("name", "unknown")
                    print(f"  {port}/tcp: {service}")
                if len(open_ports) > 10:
                    print(f"  ... and {len(open_ports) - 10} more")

            print("\nScan completed successfully")
        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            print(f"Error during scan: {e}")

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
