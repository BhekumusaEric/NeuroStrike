"""
Web UI Module
Provides a web-based interface for NeuroStrike
"""

import os
import json
import time
import threading
import gradio as gr
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

class WebUI:
    """
    Web-based UI for NeuroStrike
    """
    
    def __init__(self, red_agent=None, blue_agent=None, config=None):
        """
        Initialize the Web UI
        
        Args:
            red_agent: Red Agent instance
            blue_agent: Blue Agent instance
            config: Configuration dictionary
        """
        self.logger = get_logger("web_ui")
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
        
        # UI theme
        self.theme = self.config.get("ui", {}).get("theme", "dark")
        
        self.logger.info("Web UI initialized")
    
    def start(self):
        """Start the Web UI"""
        self.logger.info("Starting Web UI")
        
        with gr.Blocks(theme=self.theme, title="NeuroStrike") as self.interface:
            gr.Markdown("""
            # NeuroStrike: AI Red vs Blue Cyber War Game
            
            A real-world cybersecurity tool for offensive and defensive operations.
            """)
            
            with gr.Tabs():
                with gr.TabItem("Red Team"):
                    with gr.Row():
                        with gr.Column():
                            target_input = gr.Textbox(label="Target", placeholder="Enter IP address, hostname, or CIDR range")
                            scan_button = gr.Button("Scan Target", variant="primary")
                            analyze_button = gr.Button("Analyze Vulnerabilities")
                        
                        scan_output = gr.Textbox(label="Scan Results", lines=10, max_lines=20)
                    
                    with gr.Row():
                        with gr.Column():
                            vuln_dropdown = gr.Dropdown(label="Select Vulnerability")
                            exploit_button = gr.Button("Generate Exploit Plan")
                        
                        vuln_output = gr.Textbox(label="Vulnerability Details", lines=10, max_lines=20)
                    
                    with gr.Row():
                        with gr.Column():
                            plan_dropdown = gr.Dropdown(label="Select Exploit Plan")
                            execute_button = gr.Button("Execute Exploit", variant="secondary")
                        
                        exploit_output = gr.Textbox(label="Exploit Results", lines=10, max_lines=20)
                
                with gr.TabItem("Blue Team"):
                    with gr.Row():
                        with gr.Column():
                            defend_button = gr.Button("Generate Defense Strategies", variant="primary")
                            monitor_button = gr.Button("Monitor System")
                        
                        defense_output = gr.Textbox(label="Defense Results", lines=10, max_lines=20)
                    
                    with gr.Row():
                        with gr.Column():
                            mitigation_dropdown = gr.Dropdown(label="Select Mitigation Plan")
                            mitigate_button = gr.Button("Apply Mitigation")
                        
                        mitigation_output = gr.Textbox(label="Mitigation Results", lines=10, max_lines=20)
                    
                    with gr.Row():
                        with gr.Column():
                            exploit_result_dropdown = gr.Dropdown(label="Select Exploit Result")
                            rules_button = gr.Button("Generate Defense Rules")
                            deploy_button = gr.Button("Deploy Rules")
                        
                        rules_output = gr.Textbox(label="Generated Rules", lines=10, max_lines=20)
                
                with gr.TabItem("Reports"):
                    with gr.Row():
                        red_report_button = gr.Button("Generate Red Team Report")
                        blue_report_button = gr.Button("Generate Blue Team Report")
                    
                    report_output = gr.Textbox(label="Report", lines=20, max_lines=30)
            
            # Red Team event handlers
            scan_button.click(
                fn=self._scan_target,
                inputs=[target_input],
                outputs=[scan_output, vuln_dropdown]
            )
            
            analyze_button.click(
                fn=self._analyze_vulnerabilities,
                inputs=[],
                outputs=[scan_output, vuln_dropdown]
            )
            
            vuln_dropdown.change(
                fn=self._show_vulnerability,
                inputs=[vuln_dropdown],
                outputs=[vuln_output]
            )
            
            exploit_button.click(
                fn=self._generate_exploit,
                inputs=[vuln_dropdown],
                outputs=[vuln_output, plan_dropdown]
            )
            
            plan_dropdown.change(
                fn=self._show_exploit_plan,
                inputs=[plan_dropdown],
                outputs=[exploit_output]
            )
            
            execute_button.click(
                fn=self._execute_exploit,
                inputs=[plan_dropdown],
                outputs=[exploit_output, exploit_result_dropdown]
            )
            
            # Blue Team event handlers
            defend_button.click(
                fn=self._generate_defenses,
                inputs=[],
                outputs=[defense_output, mitigation_dropdown]
            )
            
            monitor_button.click(
                fn=self._monitor_system,
                inputs=[],
                outputs=[defense_output]
            )
            
            mitigation_dropdown.change(
                fn=self._show_mitigation_plan,
                inputs=[mitigation_dropdown],
                outputs=[mitigation_output]
            )
            
            mitigate_button.click(
                fn=self._apply_mitigation,
                inputs=[mitigation_dropdown],
                outputs=[mitigation_output]
            )
            
            exploit_result_dropdown.change(
                fn=self._show_exploit_result,
                inputs=[exploit_result_dropdown],
                outputs=[rules_output]
            )
            
            rules_button.click(
                fn=self._generate_rules,
                inputs=[exploit_result_dropdown],
                outputs=[rules_output]
            )
            
            deploy_button.click(
                fn=self._deploy_rules,
                inputs=[],
                outputs=[rules_output]
            )
            
            # Report event handlers
            red_report_button.click(
                fn=self._generate_red_report,
                inputs=[],
                outputs=[report_output]
            )
            
            blue_report_button.click(
                fn=self._generate_blue_report,
                inputs=[],
                outputs=[report_output]
            )
        
        # Launch the interface
        self.interface.launch(share=False)
    
    def _scan_target(self, target):
        """Scan a target and return results"""
        if not self.red_agent:
            return "Error: Red Agent not initialized", []
        
        if not target:
            return "Error: Target required", []
        
        try:
            self.current_target = target
            self.scan_results = self.red_agent.scan_target(target)
            
            # Format output
            output = f"Scan Results for {target}:\n\n"
            
            hosts_up = self.scan_results.get("network_info", {}).get("hosts_up", [])
            open_ports = self.scan_results.get("ports_and_services", {}).get("open_ports", [])
            
            output += f"Hosts up: {len(hosts_up)}\n"
            output += f"Open ports: {len(open_ports)}\n\n"
            
            if hosts_up:
                output += "Hosts:\n"
                for host in hosts_up[:10]:  # Limit to 10 hosts
                    output += f"  {host}\n"
                if len(hosts_up) > 10:
                    output += f"  ... and {len(hosts_up) - 10} more\n\n"
            
            if open_ports:
                output += "Open Ports and Services:\n"
                services = self.scan_results.get("ports_and_services", {}).get("services", {})
                for port in sorted(open_ports)[:10]:  # Limit to 10 ports
                    service = services.get(port, {}).get("name", "unknown")
                    output += f"  {port}/tcp: {service}\n"
                if len(open_ports) > 10:
                    output += f"  ... and {len(open_ports) - 10} more\n"
            
            output += "\nScan completed successfully"
            
            return output, []
        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            return f"Error during scan: {e}", []
    
    def _analyze_vulnerabilities(self):
        """Analyze vulnerabilities and return results"""
        if not self.red_agent:
            return "Error: Red Agent not initialized", []
        
        if not hasattr(self.red_agent, 'scan_results'):
            return "Error: No scan results available. Run a scan first.", []
        
        try:
            self.vulnerabilities = self.red_agent.analyze_vulnerabilities()
            
            if not self.vulnerabilities:
                return "No vulnerabilities found", []
            
            # Format output
            output = f"Found {len(self.vulnerabilities)} potential vulnerabilities:\n\n"
            
            for i, vuln in enumerate(self.vulnerabilities):
                output += f"[{i+1}] {vuln.get('description', 'Unknown vulnerability')[:100]}...\n"
                output += f"    Severity: {vuln.get('severity', 'Unknown')}\n"
                output += f"    CVE: {vuln.get('cve', 'N/A')}\n"
                output += f"    Difficulty: {vuln.get('exploitation_difficulty', 'Unknown')}\n\n"
            
            output += "Analysis completed successfully"
            
            # Create dropdown options
            dropdown_options = [f"{i+1}. {v.get('description', 'Unknown')[:50]}..." for i, v in enumerate(self.vulnerabilities)]
            
            return output, dropdown_options
        except Exception as e:
            self.logger.error(f"Error during analysis: {e}")
            return f"Error during analysis: {e}", []
    
    def _show_vulnerability(self, vuln_id):
        """Show details of a selected vulnerability"""
        if not self.vulnerabilities:
            return "No vulnerabilities available"
        
        try:
            if not vuln_id:
                return "Please select a vulnerability"
            
            # Extract index from dropdown text
            index = int(vuln_id.split('.')[0]) - 1
            
            if index < 0 or index >= len(self.vulnerabilities):
                return "Invalid vulnerability selection"
            
            vuln = self.vulnerabilities[index]
            
            # Format output
            output = f"Vulnerability Details:\n\n"
            output += f"Description: {vuln.get('description', 'Unknown')}\n\n"
            output += f"Severity: {vuln.get('severity', 'Unknown')}\n"
            output += f"CVE: {vuln.get('cve', 'N/A')}\n"
            output += f"Exploitation Difficulty: {vuln.get('exploitation_difficulty', 'Unknown')}\n"
            
            return output
        except Exception as e:
            self.logger.error(f"Error showing vulnerability: {e}")
            return f"Error showing vulnerability: {e}"
    
    def _generate_exploit(self, vuln_id):
        """Generate an exploit plan for a vulnerability"""
        if not self.red_agent:
            return "Error: Red Agent not initialized", []
        
        if not self.vulnerabilities:
            return "Error: No vulnerabilities identified. Run analysis first.", []
        
        try:
            if not vuln_id:
                return "Please select a vulnerability", []
            
            # Extract index from dropdown text
            index = int(vuln_id.split('.')[0]) - 1
            
            if index < 0 or index >= len(self.vulnerabilities):
                return "Invalid vulnerability selection", []
            
            exploit_plan = self.red_agent.generate_exploit_plan(index)
            self.exploit_plans.append(exploit_plan)
            
            # Format output
            output = f"Exploit Plan:\n\n"
            output += f"Name: {exploit_plan.get('name', 'Unnamed exploit')}\n"
            output += f"Type: {exploit_plan.get('type', 'Unknown')}\n\n"
            
            output += "Steps:\n"
            for i, step in enumerate(exploit_plan.get('steps', [])):
                output += f"  {i+1}. {step}\n"
            
            output += "\nCommands:\n"
            for i, cmd in enumerate(exploit_plan.get('commands', [])):
                output += f"  {i+1}. {cmd}\n"
            
            output += f"\nExpected Outcome: {exploit_plan.get('expected_outcome', 'Unknown')}\n"
            
            # Create dropdown options
            dropdown_options = [f"{i+1}. {p.get('name', 'Unnamed exploit')}" for i, p in enumerate(self.exploit_plans)]
            
            return output, dropdown_options
        except Exception as e:
            self.logger.error(f"Error generating exploit plan: {e}")
            return f"Error generating exploit plan: {e}", []
    
    def _show_exploit_plan(self, plan_id):
        """Show details of a selected exploit plan"""
        if not self.exploit_plans:
            return "No exploit plans available"
        
        try:
            if not plan_id:
                return "Please select an exploit plan"
            
            # Extract index from dropdown text
            index = int(plan_id.split('.')[0]) - 1
            
            if index < 0 or index >= len(self.exploit_plans):
                return "Invalid exploit plan selection"
            
            plan = self.exploit_plans[index]
            
            # Format output
            output = f"Exploit Plan Details:\n\n"
            output += f"Name: {plan.get('name', 'Unnamed exploit')}\n"
            output += f"Type: {plan.get('type', 'Unknown')}\n\n"
            
            output += "Steps:\n"
            for i, step in enumerate(plan.get('steps', [])):
                output += f"  {i+1}. {step}\n"
            
            output += "\nCommands:\n"
            for i, cmd in enumerate(plan.get('commands', [])):
                output += f"  {i+1}. {cmd}\n"
            
            output += f"\nExpected Outcome: {plan.get('expected_outcome', 'Unknown')}\n"
            
            return output
        except Exception as e:
            self.logger.error(f"Error showing exploit plan: {e}")
            return f"Error showing exploit plan: {e}"
    
    # Add the rest of the methods for the UI functionality
    # These would follow the same pattern as the methods above
    
    def _execute_exploit(self, plan_id):
        """Execute an exploit plan"""
        # Implementation similar to other methods
        pass
    
    def _generate_defenses(self):
        """Generate defense strategies"""
        # Implementation similar to other methods
        pass
    
    def _monitor_system(self):
        """Monitor the system for security events"""
        # Implementation similar to other methods
        pass
    
    def _show_mitigation_plan(self, plan_id):
        """Show details of a selected mitigation plan"""
        # Implementation similar to other methods
        pass
    
    def _apply_mitigation(self, plan_id):
        """Apply a mitigation plan"""
        # Implementation similar to other methods
        pass
    
    def _show_exploit_result(self, result_id):
        """Show details of a selected exploit result"""
        # Implementation similar to other methods
        pass
    
    def _generate_rules(self, result_id):
        """Generate defense rules for an exploit result"""
        # Implementation similar to other methods
        pass
    
    def _deploy_rules(self):
        """Deploy generated defense rules"""
        # Implementation similar to other methods
        pass
    
    def _generate_red_report(self):
        """Generate a Red Team report"""
        # Implementation similar to other methods
        pass
    
    def _generate_blue_report(self):
        """Generate a Blue Team report"""
        # Implementation similar to other methods
        pass
