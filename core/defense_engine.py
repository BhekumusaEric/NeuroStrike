"""
Defense Engine Module
Handles the generation and application of defensive measures
"""

import re
import os
import shutil
import subprocess
import time
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

class DefenseEngine:
    """
    Defense Engine for generating and applying defensive measures
    """
    
    def __init__(self, backup_before_fix: bool = True):
        """
        Initialize the Defense Engine
        
        Args:
            backup_before_fix: If True, backup files before modifying them
        """
        self.logger = get_logger("defense_engine")
        self.backup_before_fix = backup_before_fix
    
    def parse_mitigation_plan(self, llm_response: str) -> Dict[str, Any]:
        """
        Parse a mitigation plan from LLM response
        
        Args:
            llm_response: Response from LLM containing mitigation plan
            
        Returns:
            Dictionary containing the parsed mitigation plan
        """
        self.logger.info("Parsing mitigation plan from LLM response")
        
        mitigation_plan = {
            "immediate_steps": [],
            "long_term_steps": [],
            "configuration_changes": [],
            "commands": [],
            "verification_steps": []
        }
        
        # Extract immediate steps
        immediate_pattern = r'(?i)(?:immediate|short[- ]term)\s+(?:mitigation|steps|remediation):\s*(.*?)(?:(?:long[- ]term|configuration|commands|verification):|\Z)'
        immediate_match = re.search(immediate_pattern, llm_response, re.DOTALL)
        if immediate_match:
            immediate_text = immediate_match.group(1).strip()
            # Look for numbered or bulleted items
            immediate_items = re.findall(r'(?:[\d*-]+\.\s*)(.*?)(?=[\d*-]+\.\s*|\Z)', immediate_text, re.DOTALL)
            if immediate_items:
                mitigation_plan["immediate_steps"] = [item.strip() for item in immediate_items]
            else:
                # If no numbered items, split by newlines
                mitigation_plan["immediate_steps"] = [item.strip() for item in immediate_text.split('\n') if item.strip()]
        
        # Extract long-term steps
        longterm_pattern = r'(?i)long[- ]term\s+(?:remediation|steps|strategies):\s*(.*?)(?:(?:configuration|commands|verification):|\Z)'
        longterm_match = re.search(longterm_pattern, llm_response, re.DOTALL)
        if longterm_match:
            longterm_text = longterm_match.group(1).strip()
            # Look for numbered or bulleted items
            longterm_items = re.findall(r'(?:[\d*-]+\.\s*)(.*?)(?=[\d*-]+\.\s*|\Z)', longterm_text, re.DOTALL)
            if longterm_items:
                mitigation_plan["long_term_steps"] = [item.strip() for item in longterm_items]
            else:
                # If no numbered items, split by newlines
                mitigation_plan["long_term_steps"] = [item.strip() for item in longterm_text.split('\n') if item.strip()]
        
        # Extract configuration changes
        config_pattern = r'(?i)configuration\s+changes:\s*(.*?)(?:(?:commands|verification):|\Z)'
        config_match = re.search(config_pattern, llm_response, re.DOTALL)
        if config_match:
            config_text = config_match.group(1).strip()
            # Look for numbered or bulleted items
            config_items = re.findall(r'(?:[\d*-]+\.\s*)(.*?)(?=[\d*-]+\.\s*|\Z)', config_text, re.DOTALL)
            if config_items:
                mitigation_plan["configuration_changes"] = [item.strip() for item in config_items]
            else:
                # If no numbered items, split by newlines
                mitigation_plan["configuration_changes"] = [item.strip() for item in config_text.split('\n') if item.strip()]
        
        # Extract commands
        commands_pattern = r'(?i)(?:commands|code):\s*(.*?)(?:(?:verification):|\Z)'
        commands_match = re.search(commands_pattern, llm_response, re.DOTALL)
        if commands_match:
            commands_text = commands_match.group(1).strip()
            # Extract code blocks
            code_blocks = re.findall(r'```(?:\w+)?\s*(.*?)\s*```', commands_text, re.DOTALL)
            if code_blocks:
                for block in code_blocks:
                    # Split block into individual commands
                    commands = [cmd.strip() for cmd in block.split('\n') if cmd.strip()]
                    mitigation_plan["commands"].extend(commands)
            else:
                # If no code blocks, look for command lines
                command_lines = re.findall(r'(?:[$>]\s*)(.*?)(?:\n|$)', commands_text)
                if command_lines:
                    mitigation_plan["commands"] = [cmd.strip() for cmd in command_lines]
                else:
                    # If no command markers, split by newlines
                    mitigation_plan["commands"] = [cmd.strip() for cmd in commands_text.split('\n') if cmd.strip()]
        
        # Extract verification steps
        verify_pattern = r'(?i)verification\s+steps:\s*(.*?)(?:\Z)'
        verify_match = re.search(verify_pattern, llm_response, re.DOTALL)
        if verify_match:
            verify_text = verify_match.group(1).strip()
            # Look for numbered or bulleted items
            verify_items = re.findall(r'(?:[\d*-]+\.\s*)(.*?)(?=[\d*-]+\.\s*|\Z)', verify_text, re.DOTALL)
            if verify_items:
                mitigation_plan["verification_steps"] = [item.strip() for item in verify_items]
            else:
                # If no numbered items, split by newlines
                mitigation_plan["verification_steps"] = [item.strip() for item in verify_text.split('\n') if item.strip()]
        
        return mitigation_plan
    
    def apply_mitigation(self, mitigation_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply a mitigation plan
        
        Args:
            mitigation_plan: Dictionary containing the mitigation plan
            
        Returns:
            Dictionary containing the application results
        """
        self.logger.info("Applying mitigation plan")
        
        result = {
            "status": "unknown",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "applied_changes": [],
            "failed_changes": [],
            "verification_results": []
        }
        
        # Apply configuration changes
        for config_change in mitigation_plan.get("configuration_changes", []):
            change_result = self._apply_config_change(config_change)
            if change_result.get("status") == "success":
                result["applied_changes"].append(change_result)
            else:
                result["failed_changes"].append(change_result)
        
        # Execute commands
        for command in mitigation_plan.get("commands", []):
            command_result = self._execute_command(command)
            if command_result.get("status") == "success":
                result["applied_changes"].append(command_result)
            else:
                result["failed_changes"].append(command_result)
        
        # Verify changes
        for step in mitigation_plan.get("verification_steps", []):
            verify_result = self._verify_step(step)
            result["verification_results"].append(verify_result)
        
        # Determine overall status
        if not result["failed_changes"] and result["applied_changes"]:
            result["status"] = "success"
        elif result["applied_changes"]:
            result["status"] = "partial"
        else:
            result["status"] = "failed"
        
        return result
    
    def _apply_config_change(self, config_change: str) -> Dict[str, Any]:
        """Apply a configuration change"""
        self.logger.info(f"Applying configuration change: {config_change}")
        
        result = {
            "type": "config",
            "description": config_change,
            "status": "unknown"
        }
        
        # Extract file path if present
        file_path_match = re.search(r'(?:in|to|file|path)[:\s]+([/\w\.-]+)', config_change)
        file_path = file_path_match.group(1) if file_path_match else None
        
        if file_path and os.path.exists(file_path):
            # Backup file if needed
            if self.backup_before_fix:
                backup_path = f"{file_path}.bak.{int(time.time())}"
                try:
                    shutil.copy2(file_path, backup_path)
                    self.logger.info(f"Backed up {file_path} to {backup_path}")
                    result["backup_path"] = backup_path
                except Exception as e:
                    self.logger.error(f"Failed to backup {file_path}: {e}")
                    result["backup_error"] = str(e)
            
            # Extract changes to make
            # This is a simplified approach - in a real system, you'd need more sophisticated parsing
            add_line_match = re.search(r'(?:add|append)[:\s]+"([^"]+)"', config_change)
            remove_line_match = re.search(r'(?:remove|delete)[:\s]+"([^"]+)"', config_change)
            replace_match = re.search(r'(?:replace|change)[:\s]+"([^"]+)"[:\s]+(?:with|to)[:\s]+"([^"]+)"', config_change)
            
            try:
                with open(file_path, 'r') as f:
                    content = f.readlines()
                
                modified = False
                
                if add_line_match:
                    line_to_add = add_line_match.group(1) + '\n'
                    if line_to_add not in content:
                        content.append(line_to_add)
                        modified = True
                
                if remove_line_match:
                    line_to_remove = remove_line_match.group(1) + '\n'
                    if line_to_remove in content:
                        content.remove(line_to_remove)
                        modified = True
                
                if replace_match:
                    old_line = replace_match.group(1) + '\n'
                    new_line = replace_match.group(2) + '\n'
                    if old_line in content:
                        content = [new_line if line == old_line else line for line in content]
                        modified = True
                
                if modified:
                    with open(file_path, 'w') as f:
                        f.writelines(content)
                    
                    result["status"] = "success"
                    result["details"] = "Configuration file modified"
                else:
                    result["status"] = "skipped"
                    result["details"] = "No changes needed"
            except Exception as e:
                self.logger.error(f"Failed to modify {file_path}: {e}")
                result["status"] = "failed"
                result["error"] = str(e)
        else:
            result["status"] = "failed"
            result["error"] = f"File not found or no file specified: {file_path}"
        
        return result
    
    def _execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command"""
        self.logger.info(f"Executing command: {command}")
        
        result = {
            "type": "command",
            "command": command,
            "status": "unknown"
        }
        
        try:
            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=60)
            
            if process.returncode == 0:
                result["status"] = "success"
                result["stdout"] = stdout
            else:
                result["status"] = "failed"
                result["stdout"] = stdout
                result["stderr"] = stderr
                result["exit_code"] = process.returncode
        except Exception as e:
            self.logger.error(f"Failed to execute command: {e}")
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
    
    def _verify_step(self, step: str) -> Dict[str, Any]:
        """Verify a mitigation step"""
        self.logger.info(f"Verifying step: {step}")
        
        result = {
            "step": step,
            "status": "unknown"
        }
        
        # Extract command if present
        command_match = re.search(r'(?:run|execute|command)[:\s]+`([^`]+)`', step)
        
        if command_match:
            command = command_match.group(1)
            try:
                # Execute command
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                stdout, stderr = process.communicate(timeout=60)
                
                if process.returncode == 0:
                    result["status"] = "verified"
                    result["stdout"] = stdout
                else:
                    result["status"] = "failed"
                    result["stdout"] = stdout
                    result["stderr"] = stderr
                    result["exit_code"] = process.returncode
            except Exception as e:
                self.logger.error(f"Failed to verify step: {e}")
                result["status"] = "failed"
                result["error"] = str(e)
        else:
            result["status"] = "manual"
            result["details"] = "Manual verification required"
        
        return result
    
    def parse_rules(self, llm_response: str) -> Dict[str, Any]:
        """
        Parse defense rules from LLM response
        
        Args:
            llm_response: Response from LLM containing defense rules
            
        Returns:
            Dictionary containing the parsed rules
        """
        self.logger.info("Parsing defense rules from LLM response")
        
        rules = {
            "yara": [],
            "snort": [],
            "sigma": [],
            "firewall": []
        }
        
        # Extract YARA rules
        yara_pattern = r'(?i)(?:YARA rule|rule.*?YARA)(?:\s*):?\s*(rule\s+\w+\s*{.*?})'
        yara_matches = re.findall(yara_pattern, llm_response, re.DOTALL)
        for match in yara_matches:
            rules["yara"].append(match.strip())
        
        # Extract Snort/Suricata rules
        snort_pattern = r'(?i)(?:Snort|Suricata) rule(?:\s*):?\s*(alert\s+.*?(?:\(\s*.*?\s*\)))'
        snort_matches = re.findall(snort_pattern, llm_response, re.DOTALL)
        for match in snort_matches:
            rules["snort"].append(match.strip())
        
        # Extract Sigma rules
        sigma_pattern = r'(?i)Sigma rule(?:\s*):?\s*(title:.*?(?:detection:|falsepositives:|level:).*?(?=\n\s*\n|\Z))'
        sigma_matches = re.findall(sigma_pattern, llm_response, re.DOTALL)
        for match in sigma_matches:
            rules["sigma"].append(match.strip())
        
        # Extract firewall rules
        firewall_pattern = r'(?i)Firewall rule(?:\s*):?\s*((?:iptables|ufw|firewall-cmd).*?)(?=\n\s*\n|\Z)'
        firewall_matches = re.findall(firewall_pattern, llm_response, re.DOTALL)
        for match in firewall_matches:
            rules["firewall"].append(match.strip())
        
        return rules
    
    def deploy_rules(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deploy defense rules
        
        Args:
            rules: Dictionary containing rules to deploy
            
        Returns:
            Dictionary containing deployment results
        """
        self.logger.info("Deploying defense rules")
        
        result = {
            "status": "unknown",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "deployed_rules": [],
            "failed_rules": []
        }
        
        # Deploy YARA rules
        for rule in rules.get("yara", []):
            yara_result = self._deploy_yara_rule(rule)
            if yara_result.get("status") == "success":
                result["deployed_rules"].append(yara_result)
            else:
                result["failed_rules"].append(yara_result)
        
        # Deploy Snort/Suricata rules
        for rule in rules.get("snort", []):
            snort_result = self._deploy_snort_rule(rule)
            if snort_result.get("status") == "success":
                result["deployed_rules"].append(snort_result)
            else:
                result["failed_rules"].append(snort_result)
        
        # Deploy Sigma rules
        for rule in rules.get("sigma", []):
            sigma_result = self._deploy_sigma_rule(rule)
            if sigma_result.get("status") == "success":
                result["deployed_rules"].append(sigma_result)
            else:
                result["failed_rules"].append(sigma_result)
        
        # Deploy firewall rules
        for rule in rules.get("firewall", []):
            firewall_result = self._deploy_firewall_rule(rule)
            if firewall_result.get("status") == "success":
                result["deployed_rules"].append(firewall_result)
            else:
                result["failed_rules"].append(firewall_result)
        
        # Determine overall status
        if not result["failed_rules"] and result["deployed_rules"]:
            result["status"] = "success"
        elif result["deployed_rules"]:
            result["status"] = "partial"
        else:
            result["status"] = "failed"
        
        return result
    
    def _deploy_yara_rule(self, rule: str) -> Dict[str, Any]:
        """Deploy a YARA rule"""
        self.logger.info("Deploying YARA rule")
        
        result = {
            "type": "yara",
            "rule": rule,
            "status": "unknown"
        }
        
        # Extract rule name
        name_match = re.search(r'rule\s+(\w+)', rule)
        rule_name = name_match.group(1) if name_match else "unknown"
        
        # Create rules directory if it doesn't exist
        os.makedirs("data/rules/yara", exist_ok=True)
        
        # Write rule to file
        rule_path = f"data/rules/yara/{rule_name}.yar"
        try:
            with open(rule_path, 'w') as f:
                f.write(rule)
            
            result["status"] = "success"
            result["path"] = rule_path
        except Exception as e:
            self.logger.error(f"Failed to deploy YARA rule: {e}")
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
    
    def _deploy_snort_rule(self, rule: str) -> Dict[str, Any]:
        """Deploy a Snort/Suricata rule"""
        self.logger.info("Deploying Snort/Suricata rule")
        
        result = {
            "type": "snort",
            "rule": rule,
            "status": "unknown"
        }
        
        # Create rules directory if it doesn't exist
        os.makedirs("data/rules/snort", exist_ok=True)
        
        # Generate a unique filename
        rule_path = f"data/rules/snort/rule_{int(time.time())}.rules"
        
        try:
            with open(rule_path, 'w') as f:
                f.write(rule)
            
            result["status"] = "success"
            result["path"] = rule_path
        except Exception as e:
            self.logger.error(f"Failed to deploy Snort rule: {e}")
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
    
    def _deploy_sigma_rule(self, rule: str) -> Dict[str, Any]:
        """Deploy a Sigma rule"""
        self.logger.info("Deploying Sigma rule")
        
        result = {
            "type": "sigma",
            "rule": rule,
            "status": "unknown"
        }
        
        # Extract rule title
        title_match = re.search(r'title:\s*(.*?)(?:\n|$)', rule)
        rule_title = title_match.group(1) if title_match else "unknown"
        
        # Create rules directory if it doesn't exist
        os.makedirs("data/rules/sigma", exist_ok=True)
        
        # Generate filename from title
        safe_title = re.sub(r'[^\w]', '_', rule_title.lower())
        rule_path = f"data/rules/sigma/{safe_title}.yml"
        
        try:
            with open(rule_path, 'w') as f:
                f.write(rule)
            
            result["status"] = "success"
            result["path"] = rule_path
        except Exception as e:
            self.logger.error(f"Failed to deploy Sigma rule: {e}")
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
    
    def _deploy_firewall_rule(self, rule: str) -> Dict[str, Any]:
        """Deploy a firewall rule"""
        self.logger.info(f"Deploying firewall rule: {rule}")
        
        result = {
            "type": "firewall",
            "rule": rule,
            "status": "unknown"
        }
        
        try:
            # Execute the firewall command
            process = subprocess.Popen(
                rule,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode == 0:
                result["status"] = "success"
                result["stdout"] = stdout
            else:
                result["status"] = "failed"
                result["stdout"] = stdout
                result["stderr"] = stderr
                result["exit_code"] = process.returncode
        except Exception as e:
            self.logger.error(f"Failed to deploy firewall rule: {e}")
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
