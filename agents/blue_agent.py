"""
Blue Agent Module - Defensive Security AI
"""

import os
import yaml
import time
import logging
from typing import Dict, List, Any, Optional

# Import core modules
from ai_models.model_loader import load_llm
from core.intrusion_detector import IntrusionDetector
from core.defense_engine import DefenseEngine
from utils.logger import get_logger

class BlueAgent:
    """
    Blue Team Agent for defensive security operations
    Analyzes vulnerabilities, generates mitigations, and implements defenses
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Blue Agent
        
        Args:
            config: Configuration dictionary for the Blue Agent
        """
        self.config = config
        self.logger = get_logger("blue_agent")
        self.auto_remediate = config.get("auto_remediate", False)
        self.rule_generation = config.get("rule_generation", True)
        self.backup_before_fix = config.get("backup_before_fix", True)
        
        # Load prompt templates
        self.prompts = self._load_prompts()
        
        # Initialize LLM
        self.llm = load_llm()
        
        # Initialize core components
        self.intrusion_detector = IntrusionDetector()
        self.defense_engine = DefenseEngine(backup_before_fix=self.backup_before_fix)
        
        # State tracking
        self.current_vulnerabilities = []
        self.mitigation_plans = []
        self.applied_mitigations = []
        self.generated_rules = []
        
        self.logger.info("Blue Agent initialized")
    
    def _load_prompts(self) -> Dict[str, str]:
        """Load prompt templates from YAML file"""
        try:
            with open("config/prompts.yaml", "r") as file:
                all_prompts = yaml.safe_load(file)
                return all_prompts.get("blue_agent", {})
        except Exception as e:
            self.logger.error(f"Error loading prompts: {e}")
            return {}
    
    def assess_vulnerabilities(self, vulnerability_report: Dict[str, Any], system_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Assess vulnerabilities identified by the Red Agent or other sources
        
        Args:
            vulnerability_report: Report containing vulnerability information
            system_info: Information about the target system
            
        Returns:
            List of vulnerability assessments
        """
        self.logger.info("Assessing vulnerabilities")
        
        # Store the vulnerabilities
        self.current_vulnerabilities = vulnerability_report.get("vulnerabilities", [])
        
        assessments = []
        
        for vuln in self.current_vulnerabilities:
            # Format the prompt
            prompt = self.prompts.get("vulnerability_assessment", "")
            prompt = prompt.format(
                vulnerability_report=str(vuln),
                system_info=str(system_info)
            )
            
            # Query LLM for vulnerability assessment
            response = self.llm.generate(prompt)
            
            # Parse assessment
            assessment = self.intrusion_detector.parse_assessment(response)
            assessment["original_vulnerability"] = vuln
            
            assessments.append(assessment)
        
        return assessments
    
    def generate_mitigations(self, assessments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate mitigation strategies for assessed vulnerabilities
        
        Args:
            assessments: List of vulnerability assessments
            
        Returns:
            List of mitigation plans
        """
        self.logger.info("Generating mitigation strategies")
        
        mitigation_plans = []
        
        for assessment in assessments:
            # Format the prompt
            prompt = self.prompts.get("mitigation_generation", "")
            prompt = prompt.format(
                vulnerability_assessment=str(assessment),
                system_info=str(assessment.get("original_vulnerability", {}).get("system_info", ""))
            )
            
            # Query LLM for mitigation strategy
            response = self.llm.generate(prompt)
            
            # Parse mitigation plan
            mitigation_plan = self.defense_engine.parse_mitigation_plan(response)
            mitigation_plan["assessment"] = assessment
            
            mitigation_plans.append(mitigation_plan)
        
        # Store mitigation plans
        self.mitigation_plans = mitigation_plans
        
        return mitigation_plans
    
    def apply_mitigations(self, mitigation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Apply mitigation strategies to the system
        
        Args:
            mitigation_id: Optional ID of specific mitigation to apply, or None for all
            
        Returns:
            List of results from applying mitigations
        """
        if not self.mitigation_plans:
            self.logger.error("No mitigation plans available. Run generate_mitigations first.")
            return []
        
        if not self.auto_remediate:
            self.logger.warning("Auto-remediation disabled. Skipping mitigation application.")
            return [{"status": "skipped", "reason": "auto_remediate_disabled"}]
        
        self.logger.info("Applying mitigations")
        
        results = []
        
        # Apply specific mitigation or all mitigations
        plans_to_apply = [self.mitigation_plans[mitigation_id]] if mitigation_id is not None else self.mitigation_plans
        
        for plan in plans_to_apply:
            result = self.defense_engine.apply_mitigation(plan)
            results.append(result)
            
            if result.get("status") == "success":
                self.applied_mitigations.append({
                    "plan": plan,
                    "result": result,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
        
        return results
    
    def generate_defense_rules(self, threat_details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate defense rules (YARA, Snort, etc.) for a specific threat
        
        Args:
            threat_details: Details about the threat
            
        Returns:
            Dictionary containing generated rules
        """
        if not self.rule_generation:
            self.logger.warning("Rule generation disabled. Skipping.")
            return {"status": "skipped", "reason": "rule_generation_disabled"}
        
        self.logger.info("Generating defense rules")
        
        # Extract attack pattern if available
        attack_pattern = threat_details.get("attack_pattern", "")
        if not attack_pattern and "exploitation_results" in threat_details:
            # Try to extract from exploitation results
            for result in threat_details.get("exploitation_results", []):
                if result.get("status") == "success":
                    attack_pattern += str(result.get("details", "")) + "\n"
        
        # Format the prompt
        prompt = self.prompts.get("rule_generation", "")
        prompt = prompt.format(
            threat_details=str(threat_details),
            attack_pattern=attack_pattern
        )
        
        # Query LLM for defense rules
        response = self.llm.generate(prompt)
        
        # Parse rules
        rules = self.defense_engine.parse_rules(response)
        
        # Store generated rules
        self.generated_rules.append({
            "threat": threat_details,
            "rules": rules,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        
        return rules
    
    def deploy_rules(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deploy generated defense rules to security systems
        
        Args:
            rules: Dictionary containing rules to deploy
            
        Returns:
            Dictionary containing deployment results
        """
        self.logger.info("Deploying defense rules")
        
        # Deploy the rules
        result = self.defense_engine.deploy_rules(rules)
        
        return result
    
    def monitor_system(self) -> Dict[str, Any]:
        """
        Monitor the system for security events
        
        Returns:
            Dictionary containing monitoring results
        """
        self.logger.info("Monitoring system")
        
        # Monitor the system
        monitoring_results = self.intrusion_detector.monitor()
        
        return monitoring_results
    
    def get_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive report of all defensive actions
        
        Returns:
            Dictionary containing the full report
        """
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "assessed_vulnerabilities": self.current_vulnerabilities,
            "mitigation_plans": self.mitigation_plans,
            "applied_mitigations": self.applied_mitigations,
            "generated_rules": self.generated_rules,
            "summary": {
                "total_vulnerabilities": len(self.current_vulnerabilities),
                "mitigated_vulnerabilities": len(self.applied_mitigations),
                "rules_generated": sum(len(r.get("rules", {})) for r in self.generated_rules)
            }
        }
        
        return report
