"""
Red Agent Module - Offensive Security AI
"""

import os
import yaml
import time
import json
import logging
from typing import Dict, List, Any, Optional

# Import core modules
from ai_models.model_loader import load_llm
from core.analyzer import NetworkAnalyzer
from core.exploit_simulator import ExploitEngine
from utils.logger import get_logger

# Import binary analysis modules
try:
    from binary_analysis.analyzer import BinaryAnalyzer
    from binary_analysis.memory_analyzer import MemoryAnalyzer
    from binary_analysis.function_matcher import FunctionMatcher
    from binary_analysis.exploit_pathfinder import ExploitPathfinder
    from binary_analysis.workflow_automation import WorkflowAutomation
    BINARY_ANALYSIS_AVAILABLE = True
except ImportError:
    BINARY_ANALYSIS_AVAILABLE = False

class RedAgent:
    """
    Red Team Agent for offensive security operations
    Analyzes networks, identifies vulnerabilities, and generates exploitation strategies
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Red Agent

        Args:
            config: Configuration dictionary for the Red Agent
        """
        self.config = config
        self.logger = get_logger("red_agent")
        self.scan_only = config.get("scan_only", True)
        self.safe_mode = config.get("safe_mode", True)

        # Load prompt templates
        self.prompts = self._load_prompts()

        # Initialize LLM
        self.llm = load_llm()

        # Initialize core components
        self.analyzer = NetworkAnalyzer()
        self.exploit_engine = ExploitEngine(safe_mode=self.safe_mode)

        # Initialize binary analysis components if available
        if BINARY_ANALYSIS_AVAILABLE:
            self.binary_analyzer = BinaryAnalyzer()
            self.memory_analyzer = MemoryAnalyzer()
            self.function_matcher = FunctionMatcher()
            self.exploit_pathfinder = ExploitPathfinder()
            self.workflow_automation = WorkflowAutomation()
            self.logger.info("Binary analysis components initialized")
        else:
            self.logger.warning("Binary analysis components not available")

        # State tracking
        self.current_target = None
        self.current_binary = None
        self.discovered_vulnerabilities = []
        self.exploitation_results = []
        self.binary_analysis_results = {}

        self.logger.info("Red Agent initialized")

    def _load_prompts(self) -> Dict[str, str]:
        """Load prompt templates from YAML file"""
        try:
            with open("config/prompts.yaml", "r") as file:
                all_prompts = yaml.safe_load(file)
                return all_prompts.get("red_agent", {})
        except Exception as e:
            self.logger.error(f"Error loading prompts: {e}")
            return {}

    def scan_target(self, target: str) -> Dict[str, Any]:
        """
        Scan a target network or host for information gathering

        Args:
            target: IP address, hostname, or CIDR range

        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Scanning target: {target}")
        self.current_target = target

        # Perform network scan
        scan_results = self.analyzer.scan_network(target)

        # Store results
        self.scan_results = scan_results

        return scan_results

    def analyze_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Analyze scan results to identify potential vulnerabilities

        Returns:
            List of identified vulnerabilities
        """
        if not hasattr(self, 'scan_results'):
            self.logger.error("No scan results available. Run scan_target first.")
            return []

        self.logger.info("Analyzing vulnerabilities")

        # Prepare input for LLM
        system_info = self.scan_results.get("system_info", "")
        network_info = self.scan_results.get("network_info", "")
        ports_and_services = self.scan_results.get("ports_and_services", "")

        # Format the prompt
        prompt = self.prompts.get("vulnerability_analysis", "")
        prompt = prompt.format(
            system_info=system_info,
            network_info=network_info,
            ports_and_services=ports_and_services
        )

        # Query LLM for vulnerability analysis
        response = self.llm.generate(prompt)

        # Parse vulnerabilities from response
        vulnerabilities = self.analyzer.parse_vulnerabilities(response)

        # Store results
        self.discovered_vulnerabilities = vulnerabilities

        return vulnerabilities

    def generate_exploit_plan(self, vulnerability_id: int) -> Dict[str, Any]:
        """
        Generate an exploitation plan for a specific vulnerability

        Args:
            vulnerability_id: Index of the vulnerability to exploit

        Returns:
            Dictionary containing the exploitation plan
        """
        if not self.discovered_vulnerabilities:
            self.logger.error("No vulnerabilities discovered. Run analyze_vulnerabilities first.")
            return {}

        if vulnerability_id >= len(self.discovered_vulnerabilities):
            self.logger.error(f"Invalid vulnerability ID: {vulnerability_id}")
            return {}

        vulnerability = self.discovered_vulnerabilities[vulnerability_id]
        self.logger.info(f"Generating exploit plan for: {vulnerability.get('description', 'Unknown vulnerability')}")

        # Prepare input for LLM
        vulnerability_details = str(vulnerability)
        target_system = str(self.scan_results)

        # Format the prompt
        prompt = self.prompts.get("exploit_generation", "")
        prompt = prompt.format(
            vulnerability_details=vulnerability_details,
            target_system=target_system
        )

        # Query LLM for exploit plan
        response = self.llm.generate(prompt)

        # Parse exploit plan
        exploit_plan = self.exploit_engine.parse_exploit_plan(response)

        return exploit_plan

    def execute_exploit(self, exploit_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an exploitation plan against the target

        Args:
            exploit_plan: Dictionary containing the exploitation plan

        Returns:
            Dictionary containing the exploitation results
        """
        if self.scan_only:
            self.logger.warning("Scan-only mode enabled. Skipping exploitation.")
            return {"status": "skipped", "reason": "scan_only_mode"}

        if self.safe_mode:
            self.logger.info("Safe mode enabled. Simulating exploitation only.")

        self.logger.info(f"Executing exploit plan: {exploit_plan.get('name', 'Unnamed exploit')}")

        # Execute the exploit
        result = self.exploit_engine.execute(exploit_plan, self.current_target)

        # Store result
        self.exploitation_results.append(result)

        return result

    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze a binary file

        Args:
            binary_path: Path to the binary file

        Returns:
            Dictionary containing analysis results
        """
        if not BINARY_ANALYSIS_AVAILABLE:
            self.logger.error("Binary analysis components not available")
            return {"error": "Binary analysis components not available"}

        if not os.path.exists(binary_path):
            self.logger.error(f"Binary file not found: {binary_path}")
            return {"error": f"Binary file not found: {binary_path}"}

        self.logger.info(f"Analyzing binary: {binary_path}")
        self.current_binary = binary_path

        # Perform binary analysis
        analysis_results = self.binary_analyzer.analyze_binary(binary_path)

        # Store results
        self.binary_analysis_results["basic_analysis"] = analysis_results

        # Use LLM to enhance analysis with binary_analysis prompt
        if "binary_analysis" in self.prompts:
            try:
                # Extract relevant information for the prompt
                binary_info = json.dumps(analysis_results.get("file_info", {}), indent=2)
                functions = json.dumps(analysis_results.get("functions", []), indent=2)
                strings = "\n".join(analysis_results.get("strings", [])[:100])  # Limit to first 100 strings

                # Format the prompt
                prompt = self.prompts["binary_analysis"].format(
                    binary_info=binary_info,
                    functions=functions,
                    strings=strings
                )

                # Generate enhanced analysis
                enhanced_analysis = self.llm.generate(prompt)

                # Add enhanced analysis to results
                analysis_results["enhanced_analysis"] = enhanced_analysis
                self.binary_analysis_results["enhanced_analysis"] = enhanced_analysis

                self.logger.info("Enhanced binary analysis with LLM")
            except Exception as e:
                self.logger.error(f"Error enhancing binary analysis with LLM: {e}")

        return analysis_results

    def find_binary_vulnerabilities(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Find potential vulnerabilities in the current binary

        Returns:
            Dictionary mapping vulnerability types to lists of potential vulnerabilities
        """
        if not BINARY_ANALYSIS_AVAILABLE:
            self.logger.error("Binary analysis components not available")
            return {"error": "Binary analysis components not available"}

        if not self.current_binary:
            self.logger.error("No binary selected. Run analyze_binary first.")
            return {"error": "No binary selected"}

        self.logger.info(f"Finding vulnerabilities in binary: {self.current_binary}")

        # Find potential vulnerabilities
        vulnerabilities = self.exploit_pathfinder.find_potential_vulnerabilities(self.current_binary)

        # Store results
        self.binary_analysis_results["vulnerabilities"] = vulnerabilities

        return vulnerabilities

    def generate_binary_exploit(self, vulnerability_type: str, vulnerability_index: int = 0) -> Dict[str, Any]:
        """
        Generate an exploit for a binary vulnerability

        Args:
            vulnerability_type: Type of vulnerability to exploit
            vulnerability_index: Index of the vulnerability to exploit

        Returns:
            Dictionary containing the suggested exploit path
        """
        if not BINARY_ANALYSIS_AVAILABLE:
            self.logger.error("Binary analysis components not available")
            return {"error": "Binary analysis components not available"}

        if not self.current_binary:
            self.logger.error("No binary selected. Run analyze_binary first.")
            return {"error": "No binary selected"}

        if "vulnerabilities" not in self.binary_analysis_results:
            self.logger.error("No vulnerabilities found. Run find_binary_vulnerabilities first.")
            return {"error": "No vulnerabilities found"}

        vulnerabilities = self.binary_analysis_results["vulnerabilities"]

        if vulnerability_type not in vulnerabilities:
            self.logger.error(f"Vulnerability type not found: {vulnerability_type}")
            return {"error": f"Vulnerability type not found: {vulnerability_type}"}

        if vulnerability_index >= len(vulnerabilities[vulnerability_type]):
            self.logger.error(f"Invalid vulnerability index: {vulnerability_index}")
            return {"error": f"Invalid vulnerability index: {vulnerability_index}"}

        vulnerability = vulnerabilities[vulnerability_type][vulnerability_index]

        self.logger.info(f"Generating exploit for vulnerability: {vulnerability_type}")

        # Generate exploit path
        exploit_path = self.exploit_pathfinder.suggest_exploit_path(self.current_binary, vulnerability)

        # Store results
        if "exploits" not in self.binary_analysis_results:
            self.binary_analysis_results["exploits"] = []

        self.binary_analysis_results["exploits"].append(exploit_path)

        # Use LLM to enhance exploit path with exploit_pathfinding prompt
        if "exploit_pathfinding" in self.prompts:
            try:
                # Get binary information
                binary_info = {}
                if "basic_analysis" in self.binary_analysis_results:
                    binary_info = self.binary_analysis_results["basic_analysis"].get("file_info", {})

                # Format the prompt
                prompt = self.prompts["exploit_pathfinding"].format(
                    vulnerability=json.dumps(vulnerability, indent=2),
                    binary_info=json.dumps(binary_info, indent=2),
                    constraints=json.dumps({
                        "safe_mode": self.safe_mode,
                        "target_os": binary_info.get("type", "unknown")
                    }, indent=2)
                )

                # Generate enhanced exploit path
                enhanced_exploit = self.llm.generate(prompt)

                # Add enhanced exploit to results
                exploit_path["enhanced_exploit"] = enhanced_exploit

                self.logger.info("Enhanced exploit path with LLM")
            except Exception as e:
                self.logger.error(f"Error enhancing exploit path with LLM: {e}")

        return exploit_path

    def analyze_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """
        Analyze a memory dump file

        Args:
            dump_path: Path to the memory dump file

        Returns:
            Dictionary containing analysis results
        """
        if not BINARY_ANALYSIS_AVAILABLE:
            self.logger.error("Binary analysis components not available")
            return {"error": "Binary analysis components not available"}

        if not os.path.exists(dump_path):
            self.logger.error(f"Memory dump file not found: {dump_path}")
            return {"error": f"Memory dump file not found: {dump_path}"}

        self.logger.info(f"Analyzing memory dump: {dump_path}")

        # Analyze memory dump
        analysis_results = self.memory_analyzer.analyze_memory_dump(dump_path)

        # Store results
        self.binary_analysis_results["memory_analysis"] = analysis_results

        # Use LLM to enhance analysis with memory_analysis prompt
        if "memory_analysis" in self.prompts:
            try:
                # Extract relevant information for the prompt
                memory_info = json.dumps(analysis_results.get("file_info", {}), indent=2)
                regions = json.dumps(analysis_results.get("entropy_regions", []), indent=2)
                if not regions:
                    regions = json.dumps(analysis_results.get("patterns", []), indent=2)

                # Format the prompt
                prompt = self.prompts["memory_analysis"].format(
                    memory_info=memory_info,
                    regions=regions
                )

                # Generate enhanced analysis
                enhanced_analysis = self.llm.generate(prompt)

                # Add enhanced analysis to results
                analysis_results["enhanced_analysis"] = enhanced_analysis
                self.binary_analysis_results["memory_enhanced_analysis"] = enhanced_analysis

                self.logger.info("Enhanced memory analysis with LLM")
            except Exception as e:
                self.logger.error(f"Error enhancing memory analysis with LLM: {e}")

        return analysis_results

    def generate_yara_rule(self, description: str) -> Dict[str, Any]:
        """
        Generate a YARA rule for the current binary

        Args:
            description: Description of what to detect

        Returns:
            Dictionary containing the generated YARA rule
        """
        if not BINARY_ANALYSIS_AVAILABLE:
            self.logger.error("Binary analysis components not available")
            return {"error": "Binary analysis components not available"}

        if not self.current_binary:
            self.logger.error("No binary selected. Run analyze_binary first.")
            return {"error": "No binary selected"}

        self.logger.info(f"Generating YARA rule for: {description}")

        # Generate YARA rule
        yara_rule = self.workflow_automation.generate_yara_rule(self.current_binary, description)

        # Store results
        if "yara_rules" not in self.binary_analysis_results:
            self.binary_analysis_results["yara_rules"] = []

        self.binary_analysis_results["yara_rules"].append(yara_rule)

        return yara_rule

    def get_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive report of all findings

        Returns:
            Dictionary containing the full report
        """
        report = {
            "target": self.current_target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.discovered_vulnerabilities,
            "exploitation_results": self.exploitation_results,
            "summary": {
                "total_vulnerabilities": len(self.discovered_vulnerabilities),
                "exploited_vulnerabilities": len([r for r in self.exploitation_results if r.get("status") == "success"]),
                "failed_exploits": len([r for r in self.exploitation_results if r.get("status") == "failed"])
            }
        }

        # Add binary analysis results if available
        if self.current_binary and self.binary_analysis_results:
            report["binary_analysis"] = {
                "binary_path": self.current_binary,
                "results": self.binary_analysis_results
            }

        return report
