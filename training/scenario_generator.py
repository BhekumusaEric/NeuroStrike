"""
Scenario Generator Module
Generates training scenarios for specialized AI agents
"""

import os
import sys
import json
import time
import random
import subprocess
import tempfile
from typing import Dict, List, Any, Optional, Tuple

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

class ScenarioGenerator:
    """
    Generates training scenarios for specialized AI agents
    """
    
    def __init__(self, config_path: str = "config/training.json"):
        """
        Initialize the Scenario Generator
        
        Args:
            config_path: Path to the training configuration file
        """
        self.logger = get_logger("scenario_generator")
        self.logger.info("Initializing Scenario Generator")
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Create samples directory if it doesn't exist
        samples_dir = "samples"
        if not os.path.exists(samples_dir):
            os.makedirs(samples_dir)
            self.logger.info(f"Created samples directory: {samples_dir}")
        
        self.logger.info("Scenario Generator initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"Configuration file not found: {config_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            return {}
    
    def generate_scenarios(self, phase: str = "basic", count: int = 5) -> List[Dict[str, Any]]:
        """
        Generate training scenarios for a specific phase
        
        Args:
            phase: Training phase
            count: Number of scenarios to generate
            
        Returns:
            List of scenario dictionaries
        """
        self.logger.info(f"Generating {count} scenarios for phase: {phase}")
        
        scenarios = []
        
        # Generate scenarios based on phase
        if phase == "basic":
            scenarios = self._generate_basic_scenarios(count)
        elif phase == "intermediate":
            scenarios = self._generate_intermediate_scenarios(count)
        elif phase == "advanced":
            scenarios = self._generate_advanced_scenarios(count)
        elif phase == "expert":
            scenarios = self._generate_expert_scenarios(count)
        else:
            self.logger.warning(f"Unknown phase: {phase}")
            scenarios = self._generate_basic_scenarios(count)
        
        self.logger.info(f"Generated {len(scenarios)} scenarios")
        
        return scenarios
    
    def _generate_basic_scenarios(self, count: int) -> List[Dict[str, Any]]:
        """Generate basic training scenarios"""
        scenarios = []
        
        # Define scenario types
        scenario_types = [
            "binary_analysis",
            "memory_analysis",
            "function_matching",
            "vulnerability_detection",
            "workflow_automation"
        ]
        
        # Generate scenarios
        for i in range(count):
            scenario_type = random.choice(scenario_types)
            
            if scenario_type == "binary_analysis":
                scenarios.append(self._generate_basic_binary_analysis_scenario())
            elif scenario_type == "memory_analysis":
                scenarios.append(self._generate_basic_memory_analysis_scenario())
            elif scenario_type == "function_matching":
                scenarios.append(self._generate_basic_function_matching_scenario())
            elif scenario_type == "vulnerability_detection":
                scenarios.append(self._generate_basic_vulnerability_detection_scenario())
            elif scenario_type == "workflow_automation":
                scenarios.append(self._generate_basic_workflow_automation_scenario())
        
        return scenarios
    
    def _generate_intermediate_scenarios(self, count: int) -> List[Dict[str, Any]]:
        """Generate intermediate training scenarios"""
        # Similar to basic scenarios but with higher difficulty
        scenarios = self._generate_basic_scenarios(count)
        
        for scenario in scenarios:
            scenario["difficulty"] = 2
            
            # Add more complexity based on scenario type
            if scenario["type"] == "binary_analysis":
                scenario["obfuscation_level"] = "light"
            elif scenario["type"] == "vulnerability_detection":
                scenario["vulnerability_complexity"] = "medium"
        
        return scenarios
    
    def _generate_advanced_scenarios(self, count: int) -> List[Dict[str, Any]]:
        """Generate advanced training scenarios"""
        # Similar to intermediate scenarios but with higher difficulty
        scenarios = self._generate_intermediate_scenarios(count)
        
        for scenario in scenarios:
            scenario["difficulty"] = 3
            
            # Add more complexity based on scenario type
            if scenario["type"] == "binary_analysis":
                scenario["obfuscation_level"] = "medium"
            elif scenario["type"] == "vulnerability_detection":
                scenario["vulnerability_complexity"] = "high"
        
        return scenarios
    
    def _generate_expert_scenarios(self, count: int) -> List[Dict[str, Any]]:
        """Generate expert training scenarios"""
        # Similar to advanced scenarios but with higher difficulty
        scenarios = self._generate_advanced_scenarios(count)
        
        for scenario in scenarios:
            scenario["difficulty"] = 4
            
            # Add more complexity based on scenario type
            if scenario["type"] == "binary_analysis":
                scenario["obfuscation_level"] = "heavy"
            elif scenario["type"] == "vulnerability_detection":
                scenario["vulnerability_complexity"] = "very_high"
        
        return scenarios
    
    def _generate_basic_binary_analysis_scenario(self) -> Dict[str, Any]:
        """Generate a basic binary analysis scenario"""
        # Create a simple binary with known characteristics
        binary_path = self._create_simple_binary()
        
        return {
            "type": "binary_analysis",
            "difficulty": 1,
            "binary_path": binary_path,
            "task": "analyze",
            "expected_results": {
                "has_main_function": True,
                "has_buffer_overflow": False,
                "has_format_string": False
            }
        }
    
    def _generate_basic_memory_analysis_scenario(self) -> Dict[str, Any]:
        """Generate a basic memory analysis scenario"""
        # Create a simple memory dump with known characteristics
        dump_path = self._create_simple_memory_dump()
        
        return {
            "type": "memory_analysis",
            "difficulty": 1,
            "dump_path": dump_path,
            "task": "analyze",
            "expected_results": {
                "has_encryption": False,
                "has_credentials": True,
                "has_network_data": False
            }
        }
    
    def _generate_basic_function_matching_scenario(self) -> Dict[str, Any]:
        """Generate a basic function matching scenario"""
        # Create two simple binaries with some common functions
        binary1_path = self._create_simple_binary()
        binary2_path = self._create_simple_binary(variant=True)
        
        return {
            "type": "function_matching",
            "difficulty": 1,
            "binary_path": binary1_path,
            "reference_binary_path": binary2_path,
            "task": "find_similar",
            "expected_results": {
                "common_functions": ["main", "init", "cleanup"],
                "unique_functions": ["process_data", "handle_error"]
            }
        }
    
    def _generate_basic_vulnerability_detection_scenario(self) -> Dict[str, Any]:
        """Generate a basic vulnerability detection scenario"""
        # Create a simple vulnerable binary
        binary_path = self._create_vulnerable_binary()
        
        return {
            "type": "vulnerability_detection",
            "difficulty": 1,
            "binary_path": binary_path,
            "task": "find_vulnerabilities",
            "expected_results": {
                "vulnerability_types": ["buffer_overflow"],
                "vulnerable_functions": ["process_input"],
                "exploitable": True
            }
        }
    
    def _generate_basic_workflow_automation_scenario(self) -> Dict[str, Any]:
        """Generate a basic workflow automation scenario"""
        # Create a simple binary for workflow automation
        binary_path = self._create_simple_binary()
        
        return {
            "type": "workflow_automation",
            "difficulty": 1,
            "binary_path": binary_path,
            "task": "generate_yara_rule",
            "description": "Detect this specific binary",
            "expected_results": {
                "rule_should_match": [binary_path],
                "rule_should_not_match": []
            }
        }
    
    def _create_simple_binary(self, variant: bool = False) -> str:
        """
        Create a simple binary for training
        
        Args:
            variant: Whether to create a variant of the basic binary
            
        Returns:
            Path to the created binary
        """
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        
        # Create a simple C program
        c_code = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        
        void init() {
            printf("Initializing...\n");
        }
        
        void cleanup() {
            printf("Cleaning up...\n");
        }
        
        """
        
        if variant:
            c_code += """
            void process_data_v2(char *data) {
                printf("Processing data: %s\n", data);
            }
            
            void handle_error_v2(int error_code) {
                printf("Error: %d\n", error_code);
            }
            
            int main(int argc, char *argv[]) {
                init();
                
                if (argc < 2) {
                    handle_error_v2(1);
                    cleanup();
                    return 1;
                }
                
                process_data_v2(argv[1]);
                
                cleanup();
                return 0;
            }
            """
        else:
            c_code += """
            void process_data(char *data) {
                printf("Processing data: %s\n", data);
            }
            
            void handle_error(int error_code) {
                printf("Error: %d\n", error_code);
            }
            
            int main(int argc, char *argv[]) {
                init();
                
                if (argc < 2) {
                    handle_error(1);
                    cleanup();
                    return 1;
                }
                
                process_data(argv[1]);
                
                cleanup();
                return 0;
            }
            """
        
        # Write the C code to a file
        c_file_path = os.path.join(temp_dir, "simple.c")
        with open(c_file_path, "w") as f:
            f.write(c_code)
        
        # Compile the C program
        binary_name = "simple_variant" if variant else "simple"
        binary_path = os.path.join("samples", f"{binary_name}_{int(time.time())}")
        
        try:
            subprocess.run(["gcc", c_file_path, "-o", binary_path], check=True)
            self.logger.info(f"Created simple binary: {binary_path}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error compiling simple binary: {e}")
            binary_path = ""
        
        return binary_path
    
    def _create_vulnerable_binary(self) -> str:
        """
        Create a vulnerable binary for training
        
        Returns:
            Path to the created binary
        """
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        
        # Create a vulnerable C program (buffer overflow)
        c_code = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        
        void process_input(char *input) {
            char buffer[64];
            strcpy(buffer, input);  // Buffer overflow vulnerability
            printf("Processed input: %s\n", buffer);
        }
        
        int main(int argc, char *argv[]) {
            if (argc < 2) {
                printf("Usage: %s <input>\n", argv[0]);
                return 1;
            }
            
            process_input(argv[1]);
            
            return 0;
        }
        """
        
        # Write the C code to a file
        c_file_path = os.path.join(temp_dir, "vulnerable.c")
        with open(c_file_path, "w") as f:
            f.write(c_code)
        
        # Compile the C program without stack protection
        binary_path = os.path.join("samples", f"vulnerable_{int(time.time())}")
        
        try:
            subprocess.run(["gcc", c_file_path, "-o", binary_path, "-fno-stack-protector"], check=True)
            self.logger.info(f"Created vulnerable binary: {binary_path}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error compiling vulnerable binary: {e}")
            binary_path = ""
        
        return binary_path
    
    def _create_simple_memory_dump(self) -> str:
        """
        Create a simple memory dump for training
        
        Returns:
            Path to the created memory dump
        """
        # Create a memory dump with some patterns
        dump_path = os.path.join("samples", f"memory_dump_{int(time.time())}.bin")
        
        try:
            with open(dump_path, "wb") as f:
                # Write some header
                f.write(b"MEMORY_DUMP\x00")
                
                # Write some process information
                f.write(b"PROCESS_INFO\x00")
                f.write(b"PID: 1234\x00")
                f.write(b"NAME: test_process\x00")
                
                # Write some credentials
                f.write(b"CREDENTIALS\x00")
                f.write(b"username=admin\x00")
                f.write(b"password=password123\x00")
                
                # Write some random data
                for i in range(1000):
                    f.write(bytes([random.randint(0, 255)]))
                
                # Write some structured data
                f.write(b"STRUCTURED_DATA\x00")
                for i in range(10):
                    f.write(f"ENTRY_{i}\x00".encode())
                    f.write(f"VALUE_{i}\x00".encode())
                
                # Write some more random data
                for i in range(1000):
                    f.write(bytes([random.randint(0, 255)]))
            
            self.logger.info(f"Created simple memory dump: {dump_path}")
        except Exception as e:
            self.logger.error(f"Error creating simple memory dump: {e}")
            dump_path = ""
        
        return dump_path
