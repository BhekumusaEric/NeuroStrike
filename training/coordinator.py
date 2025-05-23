"""
Training Coordinator Module
Coordinates the training of specialized AI agents and facilitates their communication
"""

import os
import sys
import json
import time
import random
import logging
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger
from ai_models.model_loader import load_llm
from agents.red_agent import RedAgent
from binary_analysis.analyzer import BinaryAnalyzer
from binary_analysis.memory_analyzer import MemoryAnalyzer
from binary_analysis.function_matcher import FunctionMatcher
from binary_analysis.exploit_pathfinder import ExploitPathfinder
from binary_analysis.workflow_automation import WorkflowAutomation

class TrainingCoordinator:
    """
    Coordinates the training of specialized AI agents and facilitates their communication
    """

    def __init__(self, config_path: str = "config/training.json"):
        """
        Initialize the Training Coordinator

        Args:
            config_path: Path to the training configuration file
        """
        self.logger = get_logger("training_coordinator")
        self.logger.info("Initializing Training Coordinator")

        # Load configuration
        self.config = self._load_config(config_path)

        # Initialize specialized agents
        self.agents = {}
        self._initialize_agents()

        # Initialize communication channels
        self.channels = {}
        self._initialize_channels()

        # Training state
        self.training_state = {
            "current_phase": "initialization",
            "completed_phases": [],
            "current_scenario": None,
            "completed_scenarios": [],
            "agent_performance": {},
            "start_time": time.time(),
            "end_time": None
        }

        self.logger.info("Training Coordinator initialized")

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"Configuration file not found: {config_path}")
                return self._create_default_config(config_path)
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            return self._create_default_config(config_path)

    def _create_default_config(self, config_path: str) -> Dict[str, Any]:
        """Create default configuration"""
        config = {
            "training": {
                "phases": ["basic", "intermediate", "advanced", "expert"],
                "scenarios_per_phase": 5,
                "max_iterations_per_scenario": 10,
                "learning_rate": 0.1,
                "feedback_threshold": 0.7
            },
            "agents": {
                "binary_analyzer": {
                    "model": "gpt-3.5-turbo",
                    "temperature": 0.2,
                    "max_tokens": 1000
                },
                "memory_analyzer": {
                    "model": "gpt-3.5-turbo",
                    "temperature": 0.3,
                    "max_tokens": 1000
                },
                "function_matcher": {
                    "model": "gpt-3.5-turbo",
                    "temperature": 0.1,
                    "max_tokens": 1000
                },
                "exploit_pathfinder": {
                    "model": "gpt-4",
                    "temperature": 0.7,
                    "max_tokens": 2000
                },
                "workflow_automation": {
                    "model": "gpt-3.5-turbo",
                    "temperature": 0.4,
                    "max_tokens": 1500
                },
                "coordinator": {
                    "model": "gpt-4",
                    "temperature": 0.5,
                    "max_tokens": 2000
                }
            },
            "communication": {
                "channels": ["binary_analysis", "vulnerability_detection", "exploit_generation", "workflow_automation"],
                "message_history_limit": 50
            },
            "scenarios": {
                "basic": [
                    {"type": "binary_analysis", "difficulty": 1, "target": "samples/basic_buffer_overflow.bin"},
                    {"type": "memory_analysis", "difficulty": 1, "target": "samples/basic_memory_dump.bin"},
                    {"type": "function_matching", "difficulty": 1, "target": "samples/basic_stripped_binary.bin"},
                    {"type": "vulnerability_detection", "difficulty": 1, "target": "samples/basic_vulnerable_app.bin"},
                    {"type": "workflow_automation", "difficulty": 1, "target": "samples/basic_malware.bin"}
                ],
                "intermediate": [
                    {"type": "binary_analysis", "difficulty": 2, "target": "samples/intermediate_obfuscated.bin"},
                    {"type": "memory_analysis", "difficulty": 2, "target": "samples/intermediate_memory_dump.bin"},
                    {"type": "function_matching", "difficulty": 2, "target": "samples/intermediate_stripped_binary.bin"},
                    {"type": "vulnerability_detection", "difficulty": 2, "target": "samples/intermediate_vulnerable_app.bin"},
                    {"type": "workflow_automation", "difficulty": 2, "target": "samples/intermediate_malware.bin"}
                ],
                "advanced": [
                    {"type": "binary_analysis", "difficulty": 3, "target": "samples/advanced_obfuscated.bin"},
                    {"type": "memory_analysis", "difficulty": 3, "target": "samples/advanced_memory_dump.bin"},
                    {"type": "function_matching", "difficulty": 3, "target": "samples/advanced_stripped_binary.bin"},
                    {"type": "vulnerability_detection", "difficulty": 3, "target": "samples/advanced_vulnerable_app.bin"},
                    {"type": "workflow_automation", "difficulty": 3, "target": "samples/advanced_malware.bin"}
                ],
                "expert": [
                    {"type": "binary_analysis", "difficulty": 4, "target": "samples/expert_obfuscated.bin"},
                    {"type": "memory_analysis", "difficulty": 4, "target": "samples/expert_memory_dump.bin"},
                    {"type": "function_matching", "difficulty": 4, "target": "samples/expert_stripped_binary.bin"},
                    {"type": "vulnerability_detection", "difficulty": 4, "target": "samples/expert_vulnerable_app.bin"},
                    {"type": "workflow_automation", "difficulty": 4, "target": "samples/expert_malware.bin"}
                ]
            }
        }

        # Save default configuration
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            self.logger.info(f"Default configuration saved to: {config_path}")
        except Exception as e:
            self.logger.error(f"Error saving default configuration: {e}")

        return config

    def _initialize_agents(self):
        """Initialize specialized AI agents"""
        self.logger.info("Initializing specialized AI agents")

        # Initialize Red Agent
        red_config = {
            "safe_mode": True,
            "scan_only": False,
            "verbose": True
        }
        self.agents["red_agent"] = RedAgent(red_config)

        # Initialize specialized agents with LLMs
        agent_configs = self.config.get("agents", {})

        for agent_name, agent_config in agent_configs.items():
            model = agent_config.get("model", "gpt-3.5-turbo")
            temperature = agent_config.get("temperature", 0.5)
            max_tokens = agent_config.get("max_tokens", 1000)

            # Load LLM for the agent
            self.agents[agent_name] = {
                "llm": load_llm(model_name=model, temperature=temperature, max_tokens=max_tokens),
                "config": agent_config,
                "performance": {
                    "success_rate": 0.0,
                    "iterations": 0,
                    "successful_iterations": 0,
                    "average_time": 0.0,
                    "total_time": 0.0
                }
            }

        self.logger.info(f"Initialized {len(self.agents)} specialized AI agents")

    def _initialize_channels(self):
        """Initialize communication channels between agents"""
        self.logger.info("Initializing communication channels")

        channel_configs = self.config.get("communication", {}).get("channels", [])
        message_history_limit = self.config.get("communication", {}).get("message_history_limit", 50)

        for channel_name in channel_configs:
            self.channels[channel_name] = {
                "messages": [],
                "subscribers": [],
                "message_history_limit": message_history_limit
            }

        self.logger.info(f"Initialized {len(self.channels)} communication channels")

    def subscribe_agent_to_channel(self, agent_name: str, channel_name: str):
        """Subscribe an agent to a communication channel"""
        if channel_name in self.channels and agent_name in self.agents:
            if agent_name not in self.channels[channel_name]["subscribers"]:
                self.channels[channel_name]["subscribers"].append(agent_name)
                self.logger.info(f"Agent '{agent_name}' subscribed to channel '{channel_name}'")
        else:
            self.logger.warning(f"Cannot subscribe agent '{agent_name}' to channel '{channel_name}': not found")

    def publish_message(self, agent_name: str, channel_name: str, message: Dict[str, Any]):
        """Publish a message to a communication channel"""
        if channel_name in self.channels:
            message_with_metadata = {
                "sender": agent_name,
                "timestamp": time.time(),
                "content": message
            }

            self.channels[channel_name]["messages"].append(message_with_metadata)

            # Trim message history if needed
            if len(self.channels[channel_name]["messages"]) > self.channels[channel_name]["message_history_limit"]:
                self.channels[channel_name]["messages"] = self.channels[channel_name]["messages"][-self.channels[channel_name]["message_history_limit"]:]

            self.logger.debug(f"Message published to channel '{channel_name}' by agent '{agent_name}'")

            # Notify subscribers
            for subscriber in self.channels[channel_name]["subscribers"]:
                if subscriber != agent_name:  # Don't notify the sender
                    self._process_message(subscriber, channel_name, message_with_metadata)
        else:
            self.logger.warning(f"Cannot publish message to channel '{channel_name}': not found")

    def _process_message(self, agent_name: str, channel_name: str, message: Dict[str, Any]):
        """Process a message received by an agent"""
        self.logger.debug(f"Agent '{agent_name}' processing message from channel '{channel_name}'")

        # Get the agent instance
        agent = self.agents.get(agent_name)
        if not agent:
            self.logger.warning(f"Agent '{agent_name}' not found for message processing")
            return

        # Process the message based on the channel
        if channel_name == "binary_analysis":
            # Process binary analysis messages
            if agent_name in ["binary_analysis", "function_matching", "memory_analysis"]:
                agent.process_channel_message(channel_name, message)

        elif channel_name == "vulnerability_detection":
            # Process vulnerability detection messages
            if agent_name in ["exploit_pathfinding", "workflow_automation"]:
                agent.process_channel_message(channel_name, message)

        elif channel_name == "exploit_generation":
            # Process exploit generation messages
            if agent_name in ["exploit_pathfinding", "workflow_automation"]:
                agent.process_channel_message(channel_name, message)

        elif channel_name == "workflow_automation":
            # Process workflow automation messages
            if agent_name in ["workflow_automation"]:
                agent.process_channel_message(channel_name, message)

        # Log that the message was processed
        self.logger.debug(f"Agent '{agent_name}' processed message from channel '{channel_name}'")

        # Update agent performance metrics based on message processing
        if "performance_metrics" in message.get("content", {}):
            metrics = message["content"]["performance_metrics"]
            if agent_name in self.training_state["agent_performance"]:
                self.training_state["agent_performance"][agent_name].update(metrics)
            else:
                self.training_state["agent_performance"][agent_name] = metrics

    def start_training(self):
        """Start the training process"""
        self.logger.info("Starting training process")

        # Set up training phases
        phases = self.config.get("training", {}).get("phases", ["basic"])

        for phase in phases:
            self.training_state["current_phase"] = phase
            self.logger.info(f"Starting training phase: {phase}")

            # Get scenarios for this phase
            scenarios = self.config.get("scenarios", {}).get(phase, [])

            if not scenarios:
                self.logger.warning(f"No scenarios found for phase: {phase}")
                continue

            # Run each scenario
            for scenario in scenarios:
                self._run_scenario(scenario)

            # Record completion of phase
            self.training_state["completed_phases"].append(phase)
            self.logger.info(f"Completed training phase: {phase}")

        # Record end time
        self.training_state["end_time"] = time.time()
        self.training_state["current_phase"] = "completed"

        # Generate training report
        self._generate_training_report()

        self.logger.info("Training process completed")

    def _run_scenario(self, scenario: Dict[str, Any]):
        """Run a training scenario"""
        scenario_type = scenario.get("type", "unknown")
        difficulty = scenario.get("difficulty", 1)
        target = scenario.get("target", "")

        self.logger.info(f"Running scenario: {scenario_type} (difficulty: {difficulty})")
        self.training_state["current_scenario"] = scenario

        # Check if target exists
        if target and not os.path.exists(target):
            self.logger.warning(f"Target not found: {target}")
            return

        # Run the appropriate scenario handler
        if scenario_type == "binary_analysis":
            self._run_binary_analysis_scenario(scenario)
        elif scenario_type == "memory_analysis":
            self._run_memory_analysis_scenario(scenario)
        elif scenario_type == "function_matching":
            self._run_function_matching_scenario(scenario)
        elif scenario_type == "vulnerability_detection":
            self._run_vulnerability_detection_scenario(scenario)
        elif scenario_type == "workflow_automation":
            self._run_workflow_automation_scenario(scenario)
        else:
            self.logger.warning(f"Unknown scenario type: {scenario_type}")

        # Record completion of scenario
        self.training_state["completed_scenarios"].append(scenario)
        self.logger.info(f"Completed scenario: {scenario_type}")

    def _run_binary_analysis_scenario(self, scenario: Dict[str, Any]):
        """Run a binary analysis training scenario"""
        self.logger.info("Running binary analysis scenario")

        # This would be implemented to run a binary analysis scenario
        # For now, we'll just log it
        pass

    def _run_memory_analysis_scenario(self, scenario: Dict[str, Any]):
        """Run a memory analysis training scenario"""
        self.logger.info("Running memory analysis scenario")

        # This would be implemented to run a memory analysis scenario
        # For now, we'll just log it
        pass

    def _run_function_matching_scenario(self, scenario: Dict[str, Any]):
        """Run a function matching training scenario"""
        self.logger.info("Running function matching scenario")

        # This would be implemented to run a function matching scenario
        # For now, we'll just log it
        pass

    def _run_vulnerability_detection_scenario(self, scenario: Dict[str, Any]):
        """Run a vulnerability detection training scenario"""
        self.logger.info("Running vulnerability detection scenario")

        # This would be implemented to run a vulnerability detection scenario
        # For now, we'll just log it
        pass

    def _run_workflow_automation_scenario(self, scenario: Dict[str, Any]):
        """Run a workflow automation training scenario"""
        self.logger.info("Running workflow automation scenario")

        # This would be implemented to run a workflow automation scenario
        # For now, we'll just log it
        pass

    def _generate_training_report(self):
        """Generate a training report"""
        self.logger.info("Generating training report")

        # This would be implemented to generate a training report
        # For now, we'll just log it
        pass
