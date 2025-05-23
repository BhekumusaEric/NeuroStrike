#!/usr/bin/env python3
"""
Red Agent Training Script
Trains the Red Agent to become exceptionally skilled at binary analysis
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import Dict, List, Any, Optional

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.logger import setup_logger, get_logger
from agents.red_agent import RedAgent
from training.coordinator import TrainingCoordinator
from training.specialized_agents import (
    BinaryAnalysisAgent,
    MemoryAnalysisAgent,
    FunctionMatchingAgent,
    ExploitPathfindingAgent,
    WorkflowAutomationAgent
)
from training.scenario_generator import ScenarioGenerator
from training.evaluator import Evaluator

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Red Agent Training Script")

    parser.add_argument("--config", type=str, default="config/training.json",
                        help="Path to training configuration file")

    parser.add_argument("--phases", type=str, default="basic,intermediate,advanced,expert",
                        help="Comma-separated list of training phases to run")

    parser.add_argument("--scenarios", type=int, default=5,
                        help="Number of scenarios per phase")

    parser.add_argument("--output", type=str, default="training_results.json",
                        help="Path to output file for training results")

    parser.add_argument("--verbose", "-v", action="count", default=0,
                        help="Increase verbosity (can be used multiple times)")

    return parser.parse_args()

def initialize_specialized_agents() -> Dict[str, Any]:
    """Initialize specialized AI agents"""
    logger = get_logger("train_red_agent")
    logger.info("Initializing specialized AI agents")

    agents = {
        "binary_analysis": BinaryAnalysisAgent(),
        "memory_analysis": MemoryAnalysisAgent(),
        "function_matching": FunctionMatchingAgent(),
        "exploit_pathfinding": ExploitPathfindingAgent(),
        "workflow_automation": WorkflowAutomationAgent()
    }

    logger.info(f"Initialized {len(agents)} specialized AI agents")

    return agents

def train_red_agent(config_path: str, phases: List[str], scenarios_per_phase: int, output_path: str):
    """
    Train the Red Agent to become exceptionally skilled at binary analysis

    Args:
        config_path: Path to training configuration file
        phases: List of training phases to run
        scenarios_per_phase: Number of scenarios per phase
        output_path: Path to output file for training results
    """
    logger = get_logger("train_red_agent")
    logger.info("Starting Red Agent training")

    # Initialize training coordinator
    coordinator = TrainingCoordinator(config_path)

    # Initialize scenario generator
    scenario_generator = ScenarioGenerator(config_path)

    # Initialize evaluator
    evaluator = Evaluator(config_path)

    # Initialize Red Agent
    red_config = {
        "safe_mode": True,
        "scan_only": False,
        "verbose": True
    }
    red_agent = RedAgent(red_config)

    # Initialize specialized agents
    specialized_agents = initialize_specialized_agents()

    # Set up communication channels
    for agent_name in specialized_agents:
        coordinator.subscribe_agent_to_channel(agent_name, "binary_analysis")
        coordinator.subscribe_agent_to_channel(agent_name, "vulnerability_detection")

    # Training results
    training_results = {
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "phases": {},
        "overall_metrics": {},
        "end_time": None
    }

    # Run training phases
    for phase in phases:
        logger.info(f"Starting training phase: {phase}")

        phase_results = {
            "scenarios": [],
            "metrics": {}
        }

        # Generate scenarios for this phase
        scenarios = scenario_generator.generate_scenarios(phase, scenarios_per_phase)

        # Run each scenario
        for i, scenario in enumerate(scenarios):
            logger.info(f"Running scenario {i+1}/{len(scenarios)}: {scenario.get('type', 'unknown')}")

            # Process the scenario with the appropriate specialized agent
            scenario_type = scenario.get("type", "unknown")
            if scenario_type in specialized_agents:
                # Process the scenario
                result = specialized_agents[scenario_type].process_task(scenario)

                # Evaluate the result
                evaluation = evaluator.evaluate_task_result(scenario, result)

                # Generate feedback
                feedback = evaluator.generate_feedback(scenario, result, evaluation)

                # Provide feedback to the specialized agent
                specialized_agents[scenario_type].receive_feedback(feedback)

                # Transfer knowledge to the Red Agent
                _transfer_knowledge_to_red_agent(red_agent, specialized_agents[scenario_type], scenario, result, evaluation, feedback)

                # Record scenario results
                phase_results["scenarios"].append({
                    "scenario": scenario,
                    "result": result,
                    "evaluation": evaluation,
                    "feedback": feedback
                })
            else:
                logger.warning(f"Unknown scenario type: {scenario_type}")

        # Calculate phase metrics
        phase_metrics = _calculate_phase_metrics(phase_results["scenarios"])
        phase_results["metrics"] = phase_metrics

        # Record phase results
        training_results["phases"][phase] = phase_results

        logger.info(f"Completed training phase: {phase}")
        logger.info(f"Phase metrics: {json.dumps(phase_metrics, indent=2)}")

    # Calculate overall metrics
    overall_metrics = _calculate_overall_metrics(training_results["phases"])
    training_results["overall_metrics"] = overall_metrics

    # Record end time
    training_results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # Save training results
    with open(output_path, "w") as f:
        json.dump(training_results, f, indent=2)

    logger.info(f"Training results saved to: {output_path}")
    logger.info("Red Agent training completed")
    logger.info(f"Overall metrics: {json.dumps(overall_metrics, indent=2)}")

def _transfer_knowledge_to_red_agent(red_agent: RedAgent, specialized_agent: Any, scenario: Dict[str, Any], result: Dict[str, Any], evaluation: Dict[str, Any], feedback: Dict[str, Any]):
    """
    Transfer knowledge from a specialized agent to the Red Agent

    Args:
        red_agent: Red Agent instance
        specialized_agent: Specialized agent instance
        scenario: Scenario dictionary
        result: Result dictionary
        evaluation: Evaluation dictionary
        feedback: Feedback dictionary
    """
    logger = get_logger("train_red_agent")
    logger.info(f"Transferring knowledge from {specialized_agent.name} to Red Agent")

    # Get the specialized agent's knowledge base
    knowledge_base = specialized_agent.knowledge_base

    # Transfer knowledge based on the specialized agent type
    if specialized_agent.name == "binary_analysis":
        # Transfer binary analysis knowledge
        if hasattr(red_agent, "binary_analyzer"):
            # Transfer patterns and techniques
            for pattern in knowledge_base.get("patterns", []):
                if hasattr(red_agent.binary_analyzer, "add_pattern"):
                    red_agent.binary_analyzer.add_pattern(pattern)
                else:
                    logger.warning("Red Agent's binary analyzer does not have add_pattern method")

            # Transfer examples if available
            for example in knowledge_base.get("examples", []):
                if "assembly_code" in example and "explanation" in example:
                    if hasattr(red_agent.binary_analyzer, "add_assembly_example"):
                        red_agent.binary_analyzer.add_assembly_example(
                            example["assembly_code"],
                            example["explanation"]
                        )
                    else:
                        logger.warning("Red Agent's binary analyzer does not have add_assembly_example method")

    elif specialized_agent.name == "memory_analysis":
        # Transfer memory analysis knowledge
        if hasattr(red_agent, "memory_analyzer"):
            # Transfer patterns
            for pattern in knowledge_base.get("patterns", []):
                if hasattr(red_agent.memory_analyzer, "add_pattern"):
                    red_agent.memory_analyzer.add_pattern(pattern)
                else:
                    logger.warning("Red Agent's memory analyzer does not have add_pattern method")

    elif specialized_agent.name == "function_matching":
        # Transfer function matching knowledge
        if hasattr(red_agent, "function_matcher"):
            # Transfer function signatures
            for example in knowledge_base.get("examples", []):
                if "function_signature" in example:
                    if hasattr(red_agent.function_matcher, "add_signature"):
                        red_agent.function_matcher.add_signature(
                            example["function_signature"],
                            example.get("function_name", "unknown"),
                            example.get("version", "unknown")
                        )
                    else:
                        logger.warning("Red Agent's function matcher does not have add_signature method")

    elif specialized_agent.name == "exploit_pathfinding":
        # Transfer exploit pathfinding knowledge
        if hasattr(red_agent, "exploit_pathfinder"):
            # Transfer vulnerability patterns
            for pattern in knowledge_base.get("patterns", []):
                if hasattr(red_agent.exploit_pathfinder, "add_vulnerability_pattern"):
                    red_agent.exploit_pathfinder.add_vulnerability_pattern(pattern)
                else:
                    logger.warning("Red Agent's exploit pathfinder does not have add_vulnerability_pattern method")

            # Transfer exploit techniques
            for technique in knowledge_base.get("techniques", []):
                if hasattr(red_agent.exploit_pathfinder, "add_exploit_technique"):
                    red_agent.exploit_pathfinder.add_exploit_technique(technique)
                else:
                    logger.warning("Red Agent's exploit pathfinder does not have add_exploit_technique method")

    elif specialized_agent.name == "workflow_automation":
        # Transfer workflow automation knowledge
        if hasattr(red_agent, "workflow_automation"):
            # Transfer automation scripts
            for example in knowledge_base.get("examples", []):
                if "script_type" in example and "script" in example:
                    if hasattr(red_agent.workflow_automation, "add_script_template"):
                        red_agent.workflow_automation.add_script_template(
                            example["script_type"],
                            example["script"]
                        )
                    else:
                        logger.warning("Red Agent's workflow automation does not have add_script_template method")

    # Log the knowledge transfer
    logger.info(f"Knowledge transfer from {specialized_agent.name} to Red Agent completed")

def _calculate_phase_metrics(scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate metrics for a training phase

    Args:
        scenarios: List of scenario results

    Returns:
        Dictionary containing phase metrics
    """
    # Calculate average score
    total_score = 0.0
    for scenario in scenarios:
        total_score += scenario.get("evaluation", {}).get("score", 0.0)

    average_score = total_score / len(scenarios) if scenarios else 0.0

    # Calculate success rate
    successful_scenarios = [s for s in scenarios if s.get("evaluation", {}).get("success", False)]
    success_rate = len(successful_scenarios) / len(scenarios) if scenarios else 0.0

    return {
        "average_score": average_score,
        "success_rate": success_rate,
        "total_scenarios": len(scenarios),
        "successful_scenarios": len(successful_scenarios)
    }

def _calculate_overall_metrics(phases: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate overall metrics for the training

    Args:
        phases: Dictionary mapping phase names to phase results

    Returns:
        Dictionary containing overall metrics
    """
    # Calculate average score across all phases
    total_score = 0.0
    total_scenarios = 0
    successful_scenarios = 0

    for phase_name, phase_results in phases.items():
        phase_metrics = phase_results.get("metrics", {})
        total_score += phase_metrics.get("average_score", 0.0) * phase_metrics.get("total_scenarios", 0)
        total_scenarios += phase_metrics.get("total_scenarios", 0)
        successful_scenarios += phase_metrics.get("successful_scenarios", 0)

    average_score = total_score / total_scenarios if total_scenarios > 0 else 0.0
    success_rate = successful_scenarios / total_scenarios if total_scenarios > 0 else 0.0

    return {
        "average_score": average_score,
        "success_rate": success_rate,
        "total_scenarios": total_scenarios,
        "successful_scenarios": successful_scenarios
    }

def main():
    """Main entry point"""
    # Parse command line arguments
    args = parse_arguments()

    # Set up logging
    log_level = "DEBUG" if args.verbose > 0 else "INFO"
    setup_logger("train_red_agent", log_level)

    # Parse phases
    phases = args.phases.split(",")

    # Train the Red Agent
    train_red_agent(args.config, phases, args.scenarios, args.output)

if __name__ == "__main__":
    main()
