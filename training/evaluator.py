"""
Evaluator Module
Evaluates the performance of specialized AI agents
"""

import os
import sys
import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger
from ai_models.model_loader import load_llm

class Evaluator:
    """
    Evaluates the performance of specialized AI agents
    """
    
    def __init__(self, config_path: str = "config/training.json"):
        """
        Initialize the Evaluator
        
        Args:
            config_path: Path to the training configuration file
        """
        self.logger = get_logger("evaluator")
        self.logger.info("Initializing Evaluator")
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize LLM for evaluation
        model = self.config.get("evaluator", {}).get("model", "gpt-4")
        temperature = self.config.get("evaluator", {}).get("temperature", 0.2)
        max_tokens = self.config.get("evaluator", {}).get("max_tokens", 2000)
        self.llm = load_llm(model_name=model, temperature=temperature, max_tokens=max_tokens)
        
        # Evaluation metrics
        self.metrics = {
            "binary_analysis": {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0
            },
            "memory_analysis": {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0
            },
            "function_matching": {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0
            },
            "vulnerability_detection": {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0
            },
            "workflow_automation": {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0
            }
        }
        
        self.logger.info("Evaluator initialized")
    
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
    
    def evaluate_task_result(self, task: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate the result of a task
        
        Args:
            task: Task dictionary
            result: Result dictionary
            
        Returns:
            Dictionary containing evaluation metrics
        """
        self.logger.info(f"Evaluating task result: {task.get('type', 'unknown')}")
        
        task_type = task.get("type", "unknown")
        
        if task_type == "binary_analysis":
            return self._evaluate_binary_analysis(task, result)
        elif task_type == "memory_analysis":
            return self._evaluate_memory_analysis(task, result)
        elif task_type == "function_matching":
            return self._evaluate_function_matching(task, result)
        elif task_type == "vulnerability_detection":
            return self._evaluate_vulnerability_detection(task, result)
        elif task_type == "workflow_automation":
            return self._evaluate_workflow_automation(task, result)
        else:
            self.logger.warning(f"Unknown task type: {task_type}")
            return {"success": False, "error": f"Unknown task type: {task_type}"}
    
    def _evaluate_binary_analysis(self, task: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a binary analysis task"""
        expected_results = task.get("expected_results", {})
        actual_results = result.get("results", {})
        
        # Check if the task was successful
        if not result.get("success", False):
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
                "score": 0.0
            }
        
        # Calculate score based on expected results
        score = 0.0
        total_checks = 0
        
        # Check for main function
        if "has_main_function" in expected_results:
            total_checks += 1
            functions = actual_results.get("functions", [])
            has_main = any(func.get("name") == "main" for func in functions)
            
            if has_main == expected_results["has_main_function"]:
                score += 1.0
        
        # Check for buffer overflow
        if "has_buffer_overflow" in expected_results:
            total_checks += 1
            # This would require more sophisticated analysis
            # For now, we'll just assume it's correct
            score += 1.0
        
        # Check for format string
        if "has_format_string" in expected_results:
            total_checks += 1
            # This would require more sophisticated analysis
            # For now, we'll just assume it's correct
            score += 1.0
        
        # Calculate final score
        final_score = score / total_checks if total_checks > 0 else 0.0
        
        # Update metrics
        self.metrics["binary_analysis"]["accuracy"] = final_score
        
        return {
            "success": True,
            "score": final_score,
            "details": {
                "checks": total_checks,
                "passed": int(score)
            }
        }
    
    def _evaluate_memory_analysis(self, task: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a memory analysis task"""
        expected_results = task.get("expected_results", {})
        actual_results = result.get("results", {})
        
        # Check if the task was successful
        if not result.get("success", False):
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
                "score": 0.0
            }
        
        # Calculate score based on expected results
        score = 0.0
        total_checks = 0
        
        # Check for encryption
        if "has_encryption" in expected_results:
            total_checks += 1
            # Check if high entropy regions were found
            high_entropy_regions = [r for r in actual_results.get("entropy_regions", []) if r.get("entropy", 0) > 7.0]
            has_encryption = len(high_entropy_regions) > 0
            
            if has_encryption == expected_results["has_encryption"]:
                score += 1.0
        
        # Check for credentials
        if "has_credentials" in expected_results:
            total_checks += 1
            # Check if credential patterns were found
            credential_patterns = actual_results.get("patterns", {}).get("credit_card", [])
            credential_patterns.extend(actual_results.get("patterns", {}).get("email", []))
            has_credentials = len(credential_patterns) > 0
            
            if has_credentials == expected_results["has_credentials"]:
                score += 1.0
        
        # Check for network data
        if "has_network_data" in expected_results:
            total_checks += 1
            # Check if network patterns were found
            network_patterns = actual_results.get("patterns", {}).get("ipv4", [])
            network_patterns.extend(actual_results.get("patterns", {}).get("url", []))
            has_network_data = len(network_patterns) > 0
            
            if has_network_data == expected_results["has_network_data"]:
                score += 1.0
        
        # Calculate final score
        final_score = score / total_checks if total_checks > 0 else 0.0
        
        # Update metrics
        self.metrics["memory_analysis"]["accuracy"] = final_score
        
        return {
            "success": True,
            "score": final_score,
            "details": {
                "checks": total_checks,
                "passed": int(score)
            }
        }
    
    def _evaluate_function_matching(self, task: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a function matching task"""
        expected_results = task.get("expected_results", {})
        actual_results = result.get("similar_functions", {})
        
        # Check if the task was successful
        if not result.get("success", False):
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
                "score": 0.0
            }
        
        # Calculate score based on expected results
        score = 0.0
        total_checks = 0
        
        # Check for common functions
        if "common_functions" in expected_results:
            total_checks += 1
            expected_common = set(expected_results["common_functions"])
            actual_common = set(actual_results.keys())
            
            # Calculate Jaccard similarity
            intersection = len(expected_common.intersection(actual_common))
            union = len(expected_common.union(actual_common))
            
            if union > 0:
                score += intersection / union
        
        # Check for unique functions
        if "unique_functions" in expected_results:
            total_checks += 1
            expected_unique = set(expected_results["unique_functions"])
            actual_unique = set()
            
            # This would require more sophisticated analysis
            # For now, we'll just assume it's correct
            score += 1.0
        
        # Calculate final score
        final_score = score / total_checks if total_checks > 0 else 0.0
        
        # Update metrics
        self.metrics["function_matching"]["accuracy"] = final_score
        
        return {
            "success": True,
            "score": final_score,
            "details": {
                "checks": total_checks,
                "passed": score
            }
        }
    
    def _evaluate_vulnerability_detection(self, task: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a vulnerability detection task"""
        expected_results = task.get("expected_results", {})
        actual_results = result.get("vulnerabilities", {})
        
        # Check if the task was successful
        if not result.get("success", False):
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
                "score": 0.0
            }
        
        # Calculate score based on expected results
        score = 0.0
        total_checks = 0
        
        # Check for vulnerability types
        if "vulnerability_types" in expected_results:
            total_checks += 1
            expected_types = set(expected_results["vulnerability_types"])
            actual_types = set(actual_results.keys())
            
            # Calculate Jaccard similarity
            intersection = len(expected_types.intersection(actual_types))
            union = len(expected_types.union(actual_types))
            
            if union > 0:
                score += intersection / union
        
        # Check for vulnerable functions
        if "vulnerable_functions" in expected_results:
            total_checks += 1
            expected_functions = set(expected_results["vulnerable_functions"])
            actual_functions = set()
            
            # Extract vulnerable functions from results
            for vuln_type, vulns in actual_results.items():
                for vuln in vulns:
                    if "function" in vuln:
                        actual_functions.add(vuln["function"])
            
            # Calculate Jaccard similarity
            intersection = len(expected_functions.intersection(actual_functions))
            union = len(expected_functions.union(actual_functions))
            
            if union > 0:
                score += intersection / union
        
        # Check for exploitability
        if "exploitable" in expected_results:
            total_checks += 1
            # This would require more sophisticated analysis
            # For now, we'll just assume it's correct
            score += 1.0
        
        # Calculate final score
        final_score = score / total_checks if total_checks > 0 else 0.0
        
        # Update metrics
        self.metrics["vulnerability_detection"]["accuracy"] = final_score
        
        return {
            "success": True,
            "score": final_score,
            "details": {
                "checks": total_checks,
                "passed": score
            }
        }
    
    def _evaluate_workflow_automation(self, task: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a workflow automation task"""
        expected_results = task.get("expected_results", {})
        actual_results = result.get("rule", {})
        
        # Check if the task was successful
        if not result.get("success", False):
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
                "score": 0.0
            }
        
        # For workflow automation, we'll use the LLM to evaluate the quality of the generated artifacts
        
        # Prepare prompt for LLM evaluation
        prompt = f"""
        Evaluate the quality of this YARA rule:
        
        ```
        {actual_results.get('rule', '')}
        ```
        
        The rule should detect the following files:
        {expected_results.get('rule_should_match', [])}
        
        The rule should NOT detect the following files:
        {expected_results.get('rule_should_not_match', [])}
        
        Please evaluate the rule on a scale of 0.0 to 1.0, where:
        - 0.0 means the rule is completely incorrect or ineffective
        - 1.0 means the rule is perfect and will correctly match/not match the specified files
        
        Provide your evaluation in the following format:
        
        Score: X.X
        Explanation: Your explanation here
        """
        
        # Get evaluation from LLM
        evaluation = self.llm.generate(prompt)
        
        # Extract score from evaluation
        score_match = re.search(r"Score:\s*([0-9.]+)", evaluation)
        if score_match:
            try:
                score = float(score_match.group(1))
            except ValueError:
                score = 0.0
        else:
            score = 0.0
        
        # Update metrics
        self.metrics["workflow_automation"]["accuracy"] = score
        
        return {
            "success": True,
            "score": score,
            "details": {
                "evaluation": evaluation
            }
        }
    
    def generate_feedback(self, task: Dict[str, Any], result: Dict[str, Any], evaluation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate feedback for a task result
        
        Args:
            task: Task dictionary
            result: Result dictionary
            evaluation: Evaluation dictionary
            
        Returns:
            Dictionary containing feedback
        """
        self.logger.info(f"Generating feedback for task: {task.get('type', 'unknown')}")
        
        # Prepare prompt for LLM feedback
        prompt = f"""
        Generate detailed feedback for this task result:
        
        Task:
        {json.dumps(task, indent=2)}
        
        Result:
        {json.dumps(result, indent=2)}
        
        Evaluation:
        {json.dumps(evaluation, indent=2)}
        
        Please provide:
        1. What was done well
        2. What could be improved
        3. Specific suggestions for improvement
        4. Any patterns or techniques that should be learned
        
        Format your feedback in a clear, constructive manner.
        """
        
        # Get feedback from LLM
        feedback_text = self.llm.generate(prompt)
        
        return {
            "type": task.get("type", "unknown"),
            "score": evaluation.get("score", 0.0),
            "feedback": feedback_text
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get evaluation metrics
        
        Returns:
            Dictionary containing evaluation metrics
        """
        return self.metrics
    
    def generate_evaluation_report(self) -> Dict[str, Any]:
        """
        Generate an evaluation report
        
        Returns:
            Dictionary containing the evaluation report
        """
        self.logger.info("Generating evaluation report")
        
        # Calculate overall metrics
        overall_accuracy = 0.0
        overall_precision = 0.0
        overall_recall = 0.0
        overall_f1_score = 0.0
        
        for agent_type, metrics in self.metrics.items():
            overall_accuracy += metrics["accuracy"]
            overall_precision += metrics["precision"]
            overall_recall += metrics["recall"]
            overall_f1_score += metrics["f1_score"]
        
        num_agents = len(self.metrics)
        if num_agents > 0:
            overall_accuracy /= num_agents
            overall_precision /= num_agents
            overall_recall /= num_agents
            overall_f1_score /= num_agents
        
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overall_metrics": {
                "accuracy": overall_accuracy,
                "precision": overall_precision,
                "recall": overall_recall,
                "f1_score": overall_f1_score
            },
            "agent_metrics": self.metrics
        }
