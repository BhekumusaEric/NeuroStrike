"""
Specialized AI Agents Module
Provides specialized AI agents for different aspects of binary analysis
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
from binary_analysis.analyzer import BinaryAnalyzer
from binary_analysis.memory_analyzer import MemoryAnalyzer
from binary_analysis.function_matcher import FunctionMatcher
from binary_analysis.exploit_pathfinder import ExploitPathfinder
from binary_analysis.workflow_automation import WorkflowAutomation

class BaseSpecializedAgent:
    """Base class for specialized AI agents"""

    def __init__(self, name: str, llm=None, config: Dict[str, Any] = None):
        """
        Initialize the base specialized agent

        Args:
            name: Name of the agent
            llm: Language model to use
            config: Configuration dictionary
        """
        self.name = name
        self.logger = get_logger(f"agent_{name}")
        self.config = config or {}

        # Initialize LLM if provided
        if llm:
            self.llm = llm
        else:
            model = self.config.get("model", "gpt-3.5-turbo")
            temperature = self.config.get("temperature", 0.5)
            max_tokens = self.config.get("max_tokens", 1000)
            self.llm = load_llm(model_name=model, temperature=temperature, max_tokens=max_tokens)

        # Knowledge base
        self.knowledge_base = {
            "patterns": [],
            "techniques": [],
            "examples": [],
            "feedback": []
        }

        # Performance metrics
        self.performance = {
            "success_rate": 0.0,
            "iterations": 0,
            "successful_iterations": 0,
            "average_time": 0.0,
            "total_time": 0.0
        }

        self.logger.info(f"Specialized agent '{name}' initialized")

    def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a task

        Args:
            task: Task to process

        Returns:
            Dictionary containing the results
        """
        self.logger.info(f"Processing task: {task.get('type', 'unknown')}")

        # Record start time
        start_time = time.time()

        # Process the task (to be implemented by subclasses)
        result = self._process_task_impl(task)

        # Record end time
        end_time = time.time()
        elapsed_time = end_time - start_time

        # Update performance metrics
        self.performance["iterations"] += 1
        self.performance["total_time"] += elapsed_time
        self.performance["average_time"] = self.performance["total_time"] / self.performance["iterations"]

        if result.get("success", False):
            self.performance["successful_iterations"] += 1

        self.performance["success_rate"] = self.performance["successful_iterations"] / self.performance["iterations"]

        self.logger.info(f"Task processed in {elapsed_time:.2f} seconds")

        return result

    def _process_task_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Implementation of task processing

        Args:
            task: Task to process

        Returns:
            Dictionary containing the results
        """
        # To be implemented by subclasses
        return {"success": False, "error": "Not implemented"}

    def receive_feedback(self, feedback: Dict[str, Any]):
        """
        Receive feedback on a task

        Args:
            feedback: Feedback dictionary
        """
        self.logger.info(f"Received feedback: {feedback.get('type', 'unknown')}")

        # Add feedback to knowledge base
        self.knowledge_base["feedback"].append(feedback)

        # Learn from feedback
        self._learn_from_feedback(feedback)

    def _learn_from_feedback(self, feedback: Dict[str, Any]):
        """
        Learn from feedback

        Args:
            feedback: Feedback dictionary
        """
        # To be implemented by subclasses
        pass

    def add_to_knowledge_base(self, category: str, item: Any):
        """
        Add an item to the knowledge base

        Args:
            category: Category to add to
            item: Item to add
        """
        if category in self.knowledge_base:
            self.knowledge_base[category].append(item)
            self.logger.debug(f"Added item to knowledge base category '{category}'")
        else:
            self.logger.warning(f"Unknown knowledge base category: {category}")

    def get_performance_report(self) -> Dict[str, Any]:
        """
        Get a performance report

        Returns:
            Dictionary containing performance metrics
        """
        return {
            "name": self.name,
            "performance": self.performance
        }

    def process_channel_message(self, channel_name: str, message: Dict[str, Any]):
        """
        Process a message from a communication channel

        Args:
            channel_name: Name of the channel
            message: Message to process
        """
        self.logger.info(f"Processing message from channel '{channel_name}'")

        # Extract message content
        content = message.get("content", {})
        sender = message.get("sender", "unknown")

        # Skip processing our own messages
        if sender == self.name:
            return

        # Process based on message type
        if "knowledge_share" in content:
            self._process_knowledge_share(content["knowledge_share"])
        elif "task_request" in content:
            self._process_task_request(content["task_request"])
        elif "feedback" in content:
            self._process_feedback(content["feedback"])
        elif "result_share" in content:
            self._process_result_share(content["result_share"])

    def _process_knowledge_share(self, knowledge_data: Dict[str, Any]):
        """Process knowledge shared by another agent"""
        if "category" in knowledge_data and "items" in knowledge_data:
            category = knowledge_data["category"]
            items = knowledge_data["items"]

            for item in items:
                self.add_to_knowledge_base(category, item)

            self.logger.info(f"Added {len(items)} items to knowledge base category '{category}'")

    def _process_task_request(self, task_request: Dict[str, Any]):
        """Process a task request from another agent"""
        # Default implementation just logs the request
        self.logger.info(f"Received task request: {task_request.get('type', 'unknown')}")

    def _process_feedback(self, feedback: Dict[str, Any]):
        """Process feedback from another agent"""
        self.receive_feedback(feedback)

    def _process_result_share(self, result_data: Dict[str, Any]):
        """Process results shared by another agent"""
        # Default implementation just logs the results
        self.logger.info(f"Received shared results from another agent")


class BinaryAnalysisAgent(BaseSpecializedAgent):
    """Specialized agent for binary analysis"""

    def __init__(self, llm=None, config: Dict[str, Any] = None):
        """Initialize the binary analysis agent"""
        super().__init__("binary_analysis", llm, config)

        # Initialize binary analyzer
        self.binary_analyzer = BinaryAnalyzer()

        # Add specialized knowledge
        self.add_to_knowledge_base("patterns", "Function prologue/epilogue patterns")
        self.add_to_knowledge_base("patterns", "Common compiler optimizations")
        self.add_to_knowledge_base("patterns", "Standard library function signatures")
        self.add_to_knowledge_base("techniques", "Control flow graph analysis")
        self.add_to_knowledge_base("techniques", "Data flow analysis")
        self.add_to_knowledge_base("techniques", "Binary diffing")

    def _process_task_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process a binary analysis task"""
        task_type = task.get("type", "unknown")
        binary_path = task.get("binary_path", "")

        if not binary_path or not os.path.exists(binary_path):
            return {"success": False, "error": f"Binary file not found: {binary_path}"}

        if task_type == "analyze":
            # Analyze the binary
            analysis_results = self.binary_analyzer.analyze_binary(binary_path)
            return {"success": True, "results": analysis_results}

        elif task_type == "explain_assembly":
            # Extract assembly code
            assembly_code = task.get("assembly_code", "")
            if not assembly_code:
                # Try to extract from the binary
                functions = self.binary_analyzer.analyze_binary(binary_path).get("functions", [])
                if functions:
                    # Get the first function with instructions
                    for function in functions:
                        if function.get("instructions"):
                            assembly_code = "\n".join([instr["instruction"] for instr in function["instructions"]])
                            break

            if not assembly_code:
                return {"success": False, "error": "No assembly code provided or found"}

            # Explain the assembly code
            explanation = self.binary_analyzer.explain_assembly(assembly_code)
            return {"success": True, "explanation": explanation}

        elif task_type == "compare":
            # Compare two binaries
            binary2_path = task.get("binary2_path", "")
            if not binary2_path or not os.path.exists(binary2_path):
                return {"success": False, "error": f"Second binary file not found: {binary2_path}"}

            # Compare the binaries
            comparison_results = self.binary_analyzer.compare_binaries(binary_path, binary2_path)
            return {"success": True, "results": comparison_results}

        else:
            return {"success": False, "error": f"Unknown task type: {task_type}"}

    def _learn_from_feedback(self, feedback: Dict[str, Any]):
        """Learn from feedback"""
        feedback_type = feedback.get("type", "unknown")

        if feedback_type == "assembly_explanation":
            # Learn from assembly explanation feedback
            if feedback.get("correct", False):
                # Add the example to the knowledge base
                self.add_to_knowledge_base("examples", {
                    "assembly_code": feedback.get("assembly_code", ""),
                    "explanation": feedback.get("explanation", ""),
                    "correct": True
                })
            else:
                # Learn from the correction
                self.add_to_knowledge_base("examples", {
                    "assembly_code": feedback.get("assembly_code", ""),
                    "explanation": feedback.get("correct_explanation", ""),
                    "correct": True
                })


class MemoryAnalysisAgent(BaseSpecializedAgent):
    """Specialized agent for memory analysis"""

    def __init__(self, llm=None, config: Dict[str, Any] = None):
        """Initialize the memory analysis agent"""
        super().__init__("memory_analysis", llm, config)

        # Initialize memory analyzer
        self.memory_analyzer = MemoryAnalyzer()

        # Add specialized knowledge
        self.add_to_knowledge_base("patterns", "Common memory structures")
        self.add_to_knowledge_base("patterns", "Encryption patterns")
        self.add_to_knowledge_base("patterns", "Process memory layout")
        self.add_to_knowledge_base("techniques", "Entropy analysis")
        self.add_to_knowledge_base("techniques", "Pattern matching")
        self.add_to_knowledge_base("techniques", "Structure detection")

    def _process_task_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process a memory analysis task"""
        task_type = task.get("type", "unknown")
        dump_path = task.get("dump_path", "")

        if not dump_path or not os.path.exists(dump_path):
            return {"success": False, "error": f"Memory dump file not found: {dump_path}"}

        if task_type == "analyze":
            # Analyze the memory dump
            analysis_results = self.memory_analyzer.analyze_memory_dump(dump_path)
            return {"success": True, "results": analysis_results}

        elif task_type == "analyze_region":
            # Analyze a specific memory region
            offset = task.get("offset", 0)
            size = task.get("size", 1024)

            # Read the region from the dump
            with open(dump_path, "rb") as f:
                f.seek(offset)
                data = f.read(size)

            # Analyze the region
            region_results = self.memory_analyzer.analyze_memory_region(data, offset)
            return {"success": True, "results": region_results}

        else:
            return {"success": False, "error": f"Unknown task type: {task_type}"}


class FunctionMatchingAgent(BaseSpecializedAgent):
    """Specialized agent for function matching"""

    def __init__(self, llm=None, config: Dict[str, Any] = None):
        """Initialize the function matching agent"""
        super().__init__("function_matching", llm, config)

        # Initialize function matcher
        self.function_matcher = FunctionMatcher()

        # Add specialized knowledge
        self.add_to_knowledge_base("patterns", "Function signature patterns")
        self.add_to_knowledge_base("patterns", "Common function prologue/epilogue")
        self.add_to_knowledge_base("patterns", "Standard library function signatures")
        self.add_to_knowledge_base("techniques", "Signature matching")
        self.add_to_knowledge_base("techniques", "Structural matching")
        self.add_to_knowledge_base("techniques", "Semantic matching")

    def _process_task_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process a function matching task"""
        task_type = task.get("type", "unknown")
        binary_path = task.get("binary_path", "")

        if not binary_path or not os.path.exists(binary_path):
            return {"success": False, "error": f"Binary file not found: {binary_path}"}

        if task_type == "extract_functions":
            # Extract functions from the binary
            functions = self.function_matcher.extract_functions(binary_path)
            return {"success": True, "functions": functions}

        elif task_type == "add_to_db":
            # Add functions to the signature database
            version = task.get("version", "unknown")
            count = self.function_matcher.add_to_signature_db(binary_path, version)
            return {"success": True, "count": count}

        elif task_type == "find_similar":
            # Find similar functions
            threshold = task.get("threshold", 0.8)
            similar_functions = self.function_matcher.find_similar_functions(binary_path, threshold)
            return {"success": True, "similar_functions": similar_functions}

        elif task_type == "identify_key_functions":
            # Identify key functions
            function_names = task.get("function_names", [])
            if not function_names:
                return {"success": False, "error": "No function names provided"}

            key_functions = self.function_matcher.identify_key_functions(binary_path, function_names)
            return {"success": True, "key_functions": key_functions}

        else:
            return {"success": False, "error": f"Unknown task type: {task_type}"}


class ExploitPathfindingAgent(BaseSpecializedAgent):
    """Specialized agent for exploit pathfinding"""

    def __init__(self, llm=None, config: Dict[str, Any] = None):
        """Initialize the exploit pathfinding agent"""
        super().__init__("exploit_pathfinding", llm, config)

        # Initialize exploit pathfinder
        self.exploit_pathfinder = ExploitPathfinder()

        # Add specialized knowledge
        self.add_to_knowledge_base("patterns", "Buffer overflow patterns")
        self.add_to_knowledge_base("patterns", "Format string vulnerability patterns")
        self.add_to_knowledge_base("patterns", "Integer overflow patterns")
        self.add_to_knowledge_base("techniques", "Fuzzing")
        self.add_to_knowledge_base("techniques", "Symbolic execution")
        self.add_to_knowledge_base("techniques", "Taint analysis")

    def _process_task_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process an exploit pathfinding task"""
        task_type = task.get("type", "unknown")
        binary_path = task.get("binary_path", "")

        if not binary_path or not os.path.exists(binary_path):
            return {"success": False, "error": f"Binary file not found: {binary_path}"}

        if task_type == "find_vulnerabilities":
            # Find potential vulnerabilities
            vulnerabilities = self.exploit_pathfinder.find_potential_vulnerabilities(binary_path)
            return {"success": True, "vulnerabilities": vulnerabilities}

        elif task_type == "generate_fuzzing_harness":
            # Generate a fuzzing harness
            function_name = task.get("function_name", "")
            if not function_name:
                return {"success": False, "error": "No function name provided"}

            harness = self.exploit_pathfinder.generate_fuzzing_harness(binary_path, function_name)
            return {"success": True, "harness": harness}

        elif task_type == "suggest_exploit_path":
            # Suggest an exploit path
            vulnerability = task.get("vulnerability", {})
            if not vulnerability:
                return {"success": False, "error": "No vulnerability provided"}

            exploit_path = self.exploit_pathfinder.suggest_exploit_path(binary_path, vulnerability)
            return {"success": True, "exploit_path": exploit_path}

        else:
            return {"success": False, "error": f"Unknown task type: {task_type}"}


class WorkflowAutomationAgent(BaseSpecializedAgent):
    """Specialized agent for workflow automation"""

    def __init__(self, llm=None, config: Dict[str, Any] = None):
        """Initialize the workflow automation agent"""
        super().__init__("workflow_automation", llm, config)

        # Initialize workflow automation
        self.workflow_automation = WorkflowAutomation()

        # Add specialized knowledge
        self.add_to_knowledge_base("patterns", "Common binary structures")
        self.add_to_knowledge_base("patterns", "Malware patterns")
        self.add_to_knowledge_base("patterns", "Security-relevant features")
        self.add_to_knowledge_base("techniques", "IDA Pro scripting")
        self.add_to_knowledge_base("techniques", "Ghidra scripting")
        self.add_to_knowledge_base("techniques", "YARA rule generation")

    def _process_task_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process a workflow automation task"""
        task_type = task.get("type", "unknown")
        binary_path = task.get("binary_path", "")

        if not binary_path or not os.path.exists(binary_path):
            return {"success": False, "error": f"Binary file not found: {binary_path}"}

        if task_type == "explain_structure":
            # Explain the binary structure
            explanation = self.workflow_automation.explain_binary_structure(binary_path)
            return {"success": True, "explanation": explanation}

        elif task_type == "generate_ida_script":
            # Generate an IDA Pro script
            task_description = task.get("task_description", "")
            if not task_description:
                return {"success": False, "error": "No task description provided"}

            script = self.workflow_automation.generate_ida_script(binary_path, task_description)
            return {"success": True, "script": script}

        elif task_type == "generate_ghidra_script":
            # Generate a Ghidra script
            task_description = task.get("task_description", "")
            if not task_description:
                return {"success": False, "error": "No task description provided"}

            script = self.workflow_automation.generate_ghidra_script(binary_path, task_description)
            return {"success": True, "script": script}

        elif task_type == "generate_frida_script":
            # Generate a Frida script
            task_description = task.get("task_description", "")
            if not task_description:
                return {"success": False, "error": "No task description provided"}

            script = self.workflow_automation.generate_frida_script(binary_path, task_description)
            return {"success": True, "script": script}

        elif task_type == "generate_yara_rule":
            # Generate a YARA rule
            description = task.get("description", "")
            if not description:
                return {"success": False, "error": "No description provided"}

            rule = self.workflow_automation.generate_yara_rule(binary_path, description)
            return {"success": True, "rule": rule}

        else:
            return {"success": False, "error": f"Unknown task type: {task_type}"}
