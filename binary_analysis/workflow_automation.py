"""
Workflow Automation Module
Provides tools for security workflow automation
"""

import os
import re
import subprocess
import tempfile
import json
from typing import Dict, List, Any, Optional, Tuple, Union, Set

from utils.logger import get_logger
from ai_models.model_loader import load_llm

class WorkflowAutomation:
    """
    Workflow Automation class
    Provides tools for automating security workflows
    """

    def __init__(self):
        """Initialize the Workflow Automation"""
        self.logger = get_logger("workflow_automation")
        self.llm = load_llm()
        self.logger.info("Workflow Automation initialized")

    def explain_binary_structure(self, binary_path: str) -> str:
        """
        Explain the structure of a binary file

        Args:
            binary_path: Path to the binary file

        Returns:
            Explanation of the binary structure
        """
        self.logger.info(f"Explaining binary structure: {binary_path}")

        # Get basic file information
        file_info = self._get_file_info(binary_path)

        # Get section information
        sections = self._get_sections(binary_path)

        # Get symbol information
        symbols = self._get_symbols(binary_path)

        # Generate explanation using LLM
        prompt = f"""
        Please explain the structure of this binary file:

        File information:
        {json.dumps(file_info, indent=2)}

        Sections:
        {json.dumps(sections, indent=2)}

        Symbols (sample):
        {json.dumps(symbols[:20], indent=2)}

        Please provide:
        1. A high-level overview of the binary
        2. Explanation of key sections and their purpose
        3. Analysis of the binary's architecture and format
        4. Identification of any interesting or security-relevant features
        """

        explanation = self.llm.generate(prompt)
        return explanation

    def _get_file_info(self, binary_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        info = {
            "path": binary_path,
            "size": os.path.getsize(binary_path),
            "type": "unknown"
        }

        try:
            # Use file command to determine file type
            result = subprocess.run(["file", binary_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")
            info["type"] = output.split(":", 1)[1].strip() if ":" in output else output.strip()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting file info: {e}")
            info["error"] = str(e)

        return info

    def _get_sections(self, binary_path: str) -> List[Dict[str, Any]]:
        """Get section information"""
        sections = []

        try:
            # Use readelf to get section information
            result = subprocess.run(["readelf", "-S", binary_path],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")

            # Parse readelf output to extract sections
            in_section_headers = False
            for line in output.split("\n"):
                if "Section Headers:" in line:
                    in_section_headers = True
                    continue
                if in_section_headers and line.strip() and "[" in line and "]" in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        section_name = parts[1].strip()
                        section_type = parts[2].strip()
                        section_addr = parts[3].strip()
                        section_offset = parts[4].strip()
                        section_size = parts[5].strip()
                        sections.append({
                            "name": section_name,
                            "type": section_type,
                            "address": section_addr,
                            "offset": section_offset,
                            "size": section_size
                        })
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting section information: {e}")

        return sections

    def _get_symbols(self, binary_path: str) -> List[Dict[str, Any]]:
        """Get symbol information"""
        symbols = []

        try:
            # Use nm to get symbol information
            result = subprocess.run(["nm", "-C", binary_path],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")

            # Parse nm output to extract symbols
            for line in output.split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        address = parts[0]
                        symbol_type = parts[1]
                        name = ' '.join(parts[2:])
                        symbols.append({
                            "address": address,
                            "type": symbol_type,
                            "name": name
                        })
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting symbol information: {e}")

        return symbols

    def generate_ida_script(self, binary_path: str, task: str) -> Dict[str, Any]:
        """
        Generate an IDA Pro script for a specific task

        Args:
            binary_path: Path to the binary file
            task: Description of the task

        Returns:
            Dictionary containing the generated script
        """
        self.logger.info(f"Generating IDA Pro script for task: {task}")

        # Get basic file information
        file_info = self._get_file_info(binary_path)

        # Generate script using LLM
        prompt = f"""
        I need an IDA Pro Python script for the following task:

        Task: {task}
        Binary: {os.path.basename(binary_path)}
        Binary type: {file_info.get('type', 'unknown')}

        Please generate a complete, working IDA Pro Python script that:
        1. Accomplishes the specified task
        2. Includes necessary imports and error handling
        3. Is well-commented and easy to understand
        4. Can be run from within IDA Pro

        The script should be compatible with IDAPython and recent versions of IDA Pro.
        """

        script = self.llm.generate(prompt)

        # Extract Python code from the response
        python_code = ""
        in_code_block = False
        for line in script.split("\n"):
            if line.strip() == "```python":
                in_code_block = True
                continue
            elif line.strip() == "```" and in_code_block:
                in_code_block = False
                continue

            if in_code_block:
                python_code += line + "\n"

        # If no code block was found, use the entire response
        if not python_code:
            python_code = script

        # Save the script to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(python_code.encode())
            script_path = f.name

        return {
            "task": task,
            "script": python_code,
            "script_path": script_path,
            "full_response": script
        }

    def generate_ghidra_script(self, binary_path: str, task: str) -> Dict[str, Any]:
        """
        Generate a Ghidra script for a specific task

        Args:
            binary_path: Path to the binary file
            task: Description of the task

        Returns:
            Dictionary containing the generated script
        """
        self.logger.info(f"Generating Ghidra script for task: {task}")

        # Get basic file information
        file_info = self._get_file_info(binary_path)

        # Generate script using LLM
        prompt = f"""
        I need a Ghidra script for the following task:

        Task: {task}
        Binary: {os.path.basename(binary_path)}
        Binary type: {file_info.get('type', 'unknown')}

        Please generate a complete, working Ghidra script that:
        1. Accomplishes the specified task
        2. Includes necessary imports and error handling
        3. Is well-commented and easy to understand
        4. Can be run from within Ghidra

        The script can be either Java or Python (Jython), whichever is more appropriate for the task.
        """

        script = self.llm.generate(prompt)

        # Extract code from the response
        code = ""
        in_code_block = False
        language = "java"  # Default

        for line in script.split("\n"):
            if line.strip() == "```java":
                in_code_block = True
                language = "java"
                continue
            elif line.strip() == "```python" or line.strip() == "```jython":
                in_code_block = True
                language = "python"
                continue
            elif line.strip() == "```" and in_code_block:
                in_code_block = False
                continue

            if in_code_block:
                code += line + "\n"

        # If no code block was found, use the entire response
        if not code:
            code = script
            # Try to guess the language
            if "import ghidra" in code or "import jython" in code:
                language = "python"
            else:
                language = "java"

        # Save the script to a temporary file
        extension = ".java" if language == "java" else ".py"
        with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as f:
            f.write(code.encode())
            script_path = f.name

        return {
            "task": task,
            "script": code,
            "language": language,
            "script_path": script_path,
            "full_response": script
        }

    def generate_frida_script(self, binary_path: str, task: str) -> Dict[str, Any]:
        """
        Generate a Frida script for a specific task

        Args:
            binary_path: Path to the binary file
            task: Description of the task

        Returns:
            Dictionary containing the generated script
        """
        self.logger.info(f"Generating Frida script for task: {task}")

        # Get basic file information
        file_info = self._get_file_info(binary_path)

        # Generate script using LLM
        prompt = f"""
        I need a Frida script for the following task:

        Task: {task}
        Binary: {os.path.basename(binary_path)}
        Binary type: {file_info.get('type', 'unknown')}

        Please generate a complete, working Frida script that:
        1. Accomplishes the specified task
        2. Includes necessary error handling
        3. Is well-commented and easy to understand
        4. Can be run with the Frida CLI or Python bindings

        Also include example commands for running the script with Frida.
        """

        script = self.llm.generate(prompt)

        # Extract JavaScript code from the response
        js_code = ""
        in_code_block = False
        for line in script.split("\n"):
            if line.strip() == "```javascript" or line.strip() == "```js":
                in_code_block = True
                continue
            elif line.strip() == "```" and in_code_block:
                in_code_block = False
                continue

            if in_code_block:
                js_code += line + "\n"

        # If no code block was found, use the entire response
        if not js_code:
            js_code = script

        # Save the script to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False) as f:
            f.write(js_code.encode())
            script_path = f.name

        return {
            "task": task,
            "script": js_code,
            "script_path": script_path,
            "full_response": script
        }

    def generate_yara_rule(self, binary_path: str, description: str) -> Dict[str, Any]:
        """
        Generate a YARA rule for a binary

        Args:
            binary_path: Path to the binary file
            description: Description of what to detect

        Returns:
            Dictionary containing the generated YARA rule
        """
        self.logger.info(f"Generating YARA rule for: {description}")

        # Extract strings from the binary
        strings = self._extract_strings(binary_path)

        # Get basic file information
        file_info = self._get_file_info(binary_path)

        # Generate YARA rule using LLM
        prompt = f"""
        I need a YARA rule to detect the following:

        Description: {description}
        Binary: {os.path.basename(binary_path)}
        Binary type: {file_info.get('type', 'unknown')}

        Here are some strings from the binary that might be useful:
        {json.dumps(strings[:100], indent=2)}

        Please generate a complete, working YARA rule that:
        1. Detects the described pattern or behavior
        2. Includes appropriate metadata
        3. Uses a combination of strings and conditions
        4. Minimizes false positives

        The rule should follow best practices for YARA rule writing.
        """

        yara_rule = self.llm.generate(prompt)

        # Extract YARA rule from the response
        rule_text = ""
        in_code_block = False
        for line in yara_rule.split("\n"):
            if line.strip() == "```yara" or line.strip() == "```":
                in_code_block = not in_code_block
                continue

            if in_code_block or not rule_text:
                rule_text += line + "\n"

        # Save the rule to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False) as f:
            f.write(rule_text.encode())
            rule_path = f.name

        return {
            "description": description,
            "rule": rule_text,
            "rule_path": rule_path,
            "full_response": yara_rule
        }

    def _extract_strings(self, binary_path: str) -> List[str]:
        """Extract strings from a binary file"""
        strings = []

        try:
            # Use strings command to extract strings
            result = subprocess.run(["strings", binary_path],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")
            strings = [s.strip() for s in output.split("\n") if s.strip()]
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error extracting strings: {e}")

        return strings

    def add_script_template(self, script_type: str, script: str):
        """
        Add a script template to the workflow automation

        Args:
            script_type: Type of script (ida, ghidra, frida, yara)
            script: Script content
        """
        if not hasattr(self, 'script_templates'):
            self.script_templates = {}

        if script_type not in self.script_templates:
            self.script_templates[script_type] = []

        self.script_templates[script_type].append(script)
        self.logger.info(f"Added {script_type} script template")

    def add_workflow(self, name: str, steps: List[Dict[str, Any]]):
        """
        Add a workflow to the workflow automation

        Args:
            name: Name of the workflow
            steps: List of workflow steps
        """
        if not hasattr(self, 'workflows'):
            self.workflows = {}

        self.workflows[name] = steps
        self.logger.info(f"Added workflow: {name} with {len(steps)} steps")

    def execute_workflow(self, name: str, binary_path: str) -> Dict[str, Any]:
        """
        Execute a workflow on a binary

        Args:
            name: Name of the workflow
            binary_path: Path to the binary file

        Returns:
            Dictionary containing the workflow results
        """
        if not hasattr(self, 'workflows') or name not in self.workflows:
            self.logger.error(f"Workflow not found: {name}")
            return {"error": f"Workflow not found: {name}"}

        self.logger.info(f"Executing workflow: {name} on {binary_path}")

        results = {
            "workflow": name,
            "binary": binary_path,
            "steps": []
        }

        for i, step in enumerate(self.workflows[name]):
            step_type = step.get("type", "unknown")
            step_params = step.get("params", {})

            self.logger.info(f"Executing workflow step {i+1}: {step_type}")

            step_result = {"type": step_type, "status": "failed"}

            try:
                if step_type == "ida_script":
                    script_result = self.generate_ida_script(binary_path, step_params.get("task", ""))
                    step_result = {"type": step_type, "status": "success", "result": script_result}

                elif step_type == "ghidra_script":
                    script_result = self.generate_ghidra_script(binary_path, step_params.get("task", ""))
                    step_result = {"type": step_type, "status": "success", "result": script_result}

                elif step_type == "frida_script":
                    script_result = self.generate_frida_script(binary_path, step_params.get("task", ""))
                    step_result = {"type": step_type, "status": "success", "result": script_result}

                elif step_type == "yara_rule":
                    rule_result = self.generate_yara_rule(binary_path, step_params.get("description", ""))
                    step_result = {"type": step_type, "status": "success", "result": rule_result}

                elif step_type == "explain_structure":
                    explanation = self.explain_binary_structure(binary_path)
                    step_result = {"type": step_type, "status": "success", "result": explanation}

                else:
                    step_result = {"type": step_type, "status": "failed", "error": f"Unknown step type: {step_type}"}

            except Exception as e:
                self.logger.error(f"Error executing workflow step: {e}")
                step_result = {"type": step_type, "status": "failed", "error": str(e)}

            results["steps"].append(step_result)

        return results
