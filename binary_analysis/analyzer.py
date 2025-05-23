"""
Binary Analyzer Module
Provides tools for binary and assembly analysis
"""

import os
import subprocess
import tempfile
from typing import Dict, List, Any, Optional, Tuple, Union

from utils.logger import get_logger
from ai_models.model_loader import load_llm

class BinaryAnalyzer:
    """
    Binary and Assembly Analysis class
    Provides tools for analyzing binary files and assembly code
    """

    def __init__(self):
        """Initialize the Binary Analyzer"""
        self.logger = get_logger("binary_analyzer")
        self.llm = load_llm()
        self.logger.info("Binary Analyzer initialized")

        # Check for required tools
        self._check_tools()

    def _check_tools(self):
        """Check if required tools are available"""
        # List of tools to check
        tools = {
            "objdump": False,
            "readelf": False,
            "strings": False,
            "ghidra_server": False,
            "radare2": False
        }

        # Check each tool
        for tool in tools:
            try:
                subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                tools[tool] = True
                self.logger.info(f"Tool found: {tool}")
            except subprocess.CalledProcessError:
                self.logger.warning(f"Tool not found: {tool}")

        self.available_tools = tools

    def add_pattern(self, pattern: str):
        """
        Add a pattern to the analyzer's pattern database

        Args:
            pattern: Pattern to add
        """
        if not hasattr(self, 'patterns'):
            self.patterns = []

        self.patterns.append(pattern)
        self.logger.info(f"Added pattern to binary analyzer: {pattern}")

    def add_assembly_example(self, assembly_code: str, explanation: str):
        """
        Add an assembly code example with explanation

        Args:
            assembly_code: Assembly code
            explanation: Explanation of the assembly code
        """
        if not hasattr(self, 'assembly_examples'):
            self.assembly_examples = []

        self.assembly_examples.append({
            "assembly_code": assembly_code,
            "explanation": explanation
        })

        self.logger.info("Added assembly example to binary analyzer")

    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze a binary file

        Args:
            binary_path: Path to the binary file

        Returns:
            Dictionary containing analysis results
        """
        if not os.path.exists(binary_path):
            self.logger.error(f"Binary file not found: {binary_path}")
            return {"error": f"Binary file not found: {binary_path}"}

        self.logger.info(f"Analyzing binary: {binary_path}")

        results = {
            "file_info": self._get_file_info(binary_path),
            "strings": self._extract_strings(binary_path),
            "functions": self._extract_functions(binary_path),
            "sections": self._extract_sections(binary_path),
            "imports": self._extract_imports(binary_path),
            "exports": self._extract_exports(binary_path)
        }

        return results

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

    def _extract_strings(self, binary_path: str, min_length: int = 4) -> List[str]:
        """Extract strings from binary"""
        strings = []

        if not self.available_tools.get("strings", False):
            self.logger.warning("strings tool not available")
            return strings

        try:
            result = subprocess.run(["strings", "-n", str(min_length), binary_path],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")
            strings = [s.strip() for s in output.split("\n") if s.strip()]
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error extracting strings: {e}")

        return strings

    def _extract_functions(self, binary_path: str) -> List[Dict[str, Any]]:
        """Extract functions from binary"""
        functions = []

        if not self.available_tools.get("objdump", False):
            self.logger.warning("objdump tool not available")
            return functions

        try:
            result = subprocess.run(["objdump", "-d", binary_path],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")

            # Parse objdump output to extract functions
            current_function = None
            for line in output.split("\n"):
                if "<" in line and ">:" in line:
                    # This is a function header
                    function_name = line.split("<")[1].split(">:")[0]
                    address = line.split()[0].strip()
                    if current_function:
                        functions.append(current_function)
                    current_function = {
                        "name": function_name,
                        "address": address,
                        "instructions": []
                    }
                elif current_function and line.strip() and ":" in line:
                    # This is an instruction
                    parts = line.strip().split(":", 1)
                    if len(parts) > 1:
                        address = parts[0].strip()
                        instruction = parts[1].strip()
                        current_function["instructions"].append({
                            "address": address,
                            "instruction": instruction
                        })

            if current_function:
                functions.append(current_function)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error extracting functions: {e}")

        return functions

    def _extract_sections(self, binary_path: str) -> List[Dict[str, Any]]:
        """Extract sections from binary"""
        sections = []

        if not self.available_tools.get("readelf", False):
            self.logger.warning("readelf tool not available")
            return sections

        try:
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
            self.logger.error(f"Error extracting sections: {e}")

        return sections

    def _extract_imports(self, binary_path: str) -> List[str]:
        """Extract imported symbols from binary"""
        imports = []

        if not self.available_tools.get("objdump", False):
            self.logger.warning("objdump tool not available")
            return imports

        try:
            result = subprocess.run(["objdump", "-T", binary_path],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")

            # Parse objdump output to extract imports
            for line in output.split("\n"):
                if "*UND*" in line:  # This indicates an import
                    parts = line.split()
                    if len(parts) >= 6:
                        symbol = parts[-1]
                        imports.append(symbol)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error extracting imports: {e}")

        return imports

    def _extract_exports(self, binary_path: str) -> List[str]:
        """Extract exported symbols from binary"""
        exports = []

        if not self.available_tools.get("objdump", False):
            self.logger.warning("objdump tool not available")
            return exports

        try:
            result = subprocess.run(["objdump", "-T", binary_path],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8", errors="ignore")

            # Parse objdump output to extract exports
            for line in output.split("\n"):
                if ".text" in line and "g     F" in line:  # This indicates an export
                    parts = line.split()
                    if len(parts) >= 6:
                        symbol = parts[-1]
                        exports.append(symbol)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error extracting exports: {e}")

        return exports

    def explain_assembly(self, assembly_code: str) -> str:
        """
        Use LLM to explain assembly code

        Args:
            assembly_code: Assembly code to explain

        Returns:
            Explanation of the assembly code
        """
        self.logger.info("Explaining assembly code")

        prompt = f"""
        Analyze and explain the following assembly code in detail:

        ```
        {assembly_code}
        ```

        Please provide:
        1. A high-level overview of what this code does
        2. Explanation of key instructions and their purpose
        3. Identification of any potential security-relevant operations
        4. Equivalent pseudocode in C-like syntax
        """

        explanation = self.llm.generate(prompt)
        return explanation

    def compare_binaries(self, binary1_path: str, binary2_path: str) -> Dict[str, Any]:
        """
        Compare two binary files

        Args:
            binary1_path: Path to the first binary file
            binary2_path: Path to the second binary file

        Returns:
            Dictionary containing comparison results
        """
        self.logger.info(f"Comparing binaries: {binary1_path} and {binary2_path}")

        # Basic comparison using diff
        try:
            result = subprocess.run(["diff", "-q", binary1_path, binary2_path],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            identical = result.returncode == 0
        except subprocess.CalledProcessError:
            identical = False

        # Get file info for both binaries
        file1_info = self._get_file_info(binary1_path)
        file2_info = self._get_file_info(binary2_path)

        # Compare sizes
        size_diff = file2_info["size"] - file1_info["size"]

        # Compare strings
        strings1 = set(self._extract_strings(binary1_path))
        strings2 = set(self._extract_strings(binary2_path))
        unique_strings1 = strings1 - strings2
        unique_strings2 = strings2 - strings1
        common_strings = strings1.intersection(strings2)

        # Compare functions
        functions1 = {f["name"]: f for f in self._extract_functions(binary1_path)}
        functions2 = {f["name"]: f for f in self._extract_functions(binary2_path)}
        unique_functions1 = set(functions1.keys()) - set(functions2.keys())
        unique_functions2 = set(functions2.keys()) - set(functions1.keys())
        common_functions = set(functions1.keys()).intersection(set(functions2.keys()))

        # Compare modified functions
        modified_functions = []
        for func_name in common_functions:
            if functions1[func_name] != functions2[func_name]:
                modified_functions.append(func_name)

        return {
            "identical": identical,
            "size_diff": size_diff,
            "unique_strings1": list(unique_strings1)[:100],  # Limit to 100 strings
            "unique_strings2": list(unique_strings2)[:100],  # Limit to 100 strings
            "common_strings_count": len(common_strings),
            "unique_functions1": list(unique_functions1),
            "unique_functions2": list(unique_functions2),
            "modified_functions": modified_functions
        }
