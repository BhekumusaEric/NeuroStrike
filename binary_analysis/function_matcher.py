"""
Function Matcher Module
Provides tools for symbol resolution and function matching
"""

import os
import re
import subprocess
import tempfile
import hashlib
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union, Set

from utils.logger import get_logger
from ai_models.model_loader import load_llm

class FunctionMatcher:
    """
    Function Matching class
    Provides tools for matching functions across different binaries
    """

    def __init__(self):
        """Initialize the Function Matcher"""
        self.logger = get_logger("function_matcher")
        self.llm = load_llm()
        self.logger.info("Function Matcher initialized")

        # Function signature database
        self.signature_db = {}

        # Check for required tools
        self._check_tools()

    def _check_tools(self):
        """Check if required tools are available"""
        # List of tools to check
        tools = {
            "objdump": False,
            "nm": False,
            "readelf": False
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

    def extract_functions(self, binary_path: str) -> Dict[str, Dict[str, Any]]:
        """
        Extract functions from a binary

        Args:
            binary_path: Path to the binary file

        Returns:
            Dictionary mapping function names to function information
        """
        if not os.path.exists(binary_path):
            self.logger.error(f"Binary file not found: {binary_path}")
            return {}

        self.logger.info(f"Extracting functions from: {binary_path}")

        functions = {}

        # Extract function symbols using nm
        if self.available_tools.get("nm", False):
            try:
                result = subprocess.run(["nm", "-C", binary_path],
                                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = result.stdout.decode("utf-8", errors="ignore")

                for line in output.split("\n"):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3 and parts[1].lower() in ['t', 'w']:  # Text section symbols
                            address = parts[0]
                            name = ' '.join(parts[2:])
                            functions[name] = {
                                "name": name,
                                "address": address,
                                "source": "nm",
                                "instructions": []
                            }
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error extracting function symbols with nm: {e}")

        # Extract function disassembly using objdump
        if self.available_tools.get("objdump", False):
            try:
                result = subprocess.run(["objdump", "-d", binary_path],
                                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = result.stdout.decode("utf-8", errors="ignore")

                current_function = None
                current_name = None

                for line in output.split("\n"):
                    if "<" in line and ">:" in line:
                        # This is a function header
                        function_name = line.split("<")[1].split(">:")[0]
                        address = line.split()[0].strip()

                        # Check if we already have this function from nm
                        if function_name in functions:
                            current_function = functions[function_name]
                        else:
                            current_function = {
                                "name": function_name,
                                "address": address,
                                "source": "objdump",
                                "instructions": []
                            }
                            functions[function_name] = current_function

                        current_name = function_name

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
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error extracting function disassembly with objdump: {e}")

        # Calculate function signatures
        for name, func in functions.items():
            func["signature"] = self._calculate_function_signature(func)

        return functions

    def _calculate_function_signature(self, function: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate a signature for a function"""
        if not function.get("instructions"):
            return {"hash": "", "features": {}}

        # Extract opcodes and operands
        opcodes = []
        operands = []

        for instr in function["instructions"]:
            instruction_text = instr["instruction"]
            parts = instruction_text.split(None, 1)

            if parts:
                opcodes.append(parts[0])
                if len(parts) > 1:
                    operands.append(parts[1])

        # Calculate opcode frequency
        opcode_freq = {}
        for op in opcodes:
            if op not in opcode_freq:
                opcode_freq[op] = 0
            opcode_freq[op] += 1

        # Calculate instruction bigrams
        bigrams = []
        for i in range(len(opcodes) - 1):
            bigrams.append(f"{opcodes[i]}_{opcodes[i+1]}")

        bigram_freq = {}
        for bg in bigrams:
            if bg not in bigram_freq:
                bigram_freq[bg] = 0
            bigram_freq[bg] += 1

        # Calculate a hash of the function
        instr_text = " ".join(instr["instruction"] for instr in function["instructions"])
        hash_value = hashlib.md5(instr_text.encode()).hexdigest()

        return {
            "hash": hash_value,
            "features": {
                "instruction_count": len(function["instructions"]),
                "opcode_freq": opcode_freq,
                "bigram_freq": bigram_freq
            }
        }

    def add_to_signature_db(self, binary_path: str, binary_version: str) -> int:
        """
        Add functions from a binary to the signature database

        Args:
            binary_path: Path to the binary file
            binary_version: Version identifier for the binary

        Returns:
            Number of functions added to the database
        """
        functions = self.extract_functions(binary_path)

        count = 0
        for name, func in functions.items():
            signature = func["signature"]
            if signature["hash"]:
                key = f"{binary_version}:{name}"
                self.signature_db[key] = {
                    "name": name,
                    "version": binary_version,
                    "signature": signature,
                    "address": func["address"]
                }
                count += 1

        self.logger.info(f"Added {count} functions from {binary_path} to signature database")
        return count

    def match_function(self, function: Dict[str, Any], threshold: float = 0.8) -> List[Dict[str, Any]]:
        """
        Match a function against the signature database

        Args:
            function: Function information dictionary
            threshold: Similarity threshold (0.0 to 1.0)

        Returns:
            List of matching functions with similarity scores
        """
        if not function.get("signature"):
            function["signature"] = self._calculate_function_signature(function)

        matches = []

        for key, db_func in self.signature_db.items():
            similarity = self._calculate_similarity(function["signature"], db_func["signature"])

            if similarity >= threshold:
                matches.append({
                    "name": db_func["name"],
                    "version": db_func["version"],
                    "similarity": similarity,
                    "address": db_func["address"]
                })

        # Sort by similarity (highest first)
        matches.sort(key=lambda x: x["similarity"], reverse=True)

        return matches

    def _calculate_similarity(self, sig1: Dict[str, Any], sig2: Dict[str, Any]) -> float:
        """Calculate similarity between two function signatures"""
        # If we have exact hash match, return 1.0
        if sig1["hash"] == sig2["hash"]:
            return 1.0

        features1 = sig1["features"]
        features2 = sig2["features"]

        # Calculate instruction count similarity
        count1 = features1["instruction_count"]
        count2 = features2["instruction_count"]
        count_ratio = min(count1, count2) / max(count1, count2) if max(count1, count2) > 0 else 0

        # Calculate opcode frequency similarity
        opcode_sim = self._calculate_feature_similarity(
            features1["opcode_freq"], features2["opcode_freq"])

        # Calculate bigram frequency similarity
        bigram_sim = self._calculate_feature_similarity(
            features1["bigram_freq"], features2["bigram_freq"])

        # Weighted similarity
        similarity = 0.2 * count_ratio + 0.3 * opcode_sim + 0.5 * bigram_sim

        return similarity

    def _calculate_feature_similarity(self, freq1: Dict[str, int], freq2: Dict[str, int]) -> float:
        """Calculate similarity between two frequency dictionaries"""
        # Get all keys
        all_keys = set(freq1.keys()) | set(freq2.keys())

        if not all_keys:
            return 0.0

        # Calculate cosine similarity
        dot_product = 0
        magnitude1 = 0
        magnitude2 = 0

        for key in all_keys:
            value1 = freq1.get(key, 0)
            value2 = freq2.get(key, 0)

            dot_product += value1 * value2
            magnitude1 += value1 * value1
            magnitude2 += value2 * value2

        magnitude1 = np.sqrt(magnitude1)
        magnitude2 = np.sqrt(magnitude2)

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)

    def find_similar_functions(self, binary_path: str, threshold: float = 0.8) -> Dict[str, List[Dict[str, Any]]]:
        """
        Find functions in a binary that match functions in the signature database

        Args:
            binary_path: Path to the binary file
            threshold: Similarity threshold (0.0 to 1.0)

        Returns:
            Dictionary mapping function names to lists of matches
        """
        functions = self.extract_functions(binary_path)

        results = {}
        for name, func in functions.items():
            matches = self.match_function(func, threshold)
            if matches:
                results[name] = matches

        return results

    def identify_key_functions(self, binary_path: str, function_names: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Identify specific key functions in a binary

        Args:
            binary_path: Path to the binary file
            function_names: List of function names to look for

        Returns:
            Dictionary mapping function names to lists of potential matches
        """
        functions = self.extract_functions(binary_path)

        results = {}
        for target_name in function_names:
            results[target_name] = []

            # First, look for exact name matches
            if target_name in functions:
                results[target_name].append({
                    "name": target_name,
                    "address": functions[target_name]["address"],
                    "match_type": "exact_name",
                    "confidence": 1.0
                })
                continue

            # Look for partial name matches
            partial_matches = []
            for name, func in functions.items():
                if target_name.lower() in name.lower():
                    partial_matches.append({
                        "name": name,
                        "address": func["address"],
                        "match_type": "partial_name",
                        "confidence": 0.8
                    })

            if partial_matches:
                results[target_name].extend(partial_matches)
                continue

            # Use LLM to identify potential matches based on function behavior
            potential_matches = self._identify_by_behavior(functions, target_name)
            if potential_matches:
                results[target_name].extend(potential_matches)

        return results

    def _identify_by_behavior(self, functions: Dict[str, Dict[str, Any]], target_name: str) -> List[Dict[str, Any]]:
        """Identify functions that might match a target name based on behavior"""
        # Prepare a description of the target function for the LLM
        function_descriptions = {
            "check_activation_state": "Checks if a device is activated, likely accesses activation tickets or tokens",
            "load_ticket": "Loads or parses an activation ticket, likely handles cryptographic operations",
            "verify_ticket": "Verifies the authenticity of an activation ticket, likely uses cryptographic functions",
            "sandbox_init": "Initializes a sandbox environment, likely sets up security profiles",
            "amfi_check": "Checks Apple Mobile File Integrity, likely verifies code signatures",
            "decrypt_key": "Decrypts a key or performs key derivation, likely uses cryptographic primitives",
            "verify_signature": "Verifies a digital signature, likely uses cryptographic hash functions",
            "check_entitlement": "Checks if a process has a specific entitlement, likely accesses entitlement data",
            "load_profile": "Loads a security or configuration profile, likely parses profile data",
            "validate_certificate": "Validates a certificate, likely performs certificate chain validation"
        }

        description = function_descriptions.get(target_name, f"Function related to {target_name.replace('_', ' ')}")

        # Select a subset of functions to analyze (to avoid overwhelming the LLM)
        candidate_functions = {}
        for name, func in functions.items():
            # Skip very small functions (likely stubs)
            if len(func.get("instructions", [])) < 5:
                continue

            # Skip very large functions (too complex for this analysis)
            if len(func.get("instructions", [])) > 100:
                continue

            candidate_functions[name] = func

        # If we have too many candidates, select a reasonable number
        if len(candidate_functions) > 20:
            # Prioritize functions with interesting names
            interesting_keywords = ["activation", "ticket", "verify", "check", "load", "init",
                                   "security", "crypto", "sign", "auth", "validate", "sandbox"]

            scored_candidates = []
            for name, func in candidate_functions.items():
                score = 0
                for keyword in interesting_keywords:
                    if keyword.lower() in name.lower():
                        score += 1
                scored_candidates.append((score, name, func))

            # Sort by score (highest first) and take top 20
            scored_candidates.sort(reverse=True)
            candidate_functions = {name: func for _, name, func in scored_candidates[:20]}

        # Prepare function information for the LLM
        function_info = []
        for name, func in candidate_functions.items():
            # Get a sample of instructions (first 10)
            instructions = [instr["instruction"] for instr in func.get("instructions", [])[:10]]
            instruction_text = "\n".join(instructions)

            function_info.append(f"Function: {name}\nInstructions:\n{instruction_text}\n")

        # Ask the LLM to identify potential matches
        prompt = f"""
        I'm looking for a function named "{target_name}" or something similar in a binary.

        Description of what "{target_name}" should do:
        {description}

        Here are some functions from the binary. Please identify which ones might be "{target_name}" based on their name and instructions:

        {' '.join(function_info)}

        For each potential match, provide:
        1. The function name
        2. A confidence score (0.0 to 1.0)
        3. A brief explanation of why you think it might be a match

        Format your response as a list of matches, with the most likely matches first.
        """

        response = self.llm.generate(prompt)

        # Parse the LLM response to extract potential matches
        potential_matches = []

        # Simple parsing - in a real implementation, we would use a more robust approach
        for line in response.split("\n"):
            if ":" in line and any(name in line for name in candidate_functions.keys()):
                parts = line.split(":")
                name = parts[0].strip()

                if name in candidate_functions:
                    # Look for confidence score
                    confidence = 0.5  # Default
                    confidence_match = re.search(r"confidence[:\s]+([0-9.]+)", response, re.IGNORECASE)
                    if confidence_match:
                        try:
                            confidence = float(confidence_match.group(1))
                        except:
                            pass

                    potential_matches.append({
                        "name": name,
                        "address": candidate_functions[name]["address"],
                        "match_type": "behavior_analysis",
                        "confidence": confidence
                    })

        # Sort by confidence (highest first)
        potential_matches.sort(key=lambda x: x["confidence"], reverse=True)

        return potential_matches

    def add_signature(self, signature: str, function_name: str, version: str = "unknown"):
        """
        Add a function signature to the signature database

        Args:
            signature: Function signature
            function_name: Name of the function
            version: Version of the binary
        """
        if not hasattr(self, 'custom_signatures'):
            self.custom_signatures = []

        # Create a unique key for the signature
        key = f"{function_name}_{version}_{len(self.custom_signatures)}"

        # Add to custom signatures
        self.custom_signatures.append({
            "name": function_name,
            "version": version,
            "signature": signature,
            "key": key
        })

        # Add to signature database
        self.signature_db[key] = {
            "name": function_name,
            "version": version,
            "signature": signature,
            "address": "unknown"
        }

        self.logger.info(f"Added signature for function {function_name} (version {version})")

    def add_function_pattern(self, pattern: Dict[str, Any]):
        """
        Add a function pattern to the function matcher

        Args:
            pattern: Function pattern to add
        """
        if not hasattr(self, 'function_patterns'):
            self.function_patterns = []

        self.function_patterns.append(pattern)
        self.logger.info(f"Added function pattern: {pattern.get('name', 'unnamed')}")
