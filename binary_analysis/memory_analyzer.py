"""
Memory Analyzer Module
Provides tools for dynamic memory pattern detection
"""

import os
import re
import struct
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union, BinaryIO

from utils.logger import get_logger
from ai_models.model_loader import load_llm

class MemoryAnalyzer:
    """
    Memory Analysis class
    Provides tools for analyzing memory dumps and detecting patterns
    """

    def __init__(self):
        """Initialize the Memory Analyzer"""
        self.logger = get_logger("memory_analyzer")
        self.llm = load_llm()
        self.logger.info("Memory Analyzer initialized")

        # Patterns for common structures
        self.patterns = {
            "encryption_key": rb"(?:.{0,16})((?:[A-F0-9]{2}){16,32})(?:.{0,16})",
            "email": rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "ipv4": rb"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "url": rb"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?",
            "credit_card": rb"\b(?:\d{4}[- ]?){3}\d{4}\b",
            "json_object": rb"\{(?:[^{}]|(?R))*\}",
            "xml_tag": rb"<[^>]+>.*?</[^>]+>",
            "base64": rb"[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            "guid": rb"\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b"
        }

    def analyze_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """
        Analyze a memory dump file

        Args:
            dump_path: Path to the memory dump file

        Returns:
            Dictionary containing analysis results
        """
        if not os.path.exists(dump_path):
            self.logger.error(f"Memory dump file not found: {dump_path}")
            return {"error": f"Memory dump file not found: {dump_path}"}

        self.logger.info(f"Analyzing memory dump: {dump_path}")

        results = {
            "file_info": {
                "path": dump_path,
                "size": os.path.getsize(dump_path)
            },
            "patterns": self._detect_patterns(dump_path),
            "entropy_regions": self._analyze_entropy(dump_path),
            "structure_candidates": self._detect_structures(dump_path)
        }

        return results

    def _detect_patterns(self, dump_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """Detect patterns in memory dump"""
        pattern_matches = {pattern_name: [] for pattern_name in self.patterns}

        try:
            with open(dump_path, "rb") as f:
                data = f.read()

                for pattern_name, pattern in self.patterns.items():
                    matches = re.finditer(pattern, data)
                    for match in matches:
                        match_data = match.group(0)
                        try:
                            # Try to decode as UTF-8, but fall back to hex representation
                            match_text = match_data.decode("utf-8", errors="replace")
                        except:
                            match_text = match_data.hex()

                        pattern_matches[pattern_name].append({
                            "offset": match.start(),
                            "length": len(match_data),
                            "value": match_text
                        })
        except Exception as e:
            self.logger.error(f"Error detecting patterns: {e}")

        return pattern_matches

    def _analyze_entropy(self, dump_path: str, window_size: int = 256) -> List[Dict[str, Any]]:
        """Analyze entropy in memory dump to identify encrypted regions"""
        entropy_regions = []

        try:
            with open(dump_path, "rb") as f:
                data = f.read()

                # Calculate entropy in sliding windows
                for i in range(0, len(data) - window_size, window_size // 2):
                    window = data[i:i+window_size]
                    entropy = self._calculate_entropy(window)

                    # High entropy regions (likely encrypted or compressed)
                    if entropy > 7.5:
                        entropy_regions.append({
                            "offset": i,
                            "size": len(window),
                            "entropy": entropy,
                            "type": "likely_encrypted"
                        })
                    # Medium entropy regions (possibly obfuscated)
                    elif entropy > 6.5:
                        entropy_regions.append({
                            "offset": i,
                            "size": len(window),
                            "entropy": entropy,
                            "type": "possibly_obfuscated"
                        })
        except Exception as e:
            self.logger.error(f"Error analyzing entropy: {e}")

        # Merge adjacent regions
        merged_regions = []
        current_region = None

        for region in sorted(entropy_regions, key=lambda r: r["offset"]):
            if current_region is None:
                current_region = region.copy()
            elif region["offset"] <= current_region["offset"] + current_region["size"]:
                # Merge regions
                end_offset = max(current_region["offset"] + current_region["size"],
                                region["offset"] + region["size"])
                current_region["size"] = end_offset - current_region["offset"]
                current_region["entropy"] = max(current_region["entropy"], region["entropy"])
                if current_region["type"] != region["type"]:
                    current_region["type"] = "mixed"
            else:
                merged_regions.append(current_region)
                current_region = region.copy()

        if current_region is not None:
            merged_regions.append(current_region)

        return merged_regions

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            if byte not in byte_counts:
                byte_counts[byte] = 0
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)

        return entropy

    def _detect_structures(self, dump_path: str) -> List[Dict[str, Any]]:
        """Detect potential data structures in memory dump"""
        structures = []

        try:
            with open(dump_path, "rb") as f:
                data = f.read()

                # Look for potential C struct patterns
                # This is a simplified approach - in a real implementation,
                # we would use more sophisticated techniques

                # Look for pointer arrays (sequences of 4 or 8 byte aligned addresses)
                pointer_patterns = []

                # 32-bit pointers (look for sequences of 4-byte values that could be pointers)
                for i in range(0, len(data) - 16, 4):
                    values = []
                    for j in range(4):
                        if i + j*4 + 4 <= len(data):
                            value = struct.unpack("<I", data[i+j*4:i+j*4+4])[0]
                            values.append(value)

                    # Check if these look like pointers (within a reasonable memory range)
                    if all(0x10000 <= v <= 0x7FFFFFFF for v in values):
                        # Check if they're sequential or related
                        diffs = [values[j+1] - values[j] for j in range(len(values)-1)]
                        if len(set(diffs)) <= 2:  # Allow at most 2 different strides
                            pointer_patterns.append({
                                "offset": i,
                                "size": len(values) * 4,
                                "type": "pointer_array_32bit",
                                "values": values,
                                "stride": diffs[0] if diffs else 0
                            })

                # 64-bit pointers
                for i in range(0, len(data) - 32, 8):
                    values = []
                    for j in range(4):
                        if i + j*8 + 8 <= len(data):
                            value = struct.unpack("<Q", data[i+j*8:i+j*8+8])[0]
                            values.append(value)

                    # Check if these look like pointers (within a reasonable memory range)
                    if all(0x100000000 <= v <= 0x7FFFFFFFFFFFFFFF for v in values):
                        # Check if they're sequential or related
                        diffs = [values[j+1] - values[j] for j in range(len(values)-1)]
                        if len(set(diffs)) <= 2:  # Allow at most 2 different strides
                            pointer_patterns.append({
                                "offset": i,
                                "size": len(values) * 8,
                                "type": "pointer_array_64bit",
                                "values": values,
                                "stride": diffs[0] if diffs else 0
                            })

                structures.extend(pointer_patterns)

                # Look for other common structure patterns
                # (This would be expanded in a real implementation)
        except Exception as e:
            self.logger.error(f"Error detecting structures: {e}")

        return structures

    def analyze_memory_region(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        """
        Analyze a specific memory region

        Args:
            data: Binary data to analyze
            offset: Original offset of the data in the memory dump

        Returns:
            Dictionary containing analysis results
        """
        self.logger.info(f"Analyzing memory region at offset {offset}, size {len(data)}")

        results = {
            "offset": offset,
            "size": len(data),
            "entropy": self._calculate_entropy(data),
            "patterns": {},
            "structure_guess": None
        }

        # Detect patterns
        for pattern_name, pattern in self.patterns.items():
            matches = re.finditer(pattern, data)
            results["patterns"][pattern_name] = []

            for match in matches:
                match_data = match.group(0)
                try:
                    match_text = match_data.decode("utf-8", errors="replace")
                except:
                    match_text = match_data.hex()

                results["patterns"][pattern_name].append({
                    "offset": offset + match.start(),
                    "length": len(match_data),
                    "value": match_text
                })

        # Guess structure type
        results["structure_guess"] = self._guess_structure_type(data)

        return results

    def _guess_structure_type(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Guess the type of data structure"""
        if len(data) < 8:
            return None

        # Check for common structure signatures

        # Check if it looks like a string table
        if all(c == 0 or 32 <= c <= 126 for c in data):
            strings = data.split(b'\x00')
            if len(strings) > 1 and all(len(s) > 0 for s in strings[:-1]):
                return {
                    "type": "string_table",
                    "strings": [s.decode("utf-8", errors="replace") for s in strings if s]
                }

        # Check if it looks like an array of integers
        if len(data) % 4 == 0:
            values = [struct.unpack("<I", data[i:i+4])[0] for i in range(0, len(data), 4)]
            # Check if values are within a reasonable range and have patterns
            if all(0 <= v <= 0xFFFFFFFF for v in values):
                diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
                if len(set(diffs)) <= 3:  # Allow at most 3 different strides
                    return {
                        "type": "integer_array",
                        "element_size": 4,
                        "count": len(values),
                        "values": values[:10]  # First 10 values
                    }

        # Check if it looks like a binary tree or linked list
        if len(data) >= 16:
            # Simple heuristic: look for pointer-like values that could be next/prev pointers
            potential_pointers = []
            for i in range(0, len(data) - 8, 4):
                value = struct.unpack("<I", data[i:i+4])[0]
                if 0x10000 <= value <= 0x7FFFFFFF:
                    potential_pointers.append((i, value))

            if len(potential_pointers) >= 2:
                return {
                    "type": "linked_structure",
                    "potential_pointers": [(offset, f"0x{value:08x}") for offset, value in potential_pointers[:5]]
                }

        # Use LLM to guess structure if other methods fail
        if len(data) <= 256:  # Only for reasonably small data
            hex_dump = ' '.join(f"{b:02x}" for b in data)
            prompt = f"""
            Analyze this binary data (shown as hex) and guess what kind of data structure it might represent:

            {hex_dump}

            Consider common data structures like:
            - C structs
            - Arrays
            - Linked lists
            - Trees
            - Hash tables
            - String tables
            - File headers

            Provide your best guess at the structure and explain your reasoning.
            """

            llm_guess = self.llm.generate(prompt)
            return {
                "type": "llm_guess",
                "guess": llm_guess
            }

        return None

    def add_pattern(self, pattern: str):
        """
        Add a pattern to the memory analyzer's pattern database

        Args:
            pattern: Pattern to add
        """
        if not hasattr(self, 'custom_patterns'):
            self.custom_patterns = []

        self.custom_patterns.append(pattern)
        self.logger.info(f"Added pattern to memory analyzer: {pattern}")

        # Also add to the regular patterns dictionary with a custom name
        pattern_name = f"custom_pattern_{len(self.custom_patterns)}"
        try:
            compiled_pattern = re.compile(pattern.encode('utf-8'))
            self.patterns[pattern_name] = compiled_pattern
            self.logger.info(f"Compiled and added pattern as {pattern_name}")
        except Exception as e:
            self.logger.error(f"Failed to compile pattern: {e}")

    def add_structure_template(self, name: str, structure: Dict[str, Any]):
        """
        Add a structure template to the memory analyzer

        Args:
            name: Name of the structure
            structure: Structure definition
        """
        if not hasattr(self, 'structure_templates'):
            self.structure_templates = {}

        self.structure_templates[name] = structure
        self.logger.info(f"Added structure template to memory analyzer: {name}")
