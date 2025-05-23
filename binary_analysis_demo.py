#!/usr/bin/env python3
"""
Binary Analysis Module Demo Script
Shows how the Binary Analysis module enhances NeuroStrike's capabilities
"""

import os
import sys
import argparse
from typing import Dict, List, Any

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import NeuroStrike modules
from binary_analysis.analyzer import BinaryAnalyzer
from binary_analysis.memory_analyzer import MemoryAnalyzer
from binary_analysis.function_matcher import FunctionMatcher
from binary_analysis.exploit_pathfinder import ExploitPathfinder
from binary_analysis.workflow_automation import WorkflowAutomation

def demo_binary_analyzer(binary_path: str):
    """Demonstrate the Binary Analyzer"""
    print("\n=== Binary Analyzer Demo ===")
    print(f"Analyzing binary: {binary_path}")
    print("-" * 50)
    
    analyzer = BinaryAnalyzer()
    
    # Analyze the binary
    results = analyzer.analyze_binary(binary_path)
    
    # Print file information
    print(f"File type: {results['file_info']['type']}")
    print(f"File size: {results['file_info']['size']} bytes")
    
    # Print sections
    print("\nSections:")
    for section in results['sections'][:5]:  # Show first 5 sections
        print(f"  {section['name']} - {section['size']} bytes at {section['address']}")
    if len(results['sections']) > 5:
        print(f"  ... and {len(results['sections']) - 5} more sections")
    
    # Print functions
    print("\nFunctions:")
    for function in results['functions'][:5]:  # Show first 5 functions
        print(f"  {function['name']} at {function['address']}")
        if function['instructions']:
            print(f"    First instruction: {function['instructions'][0]['instruction']}")
    if len(results['functions']) > 5:
        print(f"  ... and {len(results['functions']) - 5} more functions")
    
    # Print imports
    print("\nImports:")
    for imp in results['imports'][:5]:  # Show first 5 imports
        print(f"  {imp}")
    if len(results['imports']) > 5:
        print(f"  ... and {len(results['imports']) - 5} more imports")
    
    # Explain some assembly code
    if results['functions'] and results['functions'][0]['instructions']:
        function = results['functions'][0]
        assembly_code = "\n".join([instr['instruction'] for instr in function['instructions'][:10]])
        
        print("\nExplaining assembly code for function:", function['name'])
        explanation = analyzer.explain_assembly(assembly_code)
        print(explanation)

def demo_memory_analyzer(dump_path: str):
    """Demonstrate the Memory Analyzer"""
    print("\n=== Memory Analyzer Demo ===")
    print(f"Analyzing memory dump: {dump_path}")
    print("-" * 50)
    
    analyzer = MemoryAnalyzer()
    
    # Analyze the memory dump
    results = analyzer.analyze_memory_dump(dump_path)
    
    # Print file information
    print(f"File size: {results['file_info']['size']} bytes")
    
    # Print detected patterns
    print("\nDetected Patterns:")
    for pattern_type, matches in results['patterns'].items():
        if matches:
            print(f"  {pattern_type}: {len(matches)} matches")
            for match in matches[:2]:  # Show first 2 matches
                print(f"    Offset: {match['offset']}, Value: {match['value'][:30]}...")
    
    # Print entropy regions
    print("\nHigh Entropy Regions (potentially encrypted):")
    for region in results['entropy_regions']:
        if region['entropy'] > 7.0:
            print(f"  Offset: {region['offset']}, Size: {region['size']} bytes, Entropy: {region['entropy']:.2f}")
    
    # Print structure candidates
    print("\nPotential Data Structures:")
    for structure in results['structure_candidates'][:5]:
        print(f"  Type: {structure['type']} at offset {structure['offset']}, Size: {structure['size']} bytes")

def demo_function_matcher(binary_path: str, reference_binary_path: str = None):
    """Demonstrate the Function Matcher"""
    print("\n=== Function Matcher Demo ===")
    print(f"Analyzing binary: {binary_path}")
    if reference_binary_path:
        print(f"Reference binary: {reference_binary_path}")
    print("-" * 50)
    
    matcher = FunctionMatcher()
    
    # Extract functions from the binary
    functions = matcher.extract_functions(binary_path)
    
    # Print functions
    print(f"Extracted {len(functions)} functions from {binary_path}")
    for name, func in list(functions.items())[:5]:  # Show first 5 functions
        print(f"  {name} at {func['address']}")
    
    # If we have a reference binary, add it to the signature database and find matches
    if reference_binary_path:
        # Add reference binary to signature database
        count = matcher.add_to_signature_db(reference_binary_path, "reference")
        print(f"\nAdded {count} functions from {reference_binary_path} to signature database")
        
        # Find similar functions
        similar_functions = matcher.find_similar_functions(binary_path, threshold=0.7)
        
        print("\nSimilar Functions:")
        for name, matches in similar_functions.items():
            print(f"  {name} matches:")
            for match in matches:
                print(f"    {match['name']} (similarity: {match['similarity']:.2f})")
    
    # Identify key functions
    key_functions = ["main", "init", "check", "verify", "encrypt", "decrypt"]
    identified = matcher.identify_key_functions(binary_path, key_functions)
    
    print("\nIdentified Key Functions:")
    for name, matches in identified.items():
        if matches:
            print(f"  {name}:")
            for match in matches:
                print(f"    {match['name']} at {match['address']} (confidence: {match['confidence']:.2f})")
        else:
            print(f"  {name}: Not found")

def demo_exploit_pathfinder(binary_path: str):
    """Demonstrate the Exploit Pathfinder"""
    print("\n=== Exploit Pathfinder Demo ===")
    print(f"Analyzing binary: {binary_path}")
    print("-" * 50)
    
    pathfinder = ExploitPathfinder()
    
    # Find potential vulnerabilities
    vulnerabilities = pathfinder.find_potential_vulnerabilities(binary_path)
    
    # Print vulnerabilities
    print("Potential Vulnerabilities:")
    for vuln_type, vulns in vulnerabilities.items():
        if vulns:
            print(f"  {vuln_type}: {len(vulns)} potential vulnerabilities")
            for vuln in vulns[:2]:  # Show first 2 vulnerabilities
                print(f"    Function: {vuln['function']}")
                print(f"    Match: {vuln['match']}")
                print(f"    Confidence: {vuln['confidence']:.2f}")
                if 'explanation' in vuln:
                    print(f"    Explanation: {vuln['explanation'][:100]}...")
                print()
    
    # Generate a fuzzing harness for a function
    if vulnerabilities:
        # Find a vulnerable function
        vuln_function = None
        for vulns in vulnerabilities.values():
            if vulns:
                vuln_function = vulns[0]['function']
                break
        
        if vuln_function:
            print(f"\nGenerating fuzzing harness for function: {vuln_function}")
            harness = pathfinder.generate_fuzzing_harness(binary_path, vuln_function)
            
            if 'error' not in harness:
                print(f"Fuzzing harness generated: {harness['harness_path']}")
                print("\nHarness code snippet:")
                print("-" * 50)
                print(harness['harness_code'][:500] + "..." if len(harness['harness_code']) > 500 else harness['harness_code'])
                print("-" * 50)

def demo_workflow_automation(binary_path: str):
    """Demonstrate the Workflow Automation"""
    print("\n=== Workflow Automation Demo ===")
    print(f"Analyzing binary: {binary_path}")
    print("-" * 50)
    
    automation = WorkflowAutomation()
    
    # Explain binary structure
    print("Explaining binary structure:")
    explanation = automation.explain_binary_structure(binary_path)
    print(explanation)
    
    # Generate a YARA rule
    print("\nGenerating YARA rule for detecting similar binaries:")
    yara_rule = automation.generate_yara_rule(binary_path, "Detect similar binaries with the same functionality")
    
    print(f"YARA rule generated: {yara_rule['rule_path']}")
    print("\nYARA rule snippet:")
    print("-" * 50)
    print(yara_rule['rule'][:500] + "..." if len(yara_rule['rule']) > 500 else yara_rule['rule'])
    print("-" * 50)
    
    # Generate an IDA Pro script
    print("\nGenerating IDA Pro script for analyzing functions:")
    ida_script = automation.generate_ida_script(binary_path, "Identify and rename cryptographic functions")
    
    print(f"IDA Pro script generated: {ida_script['script_path']}")
    print("\nIDA Pro script snippet:")
    print("-" * 50)
    print(ida_script['script'][:500] + "..." if len(ida_script['script']) > 500 else ida_script['script'])
    print("-" * 50)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Binary Analysis Module Demo")
    parser.add_argument("binary_path", help="Path to the binary file to analyze")
    parser.add_argument("--reference", help="Path to a reference binary file for function matching")
    parser.add_argument("--memory-dump", help="Path to a memory dump file for memory analysis")
    parser.add_argument("--demo", choices=["all", "analyzer", "memory", "matcher", "pathfinder", "automation"],
                       default="all", help="Which demo to run")
    
    args = parser.parse_args()
    
    # Check if the binary file exists
    if not os.path.exists(args.binary_path):
        print(f"Error: Binary file not found: {args.binary_path}")
        return 1
    
    # Check if the reference binary file exists
    if args.reference and not os.path.exists(args.reference):
        print(f"Error: Reference binary file not found: {args.reference}")
        return 1
    
    # Check if the memory dump file exists
    if args.memory_dump and not os.path.exists(args.memory_dump):
        print(f"Error: Memory dump file not found: {args.memory_dump}")
        return 1
    
    # Run the selected demo
    if args.demo in ["all", "analyzer"]:
        demo_binary_analyzer(args.binary_path)
    
    if args.demo in ["all", "memory"] and args.memory_dump:
        demo_memory_analyzer(args.memory_dump)
    
    if args.demo in ["all", "matcher"]:
        demo_function_matcher(args.binary_path, args.reference)
    
    if args.demo in ["all", "pathfinder"]:
        demo_exploit_pathfinder(args.binary_path)
    
    if args.demo in ["all", "automation"]:
        demo_workflow_automation(args.binary_path)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
