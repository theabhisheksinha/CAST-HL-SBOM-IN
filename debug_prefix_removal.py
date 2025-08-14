#!/usr/bin/env python3

import os
import sys
import json
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sbom_exporter import SBOMExporter

def test_prefix_removal():
    """Test the cast: prefix removal functionality"""
    
    # Create test SBOM data with cast: prefixes
    test_sbom = {
        "sbomVersion": "1.0",
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tool": "Test Tool"
        },
        "components": [
            {
                "type": "library",
                "name": "test-component",
                "version": "1.0.0",
                "properties": [
                    {
                        "name": "cast:origin",
                        "value": "Scan"
                    },
                    {
                        "name": "cast:lastVersion",
                        "value": "1.2.0"
                    },
                    {
                        "name": "cast:languages",
                        "value": "java"
                    },
                    {
                        "name": "regular_property",
                        "value": "test_value"
                    }
                ]
            }
        ]
    }
    
    print("Original SBOM data:")
    print(json.dumps(test_sbom, indent=2))
    print("\n" + "="*50 + "\n")
    
    # Test the prefix removal
    processed_sbom = SBOMExporter._process_sbom_properties(test_sbom)
    
    print("Processed SBOM data (after prefix removal):")
    print(json.dumps(processed_sbom, indent=2))
    print("\n" + "="*50 + "\n")
    
    # Check if prefixes were removed
    component = processed_sbom["components"][0]
    properties = component["properties"]
    
    cast_prefixes_found = []
    for prop in properties:
        if prop["name"].startswith("cast:"):
            cast_prefixes_found.append(prop["name"])
    
    if cast_prefixes_found:
        print(f"ERROR: Found {len(cast_prefixes_found)} properties still with 'cast:' prefix:")
        for prop_name in cast_prefixes_found:
            print(f"  - {prop_name}")
        return False
    else:
        print("SUCCESS: All 'cast:' prefixes have been removed!")
        return True

def test_reports_directory():
    """Test Reports directory creation"""
    
    print("Testing Reports directory creation...")
    
    # Create Reports directory if it doesn't exist
    reports_dir = "Reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"Created Reports directory: {os.path.abspath(reports_dir)}")
    else:
        print(f"Reports directory already exists: {os.path.abspath(reports_dir)}")
    
    # Test file creation
    test_filename = os.path.join(reports_dir, "test_file.txt")
    try:
        with open(test_filename, 'w') as f:
            f.write("Test file creation")
        print(f"Successfully created test file: {os.path.abspath(test_filename)}")
        
        # Clean up
        os.remove(test_filename)
        print("Test file removed successfully")
        return True
    except Exception as e:
        print(f"ERROR: Failed to create test file: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("DEBUGGING CAST PREFIX REMOVAL AND REPORTS DIRECTORY")
    print("=" * 60)
    
    # Test 1: Reports directory
    print("\nTest 1: Reports Directory Creation")
    print("-" * 40)
    reports_success = test_reports_directory()
    
    # Test 2: Prefix removal
    print("\nTest 2: Cast Prefix Removal")
    print("-" * 40)
    prefix_success = test_prefix_removal()
    
    # Summary
    print("\nSUMMARY:")
    print("-" * 40)
    print(f"Reports Directory: {'PASS' if reports_success else 'FAIL'}")
    print(f"Prefix Removal: {'PASS' if prefix_success else 'FAIL'}")
    
    if reports_success and prefix_success:
        print("\nAll tests passed! The issues should be resolved.")
    else:
        print("\nSome tests failed. Please check the output above for details.")