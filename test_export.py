#!/usr/bin/env python3

import os
import sys
import json
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sbom_exporter import SBOMExporter

def test_export():
    """Test the export functionality"""
    
    # Create simple test SBOM data
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
                    }
                ]
            }
        ]
    }
    
    # Create Reports directory
    reports_dir = "Reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"Created Reports directory: {os.path.abspath(reports_dir)}")
    else:
        print(f"Reports directory exists: {os.path.abspath(reports_dir)}")
    
    # Test JSON export
    test_filename = os.path.join(reports_dir, "test_export.json")
    print(f"\nTesting JSON export to: {os.path.abspath(test_filename)}")
    
    try:
        SBOMExporter.export_json(test_sbom, test_filename)
        
        # Check if file was created
        if os.path.exists(test_filename):
            print(f"SUCCESS: File created at {os.path.abspath(test_filename)}")
            
            # Read and check content
            with open(test_filename, 'r') as f:
                content = json.load(f)
            
            print("\nFile content:")
            print(json.dumps(content, indent=2))
            
            # Check if cast: prefixes were removed
            component = content["components"][0]
            properties = component["properties"]
            
            cast_prefixes_found = []
            for prop in properties:
                if prop["name"].startswith("cast:"):
                    cast_prefixes_found.append(prop["name"])
            
            if cast_prefixes_found:
                print(f"\nWARNING: Found {len(cast_prefixes_found)} properties still with 'cast:' prefix:")
                for prop_name in cast_prefixes_found:
                    print(f"  - {prop_name}")
            else:
                print("\nSUCCESS: All 'cast:' prefixes have been removed in the exported file!")
            
            # Clean up
            os.remove(test_filename)
            print(f"\nTest file removed: {test_filename}")
            
        else:
            print(f"ERROR: File was not created at {test_filename}")
            
    except Exception as e:
        print(f"ERROR: Export failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("=" * 50)
    print("TESTING EXPORT FUNCTIONALITY")
    print("=" * 50)
    test_export()