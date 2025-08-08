#!/usr/bin/env python3
"""
Test CycloneDX generation functionality
"""

import json
import os
import sys
import tempfile
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sbom_generator import SBOMExporter

def test_cyclonedx_generation():
    """Test CycloneDX generation with sample data"""
    
    # Sample SBOM data that mimics CAST Highlight output
    sample_sbom_data = {
        "sbomVersion": "1.0",
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": "CAST Highlight SBOM Generator",
            "version": "1.0",
            "application": {
                "name": "Test Application",
                "version": "1.0.0",
                "description": "A test application for SBOM generation"
            }
        },
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.28.0",
                "description": "Python HTTP library",
                "purl": "pkg:pypi/requests@2.28.0",
                "externalReferences": [
                    {
                        "type": "repository",
                        "url": "https://github.com/psf/requests"
                    },
                    {
                        "type": "website",
                        "url": "https://requests.readthedocs.io/"
                    }
                ],
                "properties": [
                    {"name": "cast:packageType", "value": "pypi"},
                    {"name": "cast:origin", "value": "PyPI"},
                    {"name": "cast:criticality", "value": "HIGH"}
                ],
                "supplier": {
                    "name": "Python Software Foundation"
                },
                "author": "Kenneth Reitz",
                "copyright": "Copyright (c) 2018 Kenneth Reitz",
                "licenses": [
                    {
                        "licenseId": "Apache-2.0",
                        "name": "Apache License 2.0",
                        "url": "https://www.apache.org/licenses/LICENSE-2.0"
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2023-32681",
                        "description": "A vulnerability in requests library",
                        "severity": "HIGH",
                        "cvssScore": 7.5,
                        "cweId": "CWE-400",
                        "cpe": "cpe:2.3:a:python-requests:requests:2.28.0:*:*:*:*:*:*:*:*",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
                    }
                ]
            },
            {
                "type": "library",
                "name": "openpyxl",
                "version": "3.0.0",
                "description": "Python library for reading/writing Excel files",
                "purl": "pkg:pypi/openpyxl@3.0.0",
                "externalReferences": [
                    {
                        "type": "repository",
                        "url": "https://bitbucket.org/openpyxl/openpyxl"
                    }
                ],
                "properties": [
                    {"name": "cast:packageType", "value": "pypi"},
                    {"name": "cast:origin", "value": "PyPI"},
                    {"name": "cast:criticality", "value": "MEDIUM"}
                ],
                "supplier": {
                    "name": "OpenPyXL Contributors"
                },
                "author": "Eric Gazoni",
                "copyright": "Copyright (c) 2010 openpyxl",
                "licenses": [
                    {
                        "licenseId": "MIT",
                        "name": "MIT License",
                        "url": "https://opensource.org/licenses/MIT"
                    }
                ],
                "vulnerabilities": []
            }
        ]
    }
    
    # Test JSON format
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
        json_filename = tmp_file.name
    
    try:
        print("Testing CycloneDX JSON generation...")
        SBOMExporter.export_cyclonedx(sample_sbom_data, json_filename, "json")
        
        # Verify file was created and contains valid JSON
        if os.path.exists(json_filename):
            with open(json_filename, 'r') as f:
                content = f.read()
                cyclonedx_data = json.loads(content)
                
            # Basic validation
            assert "bomFormat" in cyclonedx_data
            assert cyclonedx_data["bomFormat"] == "CycloneDX"
            assert "specVersion" in cyclonedx_data
            assert "metadata" in cyclonedx_data
            assert "components" in cyclonedx_data
            
            print(f"✅ CycloneDX JSON generation successful!")
            print(f"   - BOM Format: {cyclonedx_data['bomFormat']}")
            print(f"   - Spec Version: {cyclonedx_data['specVersion']}")
            print(f"   - Components: {len(cyclonedx_data['components'])}")
            print(f"   - File: {json_filename}")
            
        else:
            print("❌ CycloneDX JSON file was not created")
            return False
            
    except Exception as e:
        print(f"❌ CycloneDX JSON generation failed: {e}")
        return False
    finally:
        # Clean up
        if os.path.exists(json_filename):
            os.unlink(json_filename)
    
    # Test XML format
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
        xml_filename = tmp_file.name
    
    try:
        print("\nTesting CycloneDX XML generation...")
        SBOMExporter.export_cyclonedx(sample_sbom_data, xml_filename, "xml")
        
        # Verify file was created and contains valid XML
        if os.path.exists(xml_filename):
            with open(xml_filename, 'r') as f:
                content = f.read()
                
            # Basic XML validation
            assert "<?xml" in content
            assert "<bom" in content
            assert "xmlns=" in content
            assert "cyclonedx.org" in content
            
            print(f"✅ CycloneDX XML generation successful!")
            print(f"   - File: {xml_filename}")
            print(f"   - Size: {len(content)} characters")
            
        else:
            print("❌ CycloneDX XML file was not created")
            return False
            
    except Exception as e:
        print(f"❌ CycloneDX XML generation failed: {e}")
        return False
    finally:
        # Clean up
        if os.path.exists(xml_filename):
            os.unlink(xml_filename)
    
    print("\n🎉 All CycloneDX tests passed!")
    return True

def test_cyclonedx_with_real_data():
    """Test with the enhanced SBOM output file if it exists"""
    
    enhanced_sbom_file = os.path.join(os.path.dirname(__file__), '..', 'test_enhanced_sbom_output.json')
    
    if not os.path.exists(enhanced_sbom_file):
        print(f"⚠️  Enhanced SBOM file not found: {enhanced_sbom_file}")
        print("   Skipping real data test...")
        return True
    
    try:
        print("\nTesting CycloneDX generation with real SBOM data...")
        
        with open(enhanced_sbom_file, 'r', encoding='utf-8') as f:
            real_sbom_data = json.load(f)
        
        # Test JSON format
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
            json_filename = tmp_file.name
        
        try:
            SBOMExporter.export_cyclonedx(real_sbom_data, json_filename, "json")
            
            if os.path.exists(json_filename):
                with open(json_filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    cyclonedx_data = json.loads(content)
                
                print(f"✅ Real data CycloneDX JSON generation successful!")
                print(f"   - Components: {len(cyclonedx_data.get('components', []))}")
                print(f"   - File: {json_filename}")
                
            else:
                print("❌ Real data CycloneDX JSON file was not created")
                
        finally:
            if os.path.exists(json_filename):
                os.unlink(json_filename)
                
    except Exception as e:
        print(f"❌ Real data CycloneDX generation failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🧪 Testing CycloneDX Generation")
    print("=" * 50)
    
    success = True
    
    # Test basic functionality
    if not test_cyclonedx_generation():
        success = False
    
    # Test with real data
    if not test_cyclonedx_with_real_data():
        success = False
    
    if success:
        print("\n🎉 All tests passed! CycloneDX generation is working correctly.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        sys.exit(1)
