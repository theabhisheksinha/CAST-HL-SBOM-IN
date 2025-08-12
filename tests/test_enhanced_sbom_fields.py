#!/usr/bin/env python3
"""
Test script to verify the enhanced SBOM field coverage
Specifically tests for the issues identified in the observations:
1. Checksums/Hashes
2. Component Description
3. Consistent Component Properties
4. EOL Date
5. Copyright Information
6. Removal of unnecessary fields (author, timestamp at component level)
"""

import sys
import os
import json
import logging
from datetime import datetime

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from sbom_builder import SBOMBuilder
from sbom_exporter import SBOMExporter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_test_data():
    """Create test data that includes all the fields we want to test"""
    return {
        'third_party': [
            {
                'name': 'test-component',
                'version': '1.0.0',
                'description': 'This is a test component description',
                'packageType': 'maven',
                'fingerprint': 'abc123def456',
                'sha1': 'sha1hash',
                'sha256': 'sha256hash',
                'md5': 'md5hash',
                'eolDate': '2025-12-31',
                'copyright': 'Copyright (c) 2023 Test Company',
                'supplier': 'Test Supplier',
                'supplierContact': 'supplier@example.com',
                'licenses': [
                    {
                        'name': 'MIT',
                        'url': 'https://opensource.org/licenses/MIT'
                    }
                ],
                'cve': {
                    'vulnerabilities': [
                        {
                            'name': 'CVE-2023-1234',
                            'description': 'Test vulnerability',
                            'criticity': 'HIGH',
                            'cvssScore': 7.5
                        }
                    ]
                }
            }
        ],
        'components': [],
        'vulnerabilities': [],
        'licenses': []
    }

def test_sbom_builder():
    """Test the SBOM builder with our test data"""
    logger.info("Testing SBOM Builder with enhanced fields")
    
    # Create test data
    test_data = create_test_data()
    
    # Build SBOM
    builder = SBOMBuilder(test_data)
    sbom = builder.build()
    
    # Verify the SBOM has the expected fields
    assert len(sbom['components']) == 1, "Expected 1 component"
    
    component = sbom['components'][0]
    
    # Test 1: Verify description is present
    assert component['description'] == 'This is a test component description', "Description not properly set"
    
    # Test 2: Verify checksums/hashes are present
    has_hash = False
    for prop in component['properties']:
        if prop['name'] in ['cast:fingerprint', 'cast:sha1', 'cast:sha256', 'cast:md5']:
            has_hash = True
            break
    assert has_hash, "No checksums/hashes found in properties"
    
    # Test 3: Verify EOL date is present
    has_eol = False
    for prop in component['properties']:
        if prop['name'] == 'cast:eolDate':
            has_eol = True
            assert prop['value'] == '2025-12-31', "EOL date not properly set"
            break
    assert has_eol, "EOL date not found in properties"
    
    # Test 4: Verify copyright is present
    assert component['copyright'] == 'Copyright (c) 2023 Test Company', "Copyright not properly set"
    
    # Test 5: Verify author field is not present (as it's not required at component level)
    assert 'author' not in component, "Author field should not be present at component level"
    
    # Test 6: Verify timestamp field is not present at component level
    assert 'timestamp' not in component, "Timestamp field should not be present at component level"
    
    # Test 7: Verify supplier information is present
    assert component['supplier']['name'] == 'Test Supplier', "Supplier name not properly set"
    assert component['supplier']['contact'] == 'supplier@example.com', "Supplier contact not properly set"
    
    logger.info("All SBOM Builder tests passed!")
    return sbom

def test_cyclonedx_export(sbom):
    """Test the CycloneDX export with our enhanced SBOM"""
    logger.info("Testing CycloneDX export with enhanced fields")
    
    # Export to CycloneDX JSON
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_enhanced_cyclonedx.json')
    SBOMExporter.export_cyclonedx(sbom, output_file, format="json")
    
    # Read the exported file
    with open(output_file, 'r', encoding='utf-8') as f:
        cyclonedx_data = json.load(f)
    
    # Verify CycloneDX structure
    assert cyclonedx_data['bomFormat'] == 'CycloneDX', "BOM format not set to CycloneDX"
    assert cyclonedx_data['specVersion'] == '1.4', "Spec version not set to 1.4"
    
    # Verify component data
    assert len(cyclonedx_data['components']) == 1, "Expected 1 component in CycloneDX output"
    
    component = cyclonedx_data['components'][0]
    
    # Test 1: Verify description is present
    assert component['description'] == 'This is a test component description', "Description not properly exported to CycloneDX"
    
    # Test 2: Verify copyright is present
    assert 'copyright' in component, "Copyright not exported to CycloneDX"
    assert component['copyright'] == 'Copyright (c) 2023 Test Company', "Copyright not properly exported to CycloneDX"
    
    # Test 3: Verify hashes are present
    assert 'hashes' in component, "Hashes not exported to CycloneDX"
    
    # Test 4: Verify properties are present
    assert 'properties' in component, "Properties not exported to CycloneDX"
    
    # Test 5: Verify EOL date is in properties
    has_eol = False
    for prop in component['properties']:
        if prop['name'] == 'cast:eolDate':
            has_eol = True
            break
    assert has_eol, "EOL date not found in CycloneDX properties"
    
    logger.info("All CycloneDX export tests passed!")
    logger.info(f"CycloneDX output saved to {output_file}")

def main():
    """Main test function"""
    logger.info("Starting enhanced SBOM field tests")
    
    # Test SBOM builder
    sbom = test_sbom_builder()
    
    # Test CycloneDX export
    test_cyclonedx_export(sbom)
    
    logger.info("All tests completed successfully!")

if __name__ == "__main__":
    main()