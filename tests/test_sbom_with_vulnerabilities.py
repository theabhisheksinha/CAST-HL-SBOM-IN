#!/usr/bin/env python3
"""
Test script to check SBOM generation with vulnerability data
"""

import json
import sys
import os
from src.sbom_generator import load_config, CASTHighlightAPI, SBOMGenerator

def test_sbom_with_vulnerabilities():
    """Test SBOM generation and check vulnerability data processing"""
    config = load_config("config/config.json")
    
    # Extract configuration
    cast_config = config.get('cast_highlight', {})
    auth_config = cast_config.get('authentication', {})
    
    base_url = cast_config.get('api_url', '')
    username = auth_config.get('username')
    password = auth_config.get('password')
    company_id = auth_config.get('company_id')
    app_id = config.get('application_id', '481502')
    
    print(f"Testing SBOM generation with vulnerability data")
    print(f"Application ID: {app_id}")
    print("-" * 50)
    
    # Initialize API client
    try:
        api = CASTHighlightAPI(
            base_url=base_url,
            username=username,
            password=password,
            company_id=company_id
        )
        print("✅ API client initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize API client: {e}")
        return
    
    # Test vulnerability endpoint directly
    print(f"\n1. Testing vulnerability endpoint directly...")
    try:
        vulnerabilities = api.get_vulnerabilities(app_id)
        print(f"   📊 Found {len(vulnerabilities)} vulnerability records")
        if vulnerabilities:
            print(f"   📋 Sample vulnerability data: {json.dumps(vulnerabilities[0], indent=2)}")
        else:
            print("   ⚠️  No vulnerability data found")
    except Exception as e:
        print(f"   ❌ Error fetching vulnerabilities: {e}")
    
    # Test components endpoint
    print(f"\n2. Testing components endpoint...")
    try:
        components = api.get_components(app_id)
        print(f"   📊 Found {len(components)} components")
        if components:
            print(f"   📋 Sample component: {json.dumps(components[0], indent=2)}")
    except Exception as e:
        print(f"   ❌ Error fetching components: {e}")
    
    # Generate SBOM
    print(f"\n3. Generating SBOM...")
    try:
        generator = SBOMGenerator(api)
        sbom_data = generator.generate_sbom(app_id)
        
        print(f"   📊 SBOM generated successfully")
        print(f"   📋 Total components: {len(sbom_data.get('components', []))}")
        
        # Check if vulnerabilities were added to components
        components_with_vulns = [c for c in sbom_data.get('components', []) if c.get('vulnerabilities')]
        print(f"   📋 Components with vulnerabilities: {len(components_with_vulns)}")
        
        if components_with_vulns:
            print(f"   📋 Sample component with vulnerabilities: {json.dumps(components_with_vulns[0], indent=2)}")
        
        # Save SBOM to JSON for inspection
        output_file = "test_sbom_output.json"
        with open(output_file, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        print(f"   💾 SBOM saved to {output_file}")
        
    except Exception as e:
        print(f"   ❌ Error generating SBOM: {e}")

if __name__ == "__main__":
    test_sbom_with_vulnerabilities() 