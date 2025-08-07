#!/usr/bin/env python3
"""
Test script to verify enhanced SBOM generation with comprehensive field coverage
"""

import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.highlight_api import HighlightAPI
from src.sbom_builder import SBOMBuilder
from src.config_loader import load_config

def test_enhanced_sbom_generation():
    """Test enhanced SBOM generation and verify field coverage"""
    
    print("🧪 Testing Enhanced SBOM Generation")
    print("=" * 50)
    
    try:
        # Load configuration
        config = load_config("config/config.json")
        
        # Extract configuration
        cast_config = config.get('cast_highlight', {})
        auth_config = cast_config.get('authentication', {})
        
        base_url = cast_config.get('api_url', '')
        username = auth_config.get('username')
        password = auth_config.get('password')
        company_id = auth_config.get('company_id')
        app_id = config.get('application_id', '481502')
        
        print(f"Testing Enhanced SBOM generation for Application ID: {app_id}")
        print("-" * 50)
        
        # Initialize enhanced API client
        try:
            api = HighlightAPI(
                base_url=base_url,
                company_id=company_id,
                auth_method='credentials',
                username=username,
                password=password
            )
            print("✅ Enhanced API client initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize API client: {e}")
            return
        
        # Test comprehensive data collection
        print(f"\n1. Testing comprehensive data collection...")
        try:
            comprehensive_data = api.get_comprehensive_sbom_data(app_id)
            
            if not comprehensive_data:
                print("   ❌ No comprehensive data retrieved")
                return
            
            # Log data sources
            data_sources = []
            if comprehensive_data.get('third_party'):
                data_sources.append("third-party components")
                print(f"   ✅ Third-party data: {len(comprehensive_data['third_party'].get('thirdParties', []))} components")
            
            if comprehensive_data.get('components'):
                data_sources.append("detailed components")
                if isinstance(comprehensive_data['components'], list):
                    print(f"   ✅ Component data: {len(comprehensive_data['components'])} components")
                else:
                    print(f"   ✅ Component data: {len(comprehensive_data['components'].get('components', []))} components")
            
            if comprehensive_data.get('vulnerabilities'):
                data_sources.append("vulnerabilities")
                print(f"   ✅ Vulnerability data: {len(comprehensive_data['vulnerabilities'])} vulnerabilities")
            
            if comprehensive_data.get('licenses'):
                data_sources.append("licenses")
                print(f"   ✅ License data: {len(comprehensive_data['licenses'])} licenses")
            
            print(f"   📊 Data sources: {', '.join(data_sources)}")
            
        except Exception as e:
            print(f"   ❌ Error collecting comprehensive data: {e}")
            return
        
        # Test enhanced SBOM building
        print(f"\n2. Testing enhanced SBOM building...")
        try:
            sbom_builder = SBOMBuilder(comprehensive_data)
            sbom_data = sbom_builder.build()
            
            print(f"   ✅ Enhanced SBOM built successfully")
            print(f"   📊 Total components: {len(sbom_data.get('components', []))}")
            
            # Analyze field coverage
            components = sbom_data.get('components', [])
            if components:
                print(f"   📋 Field coverage analysis:")
                
                # Check basic fields
                basic_fields = ['name', 'version', 'description', 'purl', 'type']
                for field in basic_fields:
                    coverage = sum(1 for c in components if c.get(field))
                    percentage = (coverage / len(components)) * 100
                    print(f"      - {field}: {coverage}/{len(components)} ({percentage:.1f}%)")
                
                # Check enhanced fields
                enhanced_fields = ['licenses', 'vulnerabilities', 'properties', 'externalReferences']
                for field in enhanced_fields:
                    coverage = sum(1 for c in components if c.get(field))
                    percentage = (coverage / len(components)) * 100
                    print(f"      - {field}: {coverage}/{len(components)} ({percentage:.1f}%)")
                
                # Check properties coverage
                properties_coverage = {}
                for component in components:
                    for prop in component.get('properties', []):
                        prop_name = prop.get('name', 'unknown')
                        properties_coverage[prop_name] = properties_coverage.get(prop_name, 0) + 1
                
                if properties_coverage:
                    print(f"      - Properties found: {len(properties_coverage)} types")
                    for prop_name, count in sorted(properties_coverage.items()):
                        percentage = (count / len(components)) * 100
                        print(f"        * {prop_name}: {count} components ({percentage:.1f}%)")
                
                # Sample component analysis
                sample_component = components[0]
                print(f"\n   📋 Sample component analysis:")
                print(f"      - Name: {sample_component.get('name', 'Unknown')}")
                print(f"      - Version: {sample_component.get('version', 'Unknown')}")
                print(f"      - PURL: {sample_component.get('purl', 'Unknown')}")
                print(f"      - Licenses: {len(sample_component.get('licenses', []))}")
                print(f"      - Vulnerabilities: {len(sample_component.get('vulnerabilities', []))}")
                print(f"      - Properties: {len(sample_component.get('properties', []))}")
                print(f"      - External References: {len(sample_component.get('externalReferences', []))}")
            
        except Exception as e:
            print(f"   ❌ Error building enhanced SBOM: {e}")
            return
        
        # Save enhanced SBOM to JSON for inspection
        print(f"\n3. Saving enhanced SBOM for inspection...")
        try:
            output_file = "test_enhanced_sbom_output.json"
            with open(output_file, 'w') as f:
                json.dump(sbom_data, f, indent=2)
            print(f"   💾 Enhanced SBOM saved to {output_file}")
            
            # Calculate overall field coverage
            total_components = len(components)
            if total_components > 0:
                # Count components with meaningful data (not just "Unknown" or "Unavailable")
                meaningful_data_count = 0
                for component in components:
                    has_meaningful_data = False
                    for key, value in component.items():
                        if (value and 
                            value != "Unknown" and 
                            value != "Unavailable from CAST Highlight" and
                            not (isinstance(value, dict) and value.get('name') == "Unavailable from CAST Highlight")):
                            has_meaningful_data = True
                            break
                    if has_meaningful_data:
                        meaningful_data_count += 1
                
                meaningful_percentage = (meaningful_data_count / total_components) * 100
                print(f"   📊 Components with meaningful data: {meaningful_data_count}/{total_components} ({meaningful_percentage:.1f}%)")
                
                if meaningful_percentage >= 80:
                    print("   🏆 EXCELLENT - High field coverage achieved")
                elif meaningful_percentage >= 60:
                    print("   ✅ GOOD - Good field coverage achieved")
                elif meaningful_percentage >= 40:
                    print("   ⚠️  MODERATE - Moderate field coverage")
                else:
                    print("   ❌ POOR - Low field coverage")
            
        except Exception as e:
            print(f"   ❌ Error saving enhanced SBOM: {e}")
        
        print(f"\n✅ Enhanced SBOM test completed successfully!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_enhanced_sbom_generation()
