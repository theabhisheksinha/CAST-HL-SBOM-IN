#!/usr/bin/env python3
"""
Example usage of the CAST Highlight SBOM Generator
This script demonstrates how to use the SBOM generator programmatically.
"""

import json
import sys
from src.sbom_generator import CASTHighlightAPI, SBOMGenerator, SBOMExporter

def main():
    """Example usage of the SBOM generator"""
    
    # Configuration - replace with your actual values
    config = {
        "api_url": "https://your-cast-highlight-instance.com/api",
        "app_id": "your-application-id",
        # Choose one authentication method:
        "authentication": {
            "method": "credentials",  # or "api_key"
            "username": "your-username",
            "password": "your-password", 
            "company_id": "your-company-id",
            "api_key": "your-api-key-here"
        }
    }
    
    try:
        # Initialize CAST Highlight API client
        print("Initializing CAST Highlight API client...")
        
        if config["authentication"]["method"] == "credentials":
            cast_api = CASTHighlightAPI(
                config["api_url"],
                username=config["authentication"]["username"],
                password=config["authentication"]["password"],
                company_id=config["authentication"]["company_id"]
            )
        else:
            cast_api = CASTHighlightAPI(
                config["api_url"],
                api_key=config["authentication"]["api_key"]
            )
        
        # List available applications
        print("Fetching available applications...")
        applications = cast_api.get_applications()
        print(f"Found {len(applications)} applications")
        
        for app in applications[:5]:  # Show first 5 applications
            print(f"  - {app.get('name', 'Unknown')} (ID: {app.get('id', 'Unknown')})")
        
        # Generate SBOM for specified application
        print(f"\nGenerating SBOM for application {config['app_id']}...")
        generator = SBOMGenerator(cast_api)
        sbom_data = generator.generate_sbom(config["app_id"])
        
        # Export in different formats
        print("Exporting SBOM in different formats...")
        
        # JSON format
        SBOMExporter.export_json(sbom_data, "example_sbom.json")
        
        # CSV format
        SBOMExporter.export_csv(sbom_data, "example_sbom.csv")
        
        # SPDX format
        SBOMExporter.export_spdx(sbom_data, "example_sbom.spdx")
        
        # Display summary
        print("\nSBOM Generation Summary:")
        print(f"  - Total components: {len(sbom_data['components'])}")
        
        # Count components with vulnerabilities
        components_with_vulns = sum(1 for comp in sbom_data['components'] if comp.get('vulnerabilities'))
        print(f"  - Components with vulnerabilities: {components_with_vulns}")
        
        # Count components with licenses
        components_with_licenses = sum(1 for comp in sbom_data['components'] if comp.get('licenses'))
        print(f"  - Components with licenses: {components_with_licenses}")
        
        # Show sample component data
        if sbom_data['components']:
            print("\nSample component data:")
            sample_component = sbom_data['components'][0]
            print(f"  - Name: {sample_component.get('name')}")
            print(f"  - Version: {sample_component.get('version')}")
            print(f"  - Type: {sample_component.get('type')}")
            print(f"  - PURL: {sample_component.get('purl')}")
            print(f"  - Licenses: {len(sample_component.get('licenses', []))}")
            print(f"  - Vulnerabilities: {len(sample_component.get('vulnerabilities', []))}")
        
        print("\nSBOM generation completed successfully!")
        print("Files generated:")
        print("  - example_sbom.json")
        print("  - example_sbom.csv")
        print("  - example_sbom.spdx")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def analyze_compliance():
    """Analyze SBOM compliance with mandatory fields"""
    
    print("\n=== SBOM Compliance Analysis ===")
    
    # Mandatory fields that CAST Highlight can provide
    available_fields = [
        "Component name and version",
        "Package URL (PURL)",
        "Component type",
        "License information",
        "Security vulnerabilities",
        "Repository URLs",
        "Source locations",
        "Technical metadata"
    ]
    
    # Mandatory fields that CAST Highlight cannot provide
    unavailable_fields = [
        "Supplier information",
        "Author information", 
        "Copyright information",
        "Build information",
        "Distribution information",
        "Usage information"
    ]
    
    print("\n✅ Fields that CAST Highlight CAN provide:")
    for field in available_fields:
        print(f"  - {field}")
    
    print(f"\n❌ Fields that CAST Highlight CANNOT provide ({len(unavailable_fields)} fields):")
    for field in unavailable_fields:
        print(f"  - {field}")
    
    print(f"\n📊 Compliance Summary:")
    print(f"  - Available fields: {len(available_fields)}")
    print(f"  - Unavailable fields: {len(unavailable_fields)}")
    print(f"  - Coverage: {len(available_fields)/(len(available_fields) + len(unavailable_fields))*100:.1f}%")
    
    print("\n💡 Recommendations:")
    print("  1. Use CAST Highlight for technical component data")
    print("  2. Manually supplement supplier, author, and copyright information")
    print("  3. Document build and distribution processes separately")
    print("  4. Consider integrating with additional tools for complete coverage")

if __name__ == "__main__":
    print("CAST Highlight SBOM Generator - Example Usage")
    print("=" * 50)
    
    # Show compliance analysis
    analyze_compliance()
    
    # Run example (commented out to avoid API calls without proper configuration)
    print("\nTo run the example:")
    print("1. Update the config dictionary in this script with your API credentials")
    print("2. Uncomment the main() call below")
    print("3. Run: python example_usage.py")
    
    # Uncomment the line below to run the example
    # main() 