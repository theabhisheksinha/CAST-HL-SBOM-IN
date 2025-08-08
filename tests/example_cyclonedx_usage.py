#!/usr/bin/env python3
"""
Example: Generate CycloneDX SBOM from CAST Highlight data
"""

import os
import sys
import json
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sbom_generator import HighlightAPI, SBOMGenerator, SBOMExporter

def example_cyclonedx_generation():
    """Example of generating CycloneDX SBOM from CAST Highlight"""
    
    print("🚀 CAST Highlight CycloneDX SBOM Generation Example")
    print("=" * 60)
    
    # Configuration (you would normally load this from config/config.json)
    config = {
        "cast_highlight": {
            "api_url": "https://your-cast-highlight-instance.com",
            "company_id": "your-company-id"
        },
        "authentication": {
            "method": "api_key",  # or "credentials"
            "api_key": "your-api-key"
            # For credentials method:
            # "username": "your-username",
            # "password": "your-password"
        },
        "application_id": "your-application-id",
        "sbom_settings": {
            "output_formats": ["cyclonedx"]  # This will generate both JSON and XML
        }
    }
    
    try:
        # Initialize CAST Highlight API client
        print("📡 Connecting to CAST Highlight...")
        cast_api = HighlightAPI(
            base_url=config["cast_highlight"]["api_url"],
            api_key=config["authentication"]["api_key"],
            company_id=config["cast_highlight"]["company_id"]
        )
        
        # Get application details
        app_id = config["application_id"]
        print(f"🔍 Fetching data for application ID: {app_id}")
        
        # Generate SBOM
        print("🔧 Generating SBOM data...")
        generator = SBOMGenerator(cast_api)
        sbom_data = generator.generate_sbom(app_id)
        
        print(f"✅ SBOM generated with {len(sbom_data['components'])} components")
        
        # Create output directory
        output_dir = "Reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate filename
        app_name = sbom_data.get("metadata", {}).get("application", {}).get("name", "Unknown")
        safe_app_name = "".join(c for c in app_name if c.isalnum() or c in (" ", "-", "_")).rstrip()
        safe_app_name = safe_app_name.replace(" ", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"{safe_app_name}_ID{app_id}_{timestamp}"
        
        # Export CycloneDX formats
        print("📤 Exporting CycloneDX formats...")
        
        # JSON format
        json_filename = os.path.join(output_dir, f"{filename_base}_cyclonedx.json")
        SBOMExporter.export_cyclonedx(sbom_data, json_filename, "json")
        print(f"   ✅ JSON: {json_filename}")
        
        # XML format
        xml_filename = os.path.join(output_dir, f"{filename_base}_cyclonedx.xml")
        SBOMExporter.export_cyclonedx(sbom_data, xml_filename, "xml")
        print(f"   ✅ XML: {xml_filename}")
        
        print(f"\n🎉 CycloneDX SBOM generation completed!")
        print(f"📁 Files saved in: {output_dir}")
        
        # Show sample of generated data
        print(f"\n📊 Sample CycloneDX data:")
        print(f"   - BOM Format: CycloneDX")
        print(f"   - Spec Version: 1.4")
        print(f"   - Components: {len(sbom_data['components'])}")
        
        # Count vulnerabilities
        total_vulns = sum(len(comp.get("vulnerabilities", [])) for comp in sbom_data["components"])
        print(f"   - Total Vulnerabilities: {total_vulns}")
        
        # Show first few components
        print(f"\n📦 First 3 components:")
        for i, comp in enumerate(sbom_data["components"][:3]):
            vuln_count = len(comp.get("vulnerabilities", []))
            print(f"   {i+1}. {comp.get('name', 'Unknown')} v{comp.get('version', 'Unknown')} ({vuln_count} vulns)")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def example_with_sample_data():
    """Example using sample data (no CAST Highlight connection required)"""
    
    print("\n🧪 Example with Sample Data (No CAST Highlight Required)")
    print("=" * 60)
    
    # Sample SBOM data
    sample_sbom = {
        "sbomVersion": "1.0",
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": "CAST Highlight SBOM Generator",
            "version": "1.0",
            "application": {
                "name": "Sample Web Application",
                "version": "2.1.0",
                "description": "A sample web application for demonstration"
            }
        },
        "components": [
            {
                "type": "library",
                "name": "spring-boot-starter-web",
                "version": "2.7.0",
                "description": "Spring Boot web starter",
                "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.7.0",
                "externalReferences": [
                    {
                        "type": "repository",
                        "url": "https://github.com/spring-projects/spring-boot"
                    }
                ],
                "properties": [
                    {"name": "cast:packageType", "value": "maven"},
                    {"name": "cast:criticality", "value": "HIGH"}
                ],
                "supplier": {"name": "Spring Team"},
                "author": "Spring Team",
                "copyright": "Copyright (c) 2012-2022 Spring Team",
                "licenses": [
                    {
                        "licenseId": "Apache-2.0",
                        "name": "Apache License 2.0",
                        "url": "https://www.apache.org/licenses/LICENSE-2.0"
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2022-22965",
                        "description": "Spring4Shell vulnerability",
                        "severity": "CRITICAL",
                        "cvssScore": 9.8,
                        "cweId": "CWE-502",
                        "cpe": "cpe:2.3:a:spring:spring_framework:5.3.0:*:*:*:*:*:*:*:*",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
                    }
                ]
            },
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.17.0",
                "description": "Apache Log4j Core",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
                "externalReferences": [
                    {
                        "type": "repository",
                        "url": "https://github.com/apache/logging-log4j2"
                    }
                ],
                "properties": [
                    {"name": "cast:packageType", "value": "maven"},
                    {"name": "cast:criticality", "value": "MEDIUM"}
                ],
                "supplier": {"name": "Apache Software Foundation"},
                "author": "Apache Software Foundation",
                "copyright": "Copyright (c) 1999-2022 Apache Software Foundation",
                "licenses": [
                    {
                        "licenseId": "Apache-2.0",
                        "name": "Apache License 2.0",
                        "url": "https://www.apache.org/licenses/LICENSE-2.0"
                    }
                ],
                "vulnerabilities": []
            }
        ]
    }
    
    try:
        # Create output directory
        output_dir = "Reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"Sample_App_{timestamp}"
        
        # Export CycloneDX formats
        print("📤 Exporting CycloneDX formats...")
        
        # JSON format
        json_filename = os.path.join(output_dir, f"{filename_base}_cyclonedx.json")
        SBOMExporter.export_cyclonedx(sample_sbom, json_filename, "json")
        print(f"   ✅ JSON: {json_filename}")
        
        # XML format
        xml_filename = os.path.join(output_dir, f"{filename_base}_cyclonedx.xml")
        SBOMExporter.export_cyclonedx(sample_sbom, xml_filename, "xml")
        print(f"   ✅ XML: {xml_filename}")
        
        print(f"\n🎉 Sample CycloneDX SBOM generation completed!")
        print(f"📁 Files saved in: {output_dir}")
        
        # Show sample of generated data
        print(f"\n📊 Sample CycloneDX data:")
        print(f"   - BOM Format: CycloneDX")
        print(f"   - Spec Version: 1.4")
        print(f"   - Components: {len(sample_sbom['components'])}")
        
        # Count vulnerabilities
        total_vulns = sum(len(comp.get("vulnerabilities", [])) for comp in sample_sbom["components"])
        print(f"   - Total Vulnerabilities: {total_vulns}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("CAST Highlight CycloneDX SBOM Generator Examples")
    print("=" * 60)
    
    # Run sample data example (no CAST Highlight required)
    example_with_sample_data()
    
    print("\n" + "=" * 60)
    print("💡 To run the full example with CAST Highlight data:")
    print("   1. Update the config in example_cyclonedx_usage.py")
    print("   2. Uncomment the line below to run example_cyclonedx_generation()")
    print("   3. Run: python tests/example_cyclonedx_usage.py")
    
    # Uncomment the line below to run the full example (requires CAST Highlight credentials)
    # example_cyclonedx_generation()
