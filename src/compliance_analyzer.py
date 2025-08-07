#!/usr/bin/env python3
"""
SBOM Compliance Analyzer
This script analyzes SBOM data against compliance requirements and provides
detailed reporting on mandatory field coverage.
"""

import json
import sys
from typing import Dict, List, Tuple
from datetime import datetime

class SBOMComplianceAnalyzer:
    """Analyze SBOM compliance with mandatory requirements"""
    
    def __init__(self):
        # Define mandatory fields based on typical SBOM standards
        self.mandatory_fields = {
            "component_identification": [
                "name",
                "version", 
                "type",
                "purl"
            ],
            "license_information": [
                "license_id",
                "license_name",
                "license_url"
            ],
            "security_information": [
                "vulnerability_id",
                "severity",
                "cvss_score"
            ],
            "source_information": [
                "repository_url",
                "source_location"
            ],
            "metadata": [
                "timestamp",
                "tool_info",
                "application_context"
            ]
        }
        
        # Fields that CAST Highlight can provide
        self.cast_available_fields = [
            "name", "version", "type", "purl",
            "license_id", "license_name", "license_url",
            "vulnerability_id", "severity", "cvss_score",
            "repository_url", "source_location",
            "timestamp", "tool_info", "application_context"
        ]
        
        # Fields that CAST Highlight cannot provide
        self.cast_unavailable_fields = [
            "supplier_name", "supplier_contact",
            "author", "copyright",
            "build_tools", "build_environment",
            "distribution_method", "packaging_info",
            "usage_context", "component_usage"
        ]
    
    def analyze_sbom_file(self, sbom_file: str) -> Dict:
        """Analyze a specific SBOM file for compliance"""
        try:
            with open(sbom_file, 'r') as f:
                sbom_data = json.load(f)
            
            return self.analyze_sbom_data(sbom_data)
        except FileNotFoundError:
            print(f"Error: SBOM file '{sbom_file}' not found")
            return {}
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in SBOM file '{sbom_file}'")
            return {}
    
    def analyze_sbom_data(self, sbom_data: Dict) -> Dict:
        """Analyze SBOM data structure for compliance"""
        
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "overall_compliance": 0.0,
            "field_coverage": {},
            "missing_fields": [],
            "available_fields": [],
            "unavailable_fields": [],
            "recommendations": []
        }
        
        # Analyze metadata
        metadata_analysis = self._analyze_metadata(sbom_data.get("metadata", {}))
        analysis["field_coverage"]["metadata"] = metadata_analysis
        
        # Analyze components
        components_analysis = self._analyze_components(sbom_data.get("components", []))
        analysis["field_coverage"]["components"] = components_analysis
        
        # Calculate overall compliance
        total_fields = len(self.cast_available_fields) + len(self.cast_unavailable_fields)
        available_coverage = len(self.cast_available_fields) / total_fields
        analysis["overall_compliance"] = available_coverage * 100
        
        # Generate recommendations
        analysis["recommendations"] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_metadata(self, metadata: Dict) -> Dict:
        """Analyze metadata section"""
        analysis = {
            "present_fields": [],
            "missing_fields": [],
            "coverage_percentage": 0.0
        }
        
        required_metadata = ["timestamp", "tool", "version"]
        
        for field in required_metadata:
            if field in metadata and metadata[field]:
                analysis["present_fields"].append(field)
            else:
                analysis["missing_fields"].append(field)
        
        analysis["coverage_percentage"] = len(analysis["present_fields"]) / len(required_metadata) * 100
        return analysis
    
    def _analyze_components(self, components: List[Dict]) -> Dict:
        """Analyze components section"""
        analysis = {
            "total_components": len(components),
            "components_with_licenses": 0,
            "components_with_vulnerabilities": 0,
            "components_with_supplier_info": 0,
            "components_with_author_info": 0,
            "components_with_copyright_info": 0,
            "field_coverage": {}
        }
        
        if not components:
            return analysis
        
        # Analyze each component
        for component in components:
            if component.get("licenses"):
                analysis["components_with_licenses"] += 1
            if component.get("vulnerabilities"):
                analysis["components_with_vulnerabilities"] += 1
            if component.get("supplier", {}).get("name") and component["supplier"]["name"] != "Unavailable from CAST Highlight":
                analysis["components_with_supplier_info"] += 1
            if component.get("author") and component["author"] != "Unavailable from CAST Highlight":
                analysis["components_with_author_info"] += 1
            if component.get("copyright") and component["copyright"] != "Unavailable from CAST Highlight":
                analysis["components_with_copyright_info"] += 1
        
        # Calculate percentages
        analysis["field_coverage"] = {
            "licenses": analysis["components_with_licenses"] / len(components) * 100,
            "vulnerabilities": analysis["components_with_vulnerabilities"] / len(components) * 100,
            "supplier_info": analysis["components_with_supplier_info"] / len(components) * 100,
            "author_info": analysis["components_with_author_info"] / len(components) * 100,
            "copyright_info": analysis["components_with_copyright_info"] / len(components) * 100
        }
        
        return analysis
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        overall_compliance = analysis["overall_compliance"]
        
        if overall_compliance < 50:
            recommendations.append("Critical: Overall compliance is below 50%. Consider manual data supplementation.")
        elif overall_compliance < 75:
            recommendations.append("Warning: Overall compliance is below 75%. Review missing fields.")
        else:
            recommendations.append("Good: Overall compliance is above 75%.")
        
        # Component-specific recommendations
        components_analysis = analysis["field_coverage"].get("components", {})
        
        if components_analysis.get("supplier_info", 0) < 10:
            recommendations.append("Add supplier information manually for better compliance.")
        
        if components_analysis.get("author_info", 0) < 10:
            recommendations.append("Add author information manually for better compliance.")
        
        if components_analysis.get("copyright_info", 0) < 10:
            recommendations.append("Add copyright information manually for better compliance.")
        
        recommendations.append("Consider integrating with additional tools for complete field coverage.")
        recommendations.append("Document manual supplementation process for audit purposes.")
        
        return recommendations
    
    def generate_compliance_report(self, analysis: Dict, output_file: str | None = None):
        """Generate a detailed compliance report"""
        
        report = f"""
SBOM Compliance Analysis Report
Generated: {analysis.get('timestamp', 'Unknown')}
{'='*50}

OVERALL COMPLIANCE: {analysis.get('overall_compliance', 0):.1f}%

CAST Highlight API Coverage Analysis:
{'='*50}

✅ Fields that CAST Highlight CAN provide ({len(self.cast_available_fields)} fields):
"""
        
        for field in self.cast_available_fields:
            report += f"  - {field}\n"
        
        report += f"""
❌ Fields that CAST Highlight CANNOT provide ({len(self.cast_unavailable_fields)} fields):
"""
        
        for field in self.cast_unavailable_fields:
            report += f"  - {field}\n"
        
        # Add component analysis
        components_analysis = analysis.get("field_coverage", {}).get("components", {})
        if components_analysis:
            report += f"""
Component Analysis:
{'='*50}
Total Components: {components_analysis.get('total_components', 0)}

Field Coverage:
  - Components with licenses: {components_analysis.get('components_with_licenses', 0)} ({components_analysis.get('field_coverage', {}).get('licenses', 0):.1f}%)
  - Components with vulnerabilities: {components_analysis.get('components_with_vulnerabilities', 0)} ({components_analysis.get('field_coverage', {}).get('vulnerabilities', 0):.1f}%)
  - Components with supplier info: {components_analysis.get('components_with_supplier_info', 0)} ({components_analysis.get('field_coverage', {}).get('supplier_info', 0):.1f}%)
  - Components with author info: {components_analysis.get('components_with_author_info', 0)} ({components_analysis.get('field_coverage', {}).get('author_info', 0):.1f}%)
  - Components with copyright info: {components_analysis.get('components_with_copyright_info', 0)} ({components_analysis.get('field_coverage', {}).get('copyright_info', 0):.1f}%)

"""
        
        # Add recommendations
        recommendations = analysis.get("recommendations", [])
        if recommendations:
            report += f"""
Recommendations:
{'='*50}
"""
            for i, rec in enumerate(recommendations, 1):
                report += f"{i}. {rec}\n"
        
        report += f"""
Compliance Summary:
{'='*50}
- CAST Highlight provides {len(self.cast_available_fields)} out of {len(self.cast_available_fields) + len(self.cast_unavailable_fields)} mandatory fields
- Coverage: {len(self.cast_available_fields)/(len(self.cast_available_fields) + len(self.cast_unavailable_fields))*100:.1f}%
- Manual supplementation required for {len(self.cast_unavailable_fields)} fields

Note: This analysis is based on typical SBOM requirements. 
Please refer to your specific regulatory framework for exact compliance requirements.
"""
        
        if output_file is not None:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"Compliance report saved to {output_file}")
        else:
            print(report)
        
        return report

def main():
    """Main function for compliance analysis"""
    
    if len(sys.argv) < 2:
        print("Usage: python compliance_analyzer.py <sbom_file.json> [output_report.txt]")
        print("\nExample:")
        print("  python compliance_analyzer.py sbom.json")
        print("  python compliance_analyzer.py sbom.json compliance_report.txt")
        sys.exit(1)
    
    sbom_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    analyzer = SBOMComplianceAnalyzer()
    
    print(f"Analyzing SBOM file: {sbom_file}")
    analysis = analyzer.analyze_sbom_file(sbom_file)
    
    if analysis:
        analyzer.generate_compliance_report(analysis, output_file)
    else:
        print("Analysis failed. Please check the SBOM file format.")

if __name__ == "__main__":
    main() 