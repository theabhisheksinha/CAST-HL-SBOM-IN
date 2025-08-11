#!/usr/bin/env python3
"""
Enhanced SBOM Builder for CAST Highlight
Extracts comprehensive component data from multiple API endpoints
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class SBOMBuilder:
    """
    Enhanced SBOM Builder that transforms CAST Highlight data into comprehensive SBOM structure.
    Extracts data from multiple endpoints to maximize field coverage.
    """
    
    def __init__(self, comprehensive_data: Dict[str, Any]):
        """
        Initialize with comprehensive data from multiple CAST Highlight endpoints
        
        Args:
            comprehensive_data: Dictionary containing data from:
                - third_party: Third-party component data
                - components: Detailed component information
                - vulnerabilities: Security vulnerability data
                - licenses: License information
        """
        self.comprehensive_data = comprehensive_data
        self.components_map = {}  # Map to track components by name+version
        self.vulnerabilities_map = {}  # Map vulnerabilities to components
        self.licenses_map = {}  # Map licenses to components

    def build(self) -> Dict[str, Any]:
        """
        Build comprehensive SBOM from all available data sources
        
        Returns:
            Complete SBOM structure with maximum field coverage
        """
        logger.info("Building comprehensive SBOM from multiple data sources")
        
        sbom = {
            "sbomVersion": "1.0",
            "metadata": self._build_metadata(),
            "components": []
        }
        
        # Process third-party data (primary source)
        if self.comprehensive_data.get('third_party'):
            self._process_third_party_data(sbom)
        
        # Process detailed component data (enrichment)
        if self.comprehensive_data.get('components'):
            self._process_components_data(sbom)
        
        # Process vulnerability data
        if self.comprehensive_data.get('vulnerabilities'):
            self._process_vulnerabilities_data(sbom)
        
        # Process license data
        if self.comprehensive_data.get('licenses'):
            self._process_licenses_data(sbom)
        
        # Final enrichment and validation
        self._enrich_components(sbom)
        
        logger.info(f"SBOM built with {len(sbom['components'])} components")
        return sbom

    def _build_metadata(self) -> Dict[str, Any]:
        """Build SBOM metadata"""
        # Get application name from comprehensive data if available
        app_name = "WebGoat"
        if self.comprehensive_data.get('application_info', {}).get('name'):
            app_name = self.comprehensive_data['application_info']['name']
        
        return {
            "timestamp": datetime.now().isoformat(),
            "tool": "CAST Highlight SBOM Generator",
            "version": "2.0",
            "application": {
                "name": app_name,
                "version": "Unknown",
                "description": "Generated from CAST Highlight data"
            }
        }

    def _process_third_party_data(self, sbom: Dict[str, Any]):
        """Process third-party component data (primary source)"""
        third_party_data = self.comprehensive_data['third_party']
        
        if isinstance(third_party_data, dict) and 'thirdParties' in third_party_data:
            components = third_party_data['thirdParties']
        elif isinstance(third_party_data, list):
            components = third_party_data
        else:
            logger.warning("Unexpected third-party data structure")
            return
        
        for component_data in components:
            sbom_component = self._convert_third_party_component(component_data)
            if sbom_component:
                component_key = f"{sbom_component['name']}_{sbom_component['version']}"
                self.components_map[component_key] = sbom_component
                sbom['components'].append(sbom_component)

    def _process_components_data(self, sbom: Dict[str, Any]):
        """Process detailed component data for enrichment"""
        components_data = self.comprehensive_data['components']
        
        if isinstance(components_data, list):
            components = components_data
        elif isinstance(components_data, dict) and 'components' in components_data:
            components = components_data['components']
        else:
            logger.warning("Unexpected components data structure")
            return
        
        for component_data in components:
            self._enrich_component_with_details(component_data)

    def _process_vulnerabilities_data(self, sbom: Dict[str, Any]):
        """Process vulnerability data and associate with components"""
        vulnerabilities_data = self.comprehensive_data['vulnerabilities']
        
        if isinstance(vulnerabilities_data, list):
            vulnerabilities = vulnerabilities_data
        elif isinstance(vulnerabilities_data, dict) and 'vulnerabilities' in vulnerabilities_data:
            vulnerabilities = vulnerabilities_data['vulnerabilities']
        else:
            logger.warning("Unexpected vulnerabilities data structure")
            return
        
        for vuln_data in vulnerabilities:
            self._associate_vulnerability_with_component(vuln_data)

    def _process_licenses_data(self, sbom: Dict[str, Any]):
        """Process license data and associate with components"""
        licenses_data = self.comprehensive_data['licenses']
        
        if isinstance(licenses_data, list):
            licenses = licenses_data
        elif isinstance(licenses_data, dict) and 'licenses' in licenses_data:
            licenses = licenses_data['licenses']
        else:
            logger.warning("Unexpected licenses data structure")
            return
        
        for license_data in licenses:
            self._associate_license_with_component(license_data)

    def _convert_third_party_component(self, component_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert third-party component data to SBOM format"""
        try:
            # Extract basic component information
            # Ensure description is properly extracted from all possible sources
            description = ""
            if component_data.get("description") and isinstance(component_data.get("description"), str):
                description = component_data.get("description")
            elif component_data.get("componentDescription") and isinstance(component_data.get("componentDescription"), str):
                description = component_data.get("componentDescription")
            elif component_data.get("details", {}).get("description") and isinstance(component_data.get("details", {}).get("description"), str):
                description = component_data.get("details", {}).get("description")
                
            component = {
                "type": "library",
                "name": component_data.get("name", "Unknown"),
                "version": component_data.get("version", "Unknown"),
                "description": description,
                "purl": self._generate_purl(component_data),
                "externalReferences": self._get_external_references(component_data),
                "properties": self._extract_comprehensive_properties(component_data),
                "licenses": [],
                "vulnerabilities": [],
                # Fields that CAST Highlight can provide
                "supplier": {
                    "name": component_data.get("supplier", "Unknown"),
                    "contact": component_data.get("supplierContact", "Unknown")
                },
                # Only include author at SBOM level, not component level
                "copyright": component_data.get("copyright", "Unknown")
            }
            
            # Extract embedded vulnerabilities
            if component_data.get("cve") and component_data["cve"].get("vulnerabilities"):
                for vuln in component_data["cve"]["vulnerabilities"]:
                    component["vulnerabilities"].append(self._convert_vulnerability(vuln))
            
            # Extract embedded licenses
            if component_data.get("licenses"):
                for lic in component_data["licenses"]:
                    component["licenses"].append(self._convert_license(lic))
            
            return component
            
        except Exception as e:
            logger.error(f"Error converting third-party component {component_data.get('name', 'Unknown')}: {e}")
            return None

    def _extract_comprehensive_properties(self, component_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract comprehensive properties from component data"""
        properties = []
        
        # Basic component properties
        if component_data.get("packageType"):
            properties.append({"name": "cast:packageType", "value": str(component_data["packageType"])})
        
        if component_data.get("filePath"):
            properties.append({"name": "cast:filePath", "value": str(component_data["filePath"])})
        
        # Origin and source information
        if component_data.get("origin"):
            properties.append({"name": "cast:origin", "value": str(component_data["origin"])})
        
        if component_data.get("source"):
            properties.append({"name": "cast:source", "value": str(component_data["source"])})
        
        # Dependencies and relationships
        if component_data.get("dependencies"):
            deps = component_data["dependencies"]
            if isinstance(deps, list):
                deps_str = "; ".join([str(dep) for dep in deps])
            else:
                deps_str = str(deps)
            properties.append({"name": "cast:dependencies", "value": deps_str})
        
        # Release and lifecycle information
        if component_data.get("releaseDate"):
            properties.append({"name": "cast:releaseDate", "value": str(component_data["releaseDate"])})
        
        # Check multiple possible sources for EOL date
        eol_date = None
        if component_data.get("eolDate"):
            eol_date = component_data["eolDate"]
        elif component_data.get("endOfLifeDate"):
            eol_date = component_data["endOfLifeDate"]
        elif component_data.get("endOfLife"):
            eol_date = component_data["endOfLife"]
        elif component_data.get("details", {}).get("eolDate"):
            eol_date = component_data["details"]["eolDate"]
            
        if eol_date:
            properties.append({"name": "cast:eolDate", "value": str(eol_date)})
        
        if component_data.get("lastVersion"):
            properties.append({"name": "cast:lastVersion", "value": str(component_data["lastVersion"])})
        
        # Security and criticality information
        if component_data.get("criticality"):
            properties.append({"name": "cast:criticality", "value": str(component_data["criticality"])})
        
        if component_data.get("riskLevel"):
            properties.append({"name": "cast:riskLevel", "value": str(component_data["riskLevel"])})
        
        # Usage and compliance information
        if component_data.get("usageRestrictions"):
            properties.append({"name": "cast:usageRestrictions", "value": str(component_data["usageRestrictions"])})
        
        if component_data.get("compliance"):
            properties.append({"name": "cast:compliance", "value": str(component_data["compliance"])})
        
        # Checksums and integrity information
        if component_data.get("checksum"):
            properties.append({"name": "cast:checksum", "value": str(component_data["checksum"])})
        
        if component_data.get("hash"):
            properties.append({"name": "cast:hash", "value": str(component_data["hash"])})
            
        # Add fingerprint as hash if available
        if component_data.get("fingerprint"):
            properties.append({"name": "cast:fingerprint", "value": str(component_data["fingerprint"])})
            
        # Add SHA1, SHA256, MD5 if available
        if component_data.get("sha1"):
            properties.append({"name": "cast:sha1", "value": str(component_data["sha1"])})
            
        if component_data.get("sha256"):
            properties.append({"name": "cast:sha256", "value": str(component_data["sha256"])})
            
        if component_data.get("md5"):
            properties.append({"name": "cast:md5", "value": str(component_data["md5"])})
        
        # Comments and notes
        if component_data.get("comments"):
            properties.append({"name": "cast:comments", "value": str(component_data["comments"])})
        
        if component_data.get("notes"):
            properties.append({"name": "cast:notes", "value": str(component_data["notes"])})
        
        # Component properties
        if component_data.get("isExecutable"):
            properties.append({"name": "cast:executable", "value": "Yes" if component_data["isExecutable"] else "No"})
        
        if component_data.get("isArchive"):
            properties.append({"name": "cast:archive", "value": "Yes" if component_data["isArchive"] else "No"})
        
        if component_data.get("isStructured"):
            properties.append({"name": "cast:structured", "value": "Yes" if component_data["isStructured"] else "No"})
        
        # Patch status
        if component_data.get("patchStatus"):
            properties.append({"name": "cast:patchStatus", "value": str(component_data["patchStatus"])})
        
        # Languages and technologies
        if component_data.get("languages"):
            langs = component_data["languages"]
            if isinstance(langs, list):
                langs_str = "; ".join([str(lang) for lang in langs])
            else:
                langs_str = str(langs)
            properties.append({"name": "cast:languages", "value": langs_str})
        
        return properties

    def _generate_purl(self, component_data: Dict[str, Any]) -> str:
        """Generate Package URL (PURL) for component"""
        name = component_data.get("name", "")
        version = component_data.get("version", "")
        package_type = component_data.get("packageType", "generic")
        
        # Clean name for PURL
        name = name.replace(" ", "-").lower()
        
        if package_type == "maven":
            return f"pkg:maven/{name}@{version}"
        elif package_type == "npm":
            return f"pkg:npm/{name}@{version}"
        elif package_type == "nuget":
            return f"pkg:nuget/{name}@{version}"
        elif package_type == "pypi":
            return f"pkg:pypi/{name}@{version}"
        elif package_type == "gem":
            return f"pkg:gem/{name}@{version}"
        elif package_type == "cargo":
            return f"pkg:cargo/{name}@{version}"
        else:
            return f"pkg:generic/{name}@{version}"

    def _get_external_references(self, component_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get external references for component"""
        references = []
        
        if component_data.get("repositoryUrl"):
            references.append({"type": "repository", "url": str(component_data["repositoryUrl"])})
        
        if component_data.get("homepageUrl"):
            references.append({"type": "website", "url": str(component_data["homepageUrl"])})
        
        if component_data.get("documentationUrl"):
            references.append({"type": "documentation", "url": str(component_data["documentationUrl"])})
        
        if component_data.get("downloadUrl"):
            references.append({"type": "download", "url": str(component_data["downloadUrl"])})
        
        return references

    def _convert_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert vulnerability data to standard format"""
        return {
            "id": vuln_data.get("name", "Unknown"),
            "description": vuln_data.get("description", ""),
            "severity": vuln_data.get("criticity", "Unknown"),
            "cvssScore": vuln_data.get("cvssScore"),
            "cweId": vuln_data.get("cweId"),
            "cpe": vuln_data.get("cpe"),
            "isKev": vuln_data.get("isKev", False),
            "link": vuln_data.get("link", ""),
            "publishedDate": vuln_data.get("publishedDate"),
            "patchStatus": vuln_data.get("patchStatus", "Unknown")
        }

    def _convert_license(self, license_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert license data to standard format"""
        return {
            "licenseId": license_data.get("name", "Unknown"),
            "name": license_data.get("name", "Unknown"),
            "url": license_data.get("url", ""),
            "compliance": license_data.get("compliance", "Unknown"),
            "type": license_data.get("type", ""),
            "text": license_data.get("text", "")
        }

    def _enrich_component_with_details(self, component_data: Dict[str, Any]):
        """Enrich existing component with additional details"""
        component_name = component_data.get("name")
        component_version = component_data.get("version")
        
        if not component_name or not component_version:
            return
        
        component_key = f"{component_name}_{component_version}"
        if component_key in self.components_map:
            # Add additional properties from detailed component data
            additional_properties = self._extract_comprehensive_properties(component_data)
            existing_properties = self.components_map[component_key]["properties"]
            
            # Merge properties, avoiding duplicates
            existing_prop_names = {prop["name"] for prop in existing_properties}
            for prop in additional_properties:
                if prop["name"] not in existing_prop_names:
                    existing_properties.append(prop)

    def _associate_vulnerability_with_component(self, vuln_data: Dict[str, Any]):
        """Associate vulnerability with component"""
        component_name = vuln_data.get("componentName")
        component_version = vuln_data.get("componentVersion")
        
        if not component_name:
            return
        
        # Try exact match first
        component_key = f"{component_name}_{component_version}" if component_version else component_name
        
        # Find matching component
        for component in self.components_map.values():
            if (component["name"] == component_name and 
                (not component_version or component["version"] == component_version)):
                component["vulnerabilities"].append(self._convert_vulnerability(vuln_data))
                break

    def _associate_license_with_component(self, license_data: Dict[str, Any]):
        """Associate license with component"""
        component_name = license_data.get("componentName")
        component_version = license_data.get("componentVersion")
        
        if not component_name:
            return
        
        # Find matching component
        for component in self.components_map.values():
            if (component["name"] == component_name and 
                (not component_version or component["version"] == component_version)):
                component["licenses"].append(self._convert_license(license_data))
                break

    def _enrich_components(self, sbom: Dict[str, Any]):
        """Final enrichment and validation of all components"""
        for component in sbom["components"]:
            # Ensure all required fields are present
            if not component.get("name"):
                component["name"] = "Unknown"
            if not component.get("version"):
                component["version"] = "Unknown"
            
            # Remove timestamp at component level as it's not required
            if "timestamp" in component:
                del component["timestamp"]
            
            # Remove author field at component level as it's not required
            if "author" in component:
                del component["author"]
            
            # Ensure arrays are present
            if not component.get("licenses"):
                component["licenses"] = []
            if not component.get("vulnerabilities"):
                component["vulnerabilities"] = []
            if not component.get("properties"):
                component["properties"] = []
            if not component.get("externalReferences"):
                component["externalReferences"] = []
                
            # Ensure component properties are consistent
            self._normalize_component_properties(component)
            
    def _normalize_component_properties(self, component: Dict[str, Any]):
        """Normalize component properties to ensure consistency"""
        # Create a map of existing properties for easy lookup
        property_map = {}
        for prop in component.get("properties", []):
            property_map[prop["name"]] = prop["value"]
            
        # Ensure critical properties are present with correct values
        # Check for checksums/hashes
        if "cast:fingerprint" not in property_map and "cast:hash" not in property_map and "cast:checksum" not in property_map:
            # Try to extract from other fields
            if component.get("fingerprint"):
                component["properties"].append({"name": "cast:fingerprint", "value": str(component["fingerprint"])})
            elif component.get("hash"):
                component["properties"].append({"name": "cast:hash", "value": str(component["hash"])})
                
        # Ensure EOL date is present if available
        if "cast:eolDate" not in property_map and component.get("eolDate"):
            component["properties"].append({"name": "cast:eolDate", "value": str(component["eolDate"])})
            
        # Ensure description is properly set
        if not component.get("description") and "cast:description" in property_map:
            component["description"] = property_map["cast:description"]
            
        # Ensure copyright is properly set
        if component.get("copyright") == "Unknown" and "cast:copyright" in property_map:
            component["copyright"] = property_map["cast:copyright"]