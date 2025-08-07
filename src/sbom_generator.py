#!/usr/bin/env python3
"""
SBOM Generator for CAST Highlight Compliance
This application extracts software component data from CAST Highlight API
and generates SBOM (Software Bill of Materials) compliant with industry standards.
"""

import requests
import json
import csv
import sys
from datetime import datetime
from typing import Dict, List, Optional
import logging
import os
import subprocess

# For new output formats
try:
    import openpyxl  # For Excel
    from openpyxl import styles
except ImportError:
    openpyxl = None
    styles = None
try:
    from docx import Document  # For DOCX
except ImportError:
    Document = None

# Create logs directory if it doesn't exist
logs_dir = "logs"
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

# Create log file with date and time
log_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(logs_dir, f"sbom_{log_timestamp}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# CycloneDX support (JSON/XML)
try:
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType
except ImportError as e:
    Bom = None
    Component = None
    ComponentType = None
    logger.error(
        f"cyclonedx-python-lib is not installed or import failed: {e}. Cannot export CycloneDX."
    )


def load_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        logger.error(f"Config file {config_path} not found.")
        sys.exit(1)
    with open(config_path, "r") as f:
        config = json.load(f)
    return config


class HighlightAPI:
    """Client for CAST Highlight API"""

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        company_id: str | None = None,
    ):
        # Accept base_url with or without /WS2, but do not append /WS2 if already present
        base_url = base_url.rstrip("/")
        if not base_url.endswith("/WS2"):
            base_url = base_url + "/WS2"
        self.base_url = base_url
        self.username = username
        self.password = password
        self.api_key = api_key
        self.company_id = company_id
        self.access_token = None

        # Initialize headers
        self.headers = {"Content-Type": "application/json"}

        # Authenticate if credentials provided
        if username and password:
            self._authenticate_with_credentials()
        elif api_key:
            self._authenticate_with_api_key()

    def _authenticate_with_credentials(self):
        """Authenticate using username/password with Basic HTTP Authentication"""
        try:
            # Use Basic HTTP Authentication instead of token-based auth
            from requests.auth import HTTPBasicAuth

            if self.username and self.password:
                self.auth = HTTPBasicAuth(self.username, self.password)
                logger.info(
                    "Successfully set up Basic HTTP Authentication with username/password"
                )
            else:
                raise Exception(
                    "Username and password are required for Basic HTTP Authentication"
                )

        except Exception as e:
            logger.error(f"Authentication setup failed: {e}")
            raise Exception(f"Authentication setup failed: {e}")

    def _authenticate_with_api_key(self):
        """Authenticate using API key"""
        self.headers["Authorization"] = f"Bearer {self.api_key}"
        logger.info("Using API key authentication")

    def get_applications(self) -> List[Dict]:
        """Get list of applications from CAST Highlight"""
        try:
            url = f"{self.base_url}/domains/{self.company_id}/applications/"
            # Use auth parameter for Basic HTTP Authentication
            response = requests.get(
                url, headers=self.headers, auth=getattr(self, "auth", None)
            )
            response.raise_for_status()
            data = response.json()
            # Ensure we return a list
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "applications" in data:
                return data["applications"]
            else:
                logger.warning(f"Unexpected applications data structure: {type(data)}")
                return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get applications: {e}")
            return []

    def get_application_details(self, app_id: str) -> Optional[Dict]:
        """Get detailed information about a specific application"""
        try:
            url = f"{self.base_url}/domains/{self.company_id}/applications/{app_id}"
            response = requests.get(
                url, headers=self.headers, auth=getattr(self, "auth", None)
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get application details for {app_id}: {e}")
            return None

    def get_components(self, app_id: str) -> List[Dict]:
        """Get components/dependencies for an application"""
        # Try the dependencies endpoint first (based on API documentation)
        try:
            url = f"{self.base_url}/domains/{self.company_id}/applications/{app_id}/dependencies"
            response = requests.get(
                url, headers=self.headers, auth=getattr(self, "auth", None)
            )
            response.raise_for_status()
            data = response.json()

            # Handle different response structures
            if isinstance(data, dict) and "dependencies" in data:
                return data["dependencies"]
            elif isinstance(data, dict) and "thirdParties" in data:
                return data["thirdParties"]
            elif isinstance(data, list):
                return data
            else:
                logger.warning(f"Unexpected component data structure for {app_id}")
                return []

        except requests.exceptions.RequestException as e:
            logger.warning(f"Dependencies endpoint failed for {app_id}: {e}")

            # Fallback to thirdparty endpoint
            try:
                url = f"{self.base_url}/domains/{self.company_id}/applications/{app_id}/thirdparty"
                response = requests.get(
                    url, headers=self.headers, auth=getattr(self, "auth", None)
                )
                response.raise_for_status()
                data = response.json()
                if isinstance(data, dict) and "thirdParties" in data:
                    return data["thirdParties"]
                elif isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return [data]
                return []
            except requests.exceptions.RequestException as e2:
                logger.error(
                    f"Both dependencies and thirdparty endpoints failed for {app_id}: {e2}"
                )
                return []

    def get_vulnerabilities(self, app_id: str) -> List[Dict]:
        """Get security vulnerabilities for an application"""
        # Use the aggregated vulnerabilities endpoint
        try:
            url = f"{self.base_url}/domains/{self.company_id}/applications/{app_id}/vulnerabilities/aggregated/"
            response = requests.get(
                url, headers=self.headers, auth=getattr(self, "auth", None)
            )
            response.raise_for_status()
            data = response.json()

            # If the response contains vulnerabilities in a nested structure, extract them
            if isinstance(data, dict) and "vulnerabilities" in data:
                return data["vulnerabilities"]
            elif isinstance(data, list):
                return data
            else:
                logger.warning(f"Unexpected vulnerability data structure for {app_id}")
                return []

        except requests.exceptions.RequestException as e:
            logger.warning(
                f"Aggregated vulnerabilities endpoint failed for {app_id}: {e}"
            )

            # Fallback to regular vulnerabilities endpoint
            try:
                url = f"{self.base_url}/domains/{self.company_id}/applications/{app_id}/vulnerabilities"
                response = requests.get(
                    url, headers=self.headers, auth=getattr(self, "auth", None)
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e2:
                logger.warning(
                    f"Regular vulnerabilities endpoint also failed for {app_id}: {e2}"
                )

                # Final fallback to CVE endpoint
                try:
                    url = f"{self.base_url}/domains/{self.company_id}/applications/{app_id}/cve"
                    response = requests.get(
                        url, headers=self.headers, auth=getattr(self, "auth", None)
                    )
                    response.raise_for_status()
                    return response.json()
                except requests.exceptions.RequestException as e3:
                    logger.error(
                        f"All vulnerability endpoints failed for {app_id}: {e3}"
                    )
                    return []

    def get_licenses(self, app_id: str) -> List[Dict]:
        """Get license information for an application"""
        try:
            url = f"{self.base_url}/domains/{self.company_id}/applications/{app_id}/licenses"
            response = requests.get(
                url, headers=self.headers, auth=getattr(self, "auth", None)
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get licenses for {app_id}: {e}")
            return []


class SBOMGenerator:
    """Generate SBOM data from CAST Highlight information"""

    def __init__(self, cast_api: HighlightAPI):
        self.cast_api = cast_api
        self.sbom_data = {
            "sbomVersion": "1.0",
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "tool": "CAST Highlight SBOM Generator",
                "version": "1.0",
            },
            "components": [],
        }

    def generate_sbom(self, app_id: str) -> Dict:
        """Generate complete SBOM for an application"""
        logger.info(f"Generating SBOM for application {app_id}")

        # Get application details
        app_details = self.cast_api.get_application_details(app_id)
        if app_details:
            self.sbom_data["metadata"]["application"] = {
                "name": app_details.get("name", "Unknown"),
                "version": app_details.get("version", "Unknown"),
                "description": app_details.get("description", ""),
            }

        # Get components
        components = self.cast_api.get_components(app_id)
        for component in components:
            sbom_component = self._convert_to_sbom_component(component)
            if sbom_component:
                self.sbom_data["components"].append(sbom_component)

        # Get vulnerabilities and add to components
        vulnerabilities = self.cast_api.get_vulnerabilities(app_id)
        self._add_vulnerabilities_to_components(vulnerabilities)

        # Get licenses and add to components
        licenses = self.cast_api.get_licenses(app_id)
        self._add_licenses_to_components(licenses)

        logger.info(
            f"Generated SBOM with {len(self.sbom_data['components'])} components"
        )
        return self.sbom_data

    def _convert_to_sbom_component(self, cast_component: Dict) -> Optional[Dict]:
        """Convert CAST Highlight component to SBOM format"""
        try:
            # Extract vulnerabilities from component's cve field
            vulnerabilities = []
            if cast_component.get("cve") and cast_component["cve"].get(
                "vulnerabilities"
            ):
                for vuln in cast_component["cve"]["vulnerabilities"]:
                    vulnerabilities.append(
                        {
                            "id": vuln.get("name", "Unknown"),
                            "description": vuln.get("description", ""),
                            "severity": vuln.get("criticity", "Unknown"),
                            "cvssScore": vuln.get("cvssScore"),
                            "cweId": vuln.get("cweId"),
                            "cpe": vuln.get("cpe"),
                            "isKev": vuln.get("isKev", False),
                            "link": vuln.get("link", ""),
                        }
                    )

            return {
                "type": "library",
                "name": cast_component.get("name", "Unknown"),
                "version": cast_component.get("version", "Unknown"),
                "description": cast_component.get("description", ""),
                "purl": self._generate_purl(cast_component),
                "externalReferences": self._get_external_references(cast_component),
                "properties": self._get_component_properties(cast_component),
                # Fields that CAST Highlight cannot provide (marked as unavailable)
                "supplier": {
                    "name": "Unavailable from CAST Highlight",
                    "contact": "Unavailable from CAST Highlight",
                },
                "author": "Unavailable from CAST Highlight",
                "copyright": "Unavailable from CAST Highlight",
                "licenses": [],  # Will be populated later
                "vulnerabilities": vulnerabilities,  # Extract from component's cve field
            }
        except Exception as e:
            logger.error(
                f"Error converting component {cast_component.get('name', 'Unknown')}: {e}"
            )
            return None

    def _generate_purl(self, component: Dict) -> str:
        """Generate Package URL (PURL) for component"""
        name = component.get("name", "")
        version = component.get("version", "")
        package_type = component.get("packageType", "generic")

        if package_type == "maven":
            return f"pkg:maven/{name}@{version}"
        elif package_type == "npm":
            return f"pkg:npm/{name}@{version}"
        elif package_type == "nuget":
            return f"pkg:nuget/{name}@{version}"
        elif package_type == "pypi":
            return f"pkg:pypi/{name}@{version}"
        else:
            return f"pkg:generic/{name}@{version}"

    def _get_external_references(self, component: Dict) -> List[Dict]:
        """Get external references for component"""
        references = []

        if component.get("repositoryUrl"):
            references.append({"type": "repository", "url": component["repositoryUrl"]})

        if component.get("homepageUrl"):
            references.append({"type": "website", "url": component["homepageUrl"]})

        return references

    def _get_component_properties(self, component: Dict) -> List[Dict]:
        """Get component properties"""
        properties = []

        # Add CAST Highlight specific properties
        if component.get("packageType"):
            properties.append(
                {"name": "cast:packageType", "value": component["packageType"]}
            )

        if component.get("filePath"):
            properties.append({"name": "cast:filePath", "value": component["filePath"]})

        return properties

    def _add_vulnerabilities_to_components(self, vulnerabilities: List[Dict]):
        """Add vulnerability information to components"""
        for vuln in vulnerabilities:
            component_name = vuln.get("componentName")
            if component_name:
                # Find matching component
                for component in self.sbom_data["components"]:
                    if component["name"] == component_name:
                        component["vulnerabilities"].append(
                            {
                                "id": vuln.get("cveId", "Unknown"),
                                "description": vuln.get("description", ""),
                                "severity": vuln.get("severity", "Unknown"),
                                "cvssScore": vuln.get("cvssScore"),
                                "publishedDate": vuln.get("publishedDate"),
                                "references": vuln.get("references", []),
                            }
                        )
                        break

    def _add_licenses_to_components(self, licenses: List[Dict]):
        """Add license information to components"""
        for license_info in licenses:
            component_name = license_info.get("componentName")
            if component_name:
                # Find matching component
                for component in self.sbom_data["components"]:
                    if component["name"] == component_name:
                        component["licenses"].append(
                            {
                                "licenseId": license_info.get("licenseId", "Unknown"),
                                "name": license_info.get("licenseName", "Unknown"),
                                "url": license_info.get("licenseUrl", ""),
                                "compliance": license_info.get("compliance", "Unknown"),
                            }
                        )
                        break


class SBOMExporter:
    """Export SBOM data in various formats"""

    @staticmethod
    def export_json(sbom_data: Dict, filename: str):
        # Ensure all fields present in Excel export are included in JSON
        for component in sbom_data["components"]:
            properties = {
                prop.get("name", ""): prop.get("value", "")
                for prop in component.get("properties", [])
            }
            # Add all Excel fields to the component dict if not present
            component["supplier_name"] = component.get("supplier", {}).get("name", "")
            component["component_license"] = "; ".join(
                [lic.get("name", "") for lic in component.get("licenses", [])]
            )
            component["component_origin"] = properties.get("cast:origin", "Unknown")
            component["component_dependencies"] = properties.get(
                "cast:dependencies", "Unknown"
            )
            component["vulnerabilities_count"] = str(
                len(component.get("vulnerabilities", []))
            )
            component["patch_status"] = properties.get("cast:patchStatus", "Unknown")
            component["release_date"] = properties.get("cast:releaseDate", "")
            component["eol_date"] = properties.get("cast:eolDate", "")
            component["criticality"] = properties.get("cast:criticality", "Unknown")
            component["usage_restrictions"] = properties.get(
                "cast:usageRestrictions", "None"
            )
            component["checksums"] = properties.get("cast:checksum", "")
            component["comments"] = properties.get("cast:comments", "")
            component["author_of_sbom_data"] = component.get("author", "")
            component["timestamp"] = sbom_data.get("metadata", {}).get("timestamp", "")
            component["executable_property"] = properties.get("cast:executable", "No")
            component["archive_property"] = properties.get("cast:archive", "No")
            component["structured_property"] = properties.get("cast:structured", "No")
            component["external_references"] = "; ".join(
                [ref.get("url", "") for ref in component.get("externalReferences", [])]
            )
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)
        logger.info(f"SBOM exported to {filename}")

    @staticmethod
    def export_csv(sbom_data: Dict, filename: str):
        """Export SBOM as CSV with all baseline fields (parity with Excel export)"""
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header (same as Components Complete in Excel)
            writer.writerow(
                [
                    "Component Name",
                    "Component Version",
                    "Component Description",
                    "Component Supplier",
                    "Component License",
                    "Component Origin",
                    "Component Dependencies",
                    "Vulnerabilities Count",
                    "Patch Status",
                    "Release Date",
                    "End-of-Life (EOL) Date",
                    "Criticality",
                    "Usage Restrictions",
                    "Checksums or Hashes",
                    "Comments or Notes",
                    "Author of SBOM Data",
                    "Timestamp",
                    "Executable Property",
                    "Archive Property",
                    "Structured Property",
                    "Unique Identifier (PURL)",
                    "Component Type",
                    "Copyright",
                    "External References",
                ]
            )
            for component in sbom_data["components"]:
                properties = {
                    prop.get("name", ""): prop.get("value", "")
                    for prop in component.get("properties", [])
                }
                writer.writerow(
                    [
                        component.get("name", ""),
                        component.get("version", ""),
                        component.get("description", ""),
                        component.get("supplier", {}).get("name", ""),
                        "; ".join(
                            [
                                lic.get("name", "")
                                for lic in component.get("licenses", [])
                            ]
                        ),
                        properties.get("cast:origin", "Unknown"),
                        properties.get("cast:dependencies", "Unknown"),
                        str(len(component.get("vulnerabilities", []))),
                        properties.get("cast:patchStatus", "Unknown"),
                        properties.get("cast:releaseDate", ""),
                        properties.get("cast:eolDate", ""),
                        properties.get("cast:criticality", "Unknown"),
                        properties.get("cast:usageRestrictions", "None"),
                        properties.get("cast:checksum", ""),
                        properties.get("cast:comments", ""),
                        component.get("author", ""),
                        sbom_data.get("metadata", {}).get("timestamp", ""),
                        properties.get("cast:executable", "No"),
                        properties.get("cast:archive", "No"),
                        properties.get("cast:structured", "No"),
                        component.get("purl", ""),
                        component.get("type", ""),
                        component.get("copyright", ""),
                        "; ".join(
                            [
                                ref.get("url", "")
                                for ref in component.get("externalReferences", [])
                            ]
                        ),
                    ]
                )
        logger.info(f"SBOM exported to {filename}")

    @staticmethod
    def export_spdx(sbom_data: Dict, filename: str):
        """Export SBOM in SPDX format with license ID filtering and robust error handling"""
        try:
            def is_valid_spdx_license_id(license_id):
                # SPDX license IDs are usually at least 3 characters and alphanumeric (e.g., MIT, Apache-2.0)
                # This can be improved with a full SPDX list if needed
                return isinstance(license_id, str) and len(license_id) > 2 and all(c.isalnum() or c in ['-', '.'] for c in license_id)

            spdx_content = f"""SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: {sbom_data.get('metadata', {}).get('application', {}).get('name', 'Unknown Application')} SBOM
DocumentNamespace: http://spdx.org/spdxdocs/cast-highlight-sbom-{datetime.now().strftime('%Y%m%d-%H%M%S')}
Creator: Tool: CAST Highlight SBOM Generator
Created: {datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')}

"""

            for i, component in enumerate(sbom_data["components"], 1):
                # Filter license IDs
                license_ids = [lic.get('licenseId', 'NOASSERTION') for lic in component.get('licenses', [])]
                filtered_license_ids = [lid for lid in license_ids if is_valid_spdx_license_id(lid)]
                if not filtered_license_ids:
                    filtered_license_ids = ['NOASSERTION']

                spdx_content += f"""PackageName: {component.get('name', 'Unknown')}
SPDXID: SPDXRef-Package-{i}
PackageVersion: {component.get('version', 'Unknown')}
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: {'; '.join(filtered_license_ids)}
PackageLicenseDeclared: {'; '.join(filtered_license_ids)}
PackageCopyrightText: {component.get('copyright', 'NOASSERTION')}
PackageDescription: {component.get('description', 'NOASSERTION')}

"""

            with open(filename, "w", encoding="utf-8") as f:
                f.write(spdx_content)

            logger.info(f"SBOM exported to {filename}")
        except Exception as e:
            logger.error(f"Failed to export SPDX: {e}")
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"# SPDX export failed: {e}\n")
            except Exception as inner_e:
                logger.error(f"Failed to write error message to SPDX file: {inner_e}")

    @staticmethod
    def export_xlsx(sbom_data: Dict, filename: str):
        if not openpyxl:
            logger.error("openpyxl is not installed. Cannot export to .xlsx.")
            return

        wb = openpyxl.Workbook()

        # Remove default sheet and create our own
        if wb.active:
            wb.remove(wb.active)

        # 1. SBOM Overview/Summary Sheet
        ws_summary = wb.create_sheet(title="SBOM Summary")
        ws_summary.append(["SBOM Information", "Value"])
        ws_summary.append(["SBOM Version", sbom_data.get("sbomVersion", "1.0")])
        ws_summary.append(
            ["Generated Timestamp", sbom_data.get("metadata", {}).get("timestamp", "")]
        )
        ws_summary.append(["Tool", sbom_data.get("metadata", {}).get("tool", "")])
        ws_summary.append(
            ["Tool Version", sbom_data.get("metadata", {}).get("version", "")]
        )
        ws_summary.append(
            [
                "Application Name",
                sbom_data.get("metadata", {}).get("application", {}).get("name", ""),
            ]
        )
        ws_summary.append(
            [
                "Application Version",
                sbom_data.get("metadata", {}).get("application", {}).get("version", ""),
            ]
        )
        ws_summary.append(["Total Components", len(sbom_data.get("components", []))])

        # Count vulnerabilities by severity
        vuln_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for component in sbom_data.get("components", []):
            for vuln in component.get("vulnerabilities", []):
                severity = vuln.get("severity", "UNKNOWN")
                if severity in vuln_counts:
                    vuln_counts[severity] += 1

        ws_summary.append(["Critical Vulnerabilities", vuln_counts["CRITICAL"]])
        ws_summary.append(["High Vulnerabilities", vuln_counts["HIGH"]])
        ws_summary.append(["Medium Vulnerabilities", vuln_counts["MEDIUM"]])
        ws_summary.append(["Low Vulnerabilities", vuln_counts["LOW"]])

        # 2. Complete Components Sheet (All baseline information)
        ws_components = wb.create_sheet(title="Components Complete")
        ws_components.append(
            [
                "Component Name",
                "Component Version",
                "Component Description",
                "Component Supplier",
                "Component License",
                "Component Origin",
                "Component Dependencies",
                "Vulnerabilities Count",
                "Patch Status",
                "Release Date",
                "End-of-Life (EOL) Date",
                "Criticality",
                "Usage Restrictions",
                "Checksums or Hashes",
                "Comments or Notes",
                "Author of SBOM Data",
                "Timestamp",
                "Executable Property",
                "Archive Property",
                "Structured Property",
                "Unique Identifier (PURL)",
                "Component Type",
                "Copyright",
                "External References",
            ]
        )

        for component in sbom_data.get("components", []):
            # Extract properties for additional fields
            properties = {
                prop.get("name", ""): prop.get("value", "")
                for prop in component.get("properties", [])
            }

            ws_components.append(
                [
                    component.get("name", ""),
                    component.get("version", ""),
                    component.get("description", ""),
                    component.get("supplier", {}).get("name", ""),
                    "; ".join(
                        [lic.get("name", "") for lic in component.get("licenses", [])]
                    ),
                    properties.get("cast:origin", "Unknown"),  # Component Origin
                    properties.get(
                        "cast:dependencies", "Unknown"
                    ),  # Component Dependencies
                    str(len(component.get("vulnerabilities", []))),
                    properties.get("cast:patchStatus", "Unknown"),  # Patch Status
                    properties.get("cast:releaseDate", ""),  # Release Date
                    properties.get("cast:eolDate", ""),  # EOL Date
                    properties.get("cast:criticality", "Unknown"),  # Criticality
                    properties.get(
                        "cast:usageRestrictions", "None"
                    ),  # Usage Restrictions
                    properties.get("cast:checksum", ""),  # Checksums
                    properties.get("cast:comments", ""),  # Comments
                    component.get("author", ""),
                    sbom_data.get("metadata", {}).get("timestamp", ""),
                    properties.get("cast:executable", "No"),  # Executable Property
                    properties.get("cast:archive", "No"),  # Archive Property
                    properties.get("cast:structured", "No"),  # Structured Property
                    component.get("purl", ""),
                    component.get("type", ""),
                    component.get("copyright", ""),
                    "; ".join(
                        [
                            ref.get("url", "")
                            for ref in component.get("externalReferences", [])
                        ]
                    ),
                ]
            )

        # 3. Vulnerabilities Detailed Sheet
        ws_vuln = wb.create_sheet(title="Vulnerabilities")
        ws_vuln.append(
            [
                "Component Name",
                "Component Version",
                "Vulnerability ID (CVE)",
                "Severity",
                "CVSS Score",
                "Description",
                "CWE ID",
                "CPE",
                "Reference/Link",
                "Is KEV",
                "Published Date",
                "Patch Status",
                "Remediation Notes",
            ]
        )

        for component in sbom_data.get("components", []):
            for vuln in component.get("vulnerabilities", []):
                ws_vuln.append(
                    [
                        component.get("name", ""),
                        component.get("version", ""),
                        vuln.get("id", ""),
                        vuln.get("severity", ""),
                        vuln.get("cvssScore", ""),
                        vuln.get("description", ""),
                        vuln.get("cweId", ""),
                        vuln.get("cpe", ""),
                        vuln.get("link", ""),
                        "Yes" if vuln.get("isKev", False) else "No",
                        vuln.get("publishedDate", ""),
                        vuln.get("patchStatus", "Unknown"),
                        vuln.get("remediationNotes", ""),
                    ]
                )

        # 4. Licenses Sheet
        ws_licenses = wb.create_sheet(title="Licenses")
        ws_licenses.append(
            [
                "Component Name",
                "Component Version",
                "License Name",
                "License Compliance",
                "License Type",
                "License URL",
                "License Text",
                "SPDX Identifier",
            ]
        )

        for component in sbom_data.get("components", []):
            for license_info in component.get("licenses", []):
                ws_licenses.append(
                    [
                        component.get("name", ""),
                        component.get("version", ""),
                        license_info.get("name", ""),
                        license_info.get("compliance", "Unknown"),
                        license_info.get("type", ""),
                        license_info.get("url", ""),
                        license_info.get("text", ""),
                        license_info.get("spdxId", ""),
                    ]
                )

        # 5. Dependencies Sheet
        ws_deps = wb.create_sheet(title="Dependencies")
        ws_deps.append(
            [
                "Component Name",
                "Component Version",
                "Dependency Name",
                "Dependency Version",
                "Dependency Type",
                "Relationship Type",
                "Scope",
                "Optional",
            ]
        )

        for component in sbom_data.get("components", []):
            # Extract dependency information from properties
            properties = {
                prop.get("name", ""): prop.get("value", "")
                for prop in component.get("properties", [])
            }
            dependencies = properties.get("cast:dependencies", "")

            if dependencies and dependencies != "Unknown":
                # Parse dependencies if available
                deps_list = dependencies.split(";")
                for dep in deps_list:
                    ws_deps.append(
                        [
                            component.get("name", ""),
                            component.get("version", ""),
                            dep.strip(),
                            "",
                            "library",
                            "depends_on",
                            "runtime",
                            "No",
                        ]
                    )
            else:
                # Add a placeholder row
                ws_deps.append(
                    [
                        component.get("name", ""),
                        component.get("version", ""),
                        "No explicit dependencies found",
                        "",
                        "",
                        "",
                        "",
                        "",
                    ]
                )

        # 6. Security Analysis Sheet
        ws_security = wb.create_sheet(title="Security Analysis")
        ws_security.append(
            [
                "Component Name",
                "Component Version",
                "Total Vulnerabilities",
                "Critical Count",
                "High Count",
                "Medium Count",
                "Low Count",
                "KEV Count",
                "Risk Score",
                "Recommendation",
                "Last Security Review",
            ]
        )

        for component in sbom_data.get("components", []):
            vulns = component.get("vulnerabilities", [])
            critical_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
            high_count = sum(1 for v in vulns if v.get("severity") == "HIGH")
            medium_count = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
            low_count = sum(1 for v in vulns if v.get("severity") == "LOW")
            kev_count = sum(1 for v in vulns if v.get("isKev", False))

            # Calculate risk score (simple formula)
            risk_score = (
                (critical_count * 10)
                + (high_count * 7)
                + (medium_count * 4)
                + (low_count * 1)
            )

            # Generate recommendation
            if critical_count > 0:
                recommendation = (
                    "IMMEDIATE ACTION REQUIRED - Critical vulnerabilities found"
                )
            elif high_count > 0:
                recommendation = (
                    "HIGH PRIORITY - High severity vulnerabilities need attention"
                )
            elif medium_count > 0:
                recommendation = (
                    "MEDIUM PRIORITY - Consider updating or replacing component"
                )
            elif low_count > 0:
                recommendation = "LOW PRIORITY - Monitor for updates"
            else:
                recommendation = "No known vulnerabilities"

            ws_security.append(
                [
                    component.get("name", ""),
                    component.get("version", ""),
                    len(vulns),
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                    kev_count,
                    risk_score,
                    recommendation,
                    sbom_data.get("metadata", {}).get("timestamp", ""),
                ]
            )

        # 7. Metadata Sheet
        ws_metadata = wb.create_sheet(title="Metadata")
        ws_metadata.append(["Field", "Value", "Source", "Last Updated"])

        metadata = sbom_data.get("metadata", {})
        ws_metadata.append(
            [
                "SBOM Version",
                sbom_data.get("sbomVersion", ""),
                "Generated",
                metadata.get("timestamp", ""),
            ]
        )
        ws_metadata.append(
            [
                "Tool",
                metadata.get("tool", ""),
                "Generated",
                metadata.get("timestamp", ""),
            ]
        )
        ws_metadata.append(
            [
                "Tool Version",
                metadata.get("version", ""),
                "Generated",
                metadata.get("timestamp", ""),
            ]
        )
        ws_metadata.append(
            [
                "Application Name",
                metadata.get("application", {}).get("name", ""),
                "CAST Highlight",
                metadata.get("timestamp", ""),
            ]
        )
        ws_metadata.append(
            [
                "Application Version",
                metadata.get("application", {}).get("version", ""),
                "CAST Highlight",
                metadata.get("timestamp", ""),
            ]
        )
        ws_metadata.append(
            [
                "Application Description",
                metadata.get("application", {}).get("description", ""),
                "CAST Highlight",
                metadata.get("timestamp", ""),
            ]
        )
        ws_metadata.append(
            [
                "Total Components",
                str(len(sbom_data.get("components", []))),
                "Generated",
                metadata.get("timestamp", ""),
            ]
        )

        # Format worksheets for better readability
        from openpyxl.cell.cell import MergedCell
        for ws in wb.worksheets:
            # Auto-fit columns
            for col in ws.columns:
                max_length = 0
                column_letter = None
                for cell in col:
                    if not isinstance(cell, MergedCell):
                        if column_letter is None:
                            column_letter = cell.column_letter
                        try:
                            if cell.value:
                                max_length = max(max_length, len(str(cell.value)))
                        except Exception:
                            pass
                if column_letter:
                    adjusted_width = min(max_length + 2, 50)  # Cap at 50 characters
                    ws.column_dimensions[column_letter].width = adjusted_width

            # Bold headers
            if styles:
                for cell in ws[1]:
                    cell.font = styles.Font(bold=True)
                    cell.fill = styles.PatternFill(
                        start_color="CCCCCC",
                        end_color="CCCCCC",
                        fill_type="solid"
                    )

        wb.save(filename)
        logger.info(f"SBOM exported to {filename} with {len(wb.worksheets)} worksheets")

    @staticmethod
    def export_cyclonedx(sbom_data: Dict, filename: str, format: str = "json"):
        logger.warning("CycloneDX export now uses the CLI tool. Calling export_cyclonedx_with_cli instead.")
        SBOMExporter.export_cyclonedx_with_cli(filename.replace(f".{format}", ""), format=format)

    @staticmethod
    def export_docx(sbom_data: Dict, filename: str):
        if not Document:
            logger.error("python-docx is not installed. Cannot export to .docx.")
            return
        doc = Document()
        doc.add_heading("Software Bill of Materials (SBOM)", 0)
        doc.add_paragraph(f"Generated: {datetime.utcnow().isoformat()}")
        doc.add_heading("Components", level=1)
        # Match columns to Components Complete in Excel
        headers = [
            "Component Name",
            "Component Version",
            "Component Description",
            "Component Supplier",
            "Component License",
            "Component Origin",
            "Component Dependencies",
            "Vulnerabilities Count",
            "Patch Status",
            "Release Date",
            "End-of-Life (EOL) Date",
            "Criticality",
            "Usage Restrictions",
            "Checksums or Hashes",
            "Comments or Notes",
            "Author of SBOM Data",
            "Timestamp",
            "Executable Property",
            "Archive Property",
            "Structured Property",
            "Unique Identifier (PURL)",
            "Component Type",
            "Copyright",
            "External References",
        ]
        table = doc.add_table(rows=1, cols=len(headers))
        hdr_cells = table.rows[0].cells
        for i, h in enumerate(headers):
            hdr_cells[i].text = h
        for component in sbom_data["components"]:
            properties = {
                prop.get("name", ""): prop.get("value", "")
                for prop in component.get("properties", [])
            }
            row_cells = table.add_row().cells
            values = [
                component.get("name", ""),
                component.get("version", ""),
                component.get("description", ""),
                component.get("supplier", {}).get("name", ""),
                "; ".join(
                    [lic.get("name", "") for lic in component.get("licenses", [])]
                ),
                properties.get("cast:origin", "Unknown"),
                properties.get("cast:dependencies", "Unknown"),
                str(len(component.get("vulnerabilities", []))),
                properties.get("cast:patchStatus", "Unknown"),
                properties.get("cast:releaseDate", ""),
                properties.get("cast:eolDate", ""),
                properties.get("cast:criticality", "Unknown"),
                properties.get("cast:usageRestrictions", "None"),
                properties.get("cast:checksum", ""),
                properties.get("cast:comments", ""),
                component.get("author", ""),
                sbom_data.get("metadata", {}).get("timestamp", ""),
                properties.get("cast:executable", "No"),
                properties.get("cast:archive", "No"),
                properties.get("cast:structured", "No"),
                component.get("purl", ""),
                component.get("type", ""),
                component.get("copyright", ""),
                "; ".join(
                    [
                        ref.get("url", "")
                        for ref in component.get("externalReferences", [])
                    ]
                ),
            ]
            for i, v in enumerate(values):
                row_cells[i].text = str(v)
        doc.save(filename)
        logger.info(f"SBOM exported to {filename}")

    @staticmethod
    def export_cyclonedx_with_cli(output_path: str, format: str = "json"):
        fmt = "JSON" if format == "json" else "XML"
        result = subprocess.run(
            [
                "cyclonedx-py",
                "environment",
                "--output-format",
                fmt,
                "--output-file",
                f"{output_path}_cyclonedx.{format}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.error(f"CycloneDX CLI failed: {result.stderr}")
        else:
            logger.info(f"CycloneDX SBOM exported to {output_path}_cyclonedx.{format}")


def get_conf(conf, *keys, default=None):
    for k in keys:
        if k in conf:
            return conf[k]
    return default


def validate_application_id(cast_api: HighlightAPI, app_id: str) -> bool:
    """Return True if app_id exists in the list of applications, else False."""
    apps = cast_api.get_applications()
    if not apps:
        logger.error(
            "No applications found for the current user/company. Cannot validate Application ID."
        )
        return False
    for app in apps:
        if str(app.get("id")) == str(app_id):
            logger.info(
                f"Validated Application ID {app_id}: {app.get('name', '[no name]')}"
            )
            return True
    logger.error(
        f"Application ID {app_id} not found in your CAST Highlight company."
    )
    return False


def main():
    # Always use config/config.json in the config directory
    config_path = "config/config.json"
    config = load_config(config_path)
    ch_conf = config.get("cast_highlight", {})
    auth_conf = ch_conf.get("authentication", {})
    sbom_conf = config.get("sbom_settings", {})

    # Application ID or Name
    app_id = config.get("application_id") or sbom_conf.get("application_id")
    app_name = config.get("application_name") or sbom_conf.get("application_name")

    # Output formats (list)
    output_formats = sbom_conf.get("output_formats")
    if not output_formats or not isinstance(output_formats, list):
        output_formats = ["json"]

    # Authentication
    method = auth_conf.get("method", "api_key")
    company_id = (
        auth_conf.get("company_id")
        or ch_conf.get("company_id")
        or config.get("company_id")
    )
    if not company_id:
        logger.error("company_id is required in config for all authentication methods.")
        sys.exit(1)
    if method == "credentials":
        cast_api = HighlightAPI(
            ch_conf["api_url"],
            username=auth_conf.get("username"),
            password=auth_conf.get("password"),
            company_id=company_id,
        )
    else:
        cast_api = HighlightAPI(
            ch_conf["api_url"], api_key=auth_conf.get("api_key"), company_id=company_id
        )

    # If app_id is not provided, but app_name is, look up the ID
    if not app_id and app_name:
        logger.info(f"Looking up application ID for name: {app_name}")
        apps = cast_api.get_applications()
        match = next(
            (app for app in apps if app.get("name", "").lower() == app_name.lower()),
            None,
        )
        if match:
            app_id = match["id"]
            logger.info(f'Found application "{app_name}" with ID: {app_id}')
        else:
            logger.warning(
                f'Application name "{app_name}" not found in your CAST Highlight company. Falling back to application_id from config if available.'
            )
            app_id = config.get("application_id") or sbom_conf.get("application_id")
            if app_id:
                logger.info(f"Using fallback application_id: {app_id}")
            else:
                logger.error("No valid application_id found in config to fall back to.")
                sys.exit(1)
    if not app_id:
        logger.error(
            "Application ID or name is required. Please provide it in the config file."
        )
        sys.exit(1)

    # Generate SBOM
    generator = SBOMGenerator(cast_api)
    sbom_data = generator.generate_sbom(app_id)

    # Create Reports directory if it doesn't exist
    reports_dir = "Reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"Created Reports directory: {reports_dir}")

    # Get application details for filename
    app_name = (
        sbom_data.get("metadata", {}).get("application", {}).get("name", "Unknown")
    )
    # Clean app name for filename (remove special characters)
    safe_app_name = "".join(
        c for c in app_name if c.isalnum() or c in (" ", "-", "_")
    ).rstrip()
    safe_app_name = safe_app_name.replace(" ", "_")

    # Create filename with app name, ID, and timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = f"{safe_app_name}_ID{app_id}_{timestamp}"

    # Full path for output files
    output_path = os.path.join(reports_dir, filename_base)

    # Export in requested format(s)
    for fmt in output_formats:
        fmt = fmt.lower()
        if fmt == "json":
            SBOMExporter.export_json(sbom_data, f"{output_path}.json")
        elif fmt == "csv":
            SBOMExporter.export_csv(sbom_data, f"{output_path}.csv")
        elif fmt == "xlsx":
            SBOMExporter.export_xlsx(sbom_data, f"{output_path}.xlsx")
        elif fmt == "cyclonedx":
            SBOMExporter.export_cyclonedx_with_cli(output_path, format="json")
            SBOMExporter.export_cyclonedx_with_cli(output_path, format="xml")
        elif fmt == "docx":
            SBOMExporter.export_docx(sbom_data, f"{output_path}.docx")
        else:
            logger.warning(f"Unknown output format: {fmt}. Skipping.")

    print(
        f"SBOM generation completed successfully! Components found: {len(sbom_data['components'])}"
    )
    print(f"Files saved in Reports directory with prefix: {filename_base}")


if __name__ == "__main__":
    main()
