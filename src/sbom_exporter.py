import json
import csv
import logging
from typing import Dict

try:
    import openpyxl
except ImportError:
    openpyxl = None

class SBOMExporter:
    @staticmethod
    def export_json(sbom, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(sbom, f, indent=2)
        logging.info(f"SBOM exported to {filename}")

    @staticmethod
    def export_csv(sbom_data: Dict, filename: str):
        """Export SBOM as CSV with all baseline fields"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write header (same as Components Complete in Excel)
            writer.writerow([
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
                "External References"
            ])
            for component in sbom_data["components"]:
                properties = {
                    prop.get("name", ""): prop.get("value", "")
                    for prop in component.get("properties", [])
                }
                writer.writerow([
                    component.get("name", ""),
                    component.get("version", ""),
                    component.get("description", ""),
                    component.get("supplier", {}).get("name", ""),
                    "; ".join([lic.get("name", "") for lic in component.get("licenses", [])]),
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
                    component.get("timestamp", ""),
                    properties.get("cast:executable", "No"),
                    properties.get("cast:archive", "No"),
                    properties.get("cast:structured", "No"),
                    component.get("purl", ""),
                    component.get("type", ""),
                    component.get("copyright", ""),
                    "; ".join([ref.get("url", "") for ref in component.get("externalReferences", [])])
                ])
        logging.info(f"SBOM exported to {filename}")

    @staticmethod
    def export_xlsx(sbom_data: Dict, filename: str):
        if not openpyxl:
            logging.error('openpyxl is not installed. Cannot export to .xlsx.')
            return
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "SBOM Components"
        ws.append([
            "Component Name", "Version", "Type", "Description", "PURL",
            "License", "Vulnerabilities", "Supplier", "Author", "Copyright"
        ])
        for component in sbom_data["components"]:
            ws.append([
                component.get("name", ""),
                component.get("version", ""),
                component.get("type", ""),
                component.get("description", ""),
                component.get("purl", ""),
                "; ".join([lic.get("name", "") for lic in component.get("licenses", [])]),
                str(len(component.get("vulnerabilities", []))),
                component.get("supplier", {}).get("name", ""),
                component.get("author", ""),
                component.get("copyright", "")
            ])

        # Add vulnerabilities worksheet
        ws_vuln = wb.create_sheet(title="vulnerabilities")
        ws_vuln.append([
            "Component Name", "Vulnerability ID (CVE)", "Severity", "CVSS Score", "Description", "CWE ID", "CPE", "Reference/Link"
        ])
        for component in sbom_data["components"]:
            for vuln in component.get("vulnerabilities", []):
                ws_vuln.append([
                    component.get("name", ""),
                    vuln.get("id", ""),
                    vuln.get("severity", ""),
                    vuln.get("cvssScore", ""),
                    vuln.get("description", ""),
                    vuln.get("cweId", ""),
                    vuln.get("cpe", ""),
                    vuln.get("link", "")
                ])
        wb.save(filename)
        logging.info(f"SBOM exported to {filename}") 