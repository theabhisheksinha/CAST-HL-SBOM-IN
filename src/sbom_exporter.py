import json
import csv
import logging
import uuid
from typing import Dict
from datetime import datetime

try:
    import openpyxl
except ImportError:
    openpyxl = None

try:
    from docx import Document
    from docx.shared import Inches
except ImportError:
    Document = None

class SBOMExporter:
    @staticmethod
    def export_json(sbom, filename):
        # Process the SBOM to remove 'cast:' prefixes from property names
        processed_sbom = SBOMExporter._process_sbom_properties(sbom)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(processed_sbom, f, indent=2)
        logging.info(f"SBOM exported to {filename}")
        
    @staticmethod
    def _process_sbom_properties(sbom):
        """Remove 'cast:' prefix from property names in the SBOM"""
        # Create a deep copy to avoid modifying the original
        processed_sbom = json.loads(json.dumps(sbom))
        
        # Process each component
        for component in processed_sbom.get("components", []):
            # Process properties
            if "properties" in component:
                for prop in component["properties"]:
                    if "name" in prop and prop["name"].startswith("cast:"):
                        prop["name"] = prop["name"].replace("cast:", "")
                        
        return processed_sbom

    @staticmethod
    def export_cyclonedx(sbom_data: Dict, filename: str, format: str = "json"):
        """Export SBOM data in CycloneDX format (manual implementation)"""
        try:
            # Create CycloneDX structure manually
            cyclonedx_bom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "metadata": {
                    "timestamp": sbom_data.get("metadata", {}).get("timestamp", datetime.utcnow().isoformat()),
                    "tools": [
                        {
                            "vendor": "CAST Highlight SBOM Generator",
                            "name": "SBOM Generator",
                            "version": sbom_data.get("metadata", {}).get("version", "1.0")
                        }
                    ]
                },
                "components": []
            }

            # Add application as metadata component
            app_info = sbom_data.get("metadata", {}).get("application", {})
            if app_info:
                cyclonedx_bom["metadata"]["component"] = {
                    "type": "application",
                    "name": app_info.get("name", "Unknown Application"),
                    "version": app_info.get("version", "Unknown"),
                    "description": app_info.get("description", "")
                }

            # Convert components to CycloneDX format
            for comp_data in sbom_data.get("components", []):
                cyclonedx_component = {
                    "type": "library",
                    "name": comp_data.get("name", "Unknown"),
                    "version": comp_data.get("version", "Unknown"),
                    "description": comp_data.get("description", "")
                }
                
                # Add copyright if available
                if comp_data.get("copyright") and comp_data.get("copyright") != "Unknown":
                    cyclonedx_component["copyright"] = comp_data.get("copyright")

                # Add PURL
                if comp_data.get("purl"):
                    cyclonedx_component["purl"] = comp_data["purl"]

                # Add licenses
                licenses = []
                for license_info in comp_data.get("licenses", []):
                    license_obj = {
                        "id": license_info.get("licenseId", "Unknown"),
                        "name": license_info.get("name", "Unknown")
                    }
                    if license_info.get("url"):
                        license_obj["url"] = license_info["url"]
                    licenses.append(license_obj)

                if licenses:
                    cyclonedx_component["licenses"] = licenses

                # Add external references
                ext_refs = []
                for ref in comp_data.get("externalReferences", []):
                    ref_type = "other"
                    if ref.get("type") == "repository":
                        ref_type = "vcs"
                    elif ref.get("type") == "website":
                        ref_type = "website"

                    ext_ref = {
                        "type": ref_type,
                        "url": ref.get("url", "")
                    }
                    ext_refs.append(ext_ref)

                if ext_refs:
                    cyclonedx_component["externalReferences"] = ext_refs

                # Add properties
                properties = []
                for prop in comp_data.get("properties", []):
                    # Skip properties that are already represented in other fields
                    if prop.get("name") in ["cast:timestamp"]:
                        continue
                        
                    # Ensure checksum/hash properties are properly formatted
                    if prop.get("name") in ["cast:checksum", "cast:hash", "cast:fingerprint", "cast:sha1", "cast:sha256", "cast:md5"]:
                        hash_type = prop.get("name").replace("cast:", "")
                        if "hashes" not in cyclonedx_component:
                            cyclonedx_component["hashes"] = []
                        cyclonedx_component["hashes"].append({
                            "alg": hash_type.upper(),
                            "content": prop.get("value", "")
                        })
                    else:
                        # Remove 'cast:' prefix from property names
                        prop_name = prop.get("name", "")
                        if prop_name.startswith("cast:"):
                            prop_name = prop_name.replace("cast:", "")
                            
                        property_obj = {
                            "name": prop_name,
                            "value": prop.get("value", "")
                        }
                        properties.append(property_obj)

                if properties:
                    cyclonedx_component["properties"] = properties

                # Add vulnerabilities
                vulnerabilities = []
                for vuln_data in comp_data.get("vulnerabilities", []):
                    vuln = {
                        "id": vuln_data.get("id", "Unknown"),
                        "description": vuln_data.get("description", "")
                    }

                    # Add CWE if available
                    if vuln_data.get("cweId"):
                        vuln["cwes"] = [vuln_data["cweId"]]

                    # Add CPE if available
                    if vuln_data.get("cpe"):
                        vuln["cpe"] = vuln_data["cpe"]

                    # Add rating if CVSS score is available
                    if vuln_data.get("cvssScore"):
                        try:
                            cvss_score = float(vuln_data["cvssScore"])
                            severity = "low"
                            if cvss_score >= 9.0:
                                severity = "critical"
                            elif cvss_score >= 7.0:
                                severity = "high"
                            elif cvss_score >= 4.0:
                                severity = "medium"

                            vuln["ratings"] = [
                                {
                                    "source": {
                                        "name": "CVSS",
                                        "url": "https://www.first.org/cvss/"
                                    },
                                    "score": cvss_score,
                                    "severity": severity,
                                    "method": "CVSSv3"
                                }
                            ]
                        except (ValueError, TypeError):
                            pass

                    # Add reference if available
                    if vuln_data.get("link"):
                        vuln["references"] = [
                            {
                                "id": vuln_data.get("id", "Unknown"),
                                "source": {
                                    "name": "CVE",
                                    "url": vuln_data["link"]
                                }
                            }
                        ]

                    vulnerabilities.append(vuln)

                if vulnerabilities:
                    cyclonedx_component["vulnerabilities"] = vulnerabilities

                cyclonedx_bom["components"].append(cyclonedx_component)

            # Export based on format
            if format.lower() == "json":
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(cyclonedx_bom, f, indent=2, ensure_ascii=False)

                logging.info(f"CycloneDX JSON SBOM exported to {filename}")

            elif format.lower() == "xml":
                # Generate XML format
                xml_content = SBOMExporter._cyclonedx_to_xml(cyclonedx_bom)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(xml_content)

                logging.info(f"CycloneDX XML SBOM exported to {filename}")

            else:
                logging.error(f"Unsupported CycloneDX format: {format}")
                return

        except Exception as e:
            logging.error(f"Failed to export CycloneDX: {e}")
            # Fallback to CLI method if manual method fails
            logging.info("Falling back to CLI method...")
            SBOMExporter.export_cyclonedx_with_cli(filename.replace(f".{format}", ""), format=format)

    @staticmethod
    def _cyclonedx_to_xml(cyclonedx_bom):
        """Convert CycloneDX BOM to XML format"""
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.4"',
            '     version="1"',
            '     serialNumber="urn:uuid:' + str(uuid.uuid4()) + '">'
        ]

        # Add metadata
        if "metadata" in cyclonedx_bom:
            xml_lines.append('  <metadata>')
            
            if "timestamp" in cyclonedx_bom["metadata"]:
                xml_lines.append(f'    <timestamp>{cyclonedx_bom["metadata"]["timestamp"]}</timestamp>')
            
            if "tools" in cyclonedx_bom["metadata"]:
                xml_lines.append('    <tools>')
                for tool in cyclonedx_bom["metadata"]["tools"]:
                    xml_lines.append('      <tool>')
                    if "vendor" in tool:
                        xml_lines.append(f'        <vendor>{tool["vendor"]}</vendor>')
                    if "name" in tool:
                        xml_lines.append(f'        <name>{tool["name"]}</name>')
                    if "version" in tool:
                        xml_lines.append(f'        <version>{tool["version"]}</version>')
                    xml_lines.append('      </tool>')
                xml_lines.append('    </tools>')
            
            if "component" in cyclonedx_bom["metadata"]:
                comp = cyclonedx_bom["metadata"]["component"]
                xml_lines.append('    <component type="' + comp.get("type", "application") + '">')
                if "name" in comp:
                    xml_lines.append(f'      <name>{comp["name"]}</name>')
                if "version" in comp:
                    xml_lines.append(f'      <version>{comp["version"]}</version>')
                if "description" in comp:
                    xml_lines.append(f'      <description>{comp["description"]}</description>')
                xml_lines.append('    </component>')
            
            xml_lines.append('  </metadata>')

        # Add components
        if "components" in cyclonedx_bom:
            xml_lines.append('  <components>')
            for comp in cyclonedx_bom["components"]:
                xml_lines.append('    <component type="' + comp.get("type", "library") + '">')
                
                if "name" in comp:
                    xml_lines.append(f'      <name>{comp["name"]}</name>')
                if "version" in comp:
                    xml_lines.append(f'      <version>{comp["version"]}</version>')
                if "description" in comp:
                    xml_lines.append(f'      <description>{comp["description"]}</description>')
                if "purl" in comp:
                    xml_lines.append(f'      <purl>{comp["purl"]}</purl>')
                
                # Add licenses
                if "licenses" in comp:
                    xml_lines.append('      <licenses>')
                    for license_info in comp["licenses"]:
                        xml_lines.append('        <license>')
                        if "id" in license_info:
                            xml_lines.append(f'          <id>{license_info["id"]}</id>')
                        if "name" in license_info:
                            xml_lines.append(f'          <name>{license_info["name"]}</name>')
                        if "url" in license_info:
                            xml_lines.append(f'          <url>{license_info["url"]}</url>')
                        xml_lines.append('        </license>')
                    xml_lines.append('      </licenses>')
                
                # Add external references
                if "externalReferences" in comp:
                    xml_lines.append('      <externalReferences>')
                    for ref in comp["externalReferences"]:
                        xml_lines.append('        <reference>')
                        if "type" in ref:
                            xml_lines.append(f'          <type>{ref["type"]}</type>')
                        if "url" in ref:
                            xml_lines.append(f'          <url>{ref["url"]}</url>')
                        xml_lines.append('        </reference>')
                    xml_lines.append('      </externalReferences>')
                
                # Add properties
                if "properties" in comp:
                    xml_lines.append('      <properties>')
                    for prop in comp["properties"]:
                        xml_lines.append('        <property>')
                        if "name" in prop:
                            xml_lines.append(f'          <name>{prop["name"]}</name>')
                        if "value" in prop:
                            xml_lines.append(f'          <value>{prop["value"]}</value>')
                        xml_lines.append('        </property>')
                    xml_lines.append('      </properties>')
                
                # Add vulnerabilities
                if "vulnerabilities" in comp:
                    xml_lines.append('      <vulnerabilities>')
                    for vuln in comp["vulnerabilities"]:
                        xml_lines.append('        <vulnerability>')
                        if "id" in vuln:
                            xml_lines.append(f'          <id>{vuln["id"]}</id>')
                        if "description" in vuln:
                            xml_lines.append(f'          <description>{vuln["description"]}</description>')
                        
                        # Add CWEs
                        if "cwes" in vuln:
                            xml_lines.append('          <cwes>')
                            for cwe in vuln["cwes"]:
                                xml_lines.append(f'            <cwe>{cwe}</cwe>')
                            xml_lines.append('          </cwes>')
                        
                        # Add ratings
                        if "ratings" in vuln:
                            xml_lines.append('          <ratings>')
                            for rating in vuln["ratings"]:
                                xml_lines.append('            <rating>')
                                if "score" in rating:
                                    xml_lines.append(f'              <score>{rating["score"]}</score>')
                                if "severity" in rating:
                                    xml_lines.append(f'              <severity>{rating["severity"]}</severity>')
                                if "method" in rating:
                                    xml_lines.append(f'              <method>{rating["method"]}</method>')
                                xml_lines.append('            </rating>')
                            xml_lines.append('          </ratings>')
                        
                        xml_lines.append('        </vulnerability>')
                    xml_lines.append('      </vulnerabilities>')
                
                xml_lines.append('    </component>')
            xml_lines.append('  </components>')

        xml_lines.append('</bom>')
        return '\n'.join(xml_lines)

    @staticmethod
    def export_cyclonedx_with_cli(output_path: str, format: str = "json"):
        """Export CycloneDX using CLI tool (fallback method)"""
        try:
            import subprocess
            import sys
            
            # Try to use cyclonedx-py CLI tool
            cmd = [sys.executable, "-m", "cyclonedx_py", "bom", "--input-format", "json", "--output-format", format, "--output-file", f"{output_path}.{format}"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logging.info(f"CycloneDX {format.upper()} exported using CLI to {output_path}.{format}")
            else:
                logging.error(f"CLI export failed: {result.stderr}")
                
        except Exception as e:
            logging.error(f"CLI export error: {e}")

    @staticmethod
    def export_docx(sbom_data: Dict, filename: str):
        """Export SBOM as DOCX document"""
        if not Document:
            logging.error('python-docx is not installed. Cannot export to .docx.')
            return
        
        try:
            doc = Document()
            
            # Add title
            title = doc.add_heading('Software Bill of Materials (SBOM)', 0)
            title.alignment = 1  # Center alignment
            
            # Add metadata section
            doc.add_heading('Metadata', level=1)
            metadata = sbom_data.get("metadata", {})
            
            metadata_table = doc.add_table(rows=1, cols=2)
            metadata_table.style = 'Table Grid'
            hdr_cells = metadata_table.rows[0].cells
            hdr_cells[0].text = 'Field'
            hdr_cells[1].text = 'Value'
            
            # Add metadata rows
            metadata_fields = [
                ('Timestamp', metadata.get('timestamp', 'Unknown')),
                ('Tool', metadata.get('tool', 'CAST Highlight SBOM Generator')),
                ('Version', metadata.get('version', '2.0')),
                ('Total Components', str(len(sbom_data.get('components', []))))
            ]
            
            for field, value in metadata_fields:
                row_cells = metadata_table.add_row().cells
                row_cells[0].text = field
                row_cells[1].text = str(value)
            
            # Add components section
            doc.add_heading('Components', level=1)
            
            if sbom_data.get("components"):
                # Create components table
                components_table = doc.add_table(rows=1, cols=6)
                components_table.style = 'Table Grid'
                hdr_cells = components_table.rows[0].cells
                hdr_cells[0].text = 'Name'
                hdr_cells[1].text = 'Version'
                hdr_cells[2].text = 'Type'
                hdr_cells[3].text = 'Description'
                hdr_cells[4].text = 'License'
                hdr_cells[5].text = 'Vulnerabilities'
                
                # Add component rows
                for component in sbom_data["components"]:
                    row_cells = components_table.add_row().cells
                    row_cells[0].text = component.get('name', 'Unknown')
                    row_cells[1].text = component.get('version', 'Unknown')
                    row_cells[2].text = component.get('type', 'Unknown')
                    row_cells[3].text = component.get('description', '')[:100] + '...' if len(component.get('description', '')) > 100 else component.get('description', '')
                    
                    # License information
                    licenses = component.get('licenses', [])
                    license_text = '; '.join([lic.get('name', '') for lic in licenses]) if licenses else 'Unknown'
                    row_cells[4].text = license_text
                    
                    # Vulnerability count
                    vuln_count = len(component.get('vulnerabilities', []))
                    row_cells[5].text = str(vuln_count)
            
            # Add summary section
            doc.add_heading('Summary', level=1)
            summary_para = doc.add_paragraph()
            summary_para.add_run(f"This SBOM contains {len(sbom_data.get('components', []))} components. ")
            summary_para.add_run("Generated by CAST Highlight SBOM Generator v2.0.")
            
            # Save document
            doc.save(filename)
            logging.info(f"SBOM exported to {filename}")
            
        except Exception as e:
            logging.error(f"Failed to export DOCX: {e}")

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