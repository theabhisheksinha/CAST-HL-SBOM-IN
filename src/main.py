import logging
import os
import sys
import argparse
from datetime import datetime
from logging_config import setup_module_logging, cleanup_empty_log_files

import json
from config_loader import load_config, ConfigError
from highlight_api import HighlightAPI
from sbom_builder import SBOMBuilder
from sbom_exporter import SBOMExporter

def parse_arguments():
    """Parse command line arguments for logging control"""
    parser = argparse.ArgumentParser(
        description='SBOM Generator with configurable logging levels',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Logging Level Examples:
  python main.py --log-level DEBUG    # Show all logs including debug
  python main.py --debug              # Enable debug logging
  python main.py --quiet              # Only show errors
  python main.py                      # Default INFO level logging"""
    )
    
    # Logging level arguments (mutually exclusive)
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set the logging level (default: INFO)'
    )
    log_group.add_argument(
        '--debug',
        action='store_const',
        const='DEBUG',
        dest='log_level',
        help='Enable debug logging (equivalent to --log-level DEBUG)'
    )
    log_group.add_argument(
        '--quiet',
        action='store_const',
        const='QUIET',
        dest='log_level',
        help='Quiet mode - only show errors'
    )
    
    return parser.parse_args()

def setup_global_logging(log_level: str):
    """Set up logging for all modules with the specified level"""
    # Import all modules that use logging
    import sbom_builder
    import sbom_generator
    import highlight_api
    import verify_compliance
    
    # Update their loggers with the new level
    sbom_builder.logger, sbom_builder.log_files = setup_module_logging('sbom_builder', log_level)
    sbom_generator.logger, sbom_generator.log_files = setup_module_logging('sbom_generator', log_level)
    highlight_api.logger, highlight_api.log_files = setup_module_logging('highlight_api', log_level)
    verify_compliance.logger, verify_compliance.log_files = setup_module_logging('verify_compliance', log_level)

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up separated logging for main module with specified level
    global logger, log_files
    logger, log_files = setup_module_logging('main', args.log_level)
    
    # Set up logging for all other modules
    setup_global_logging(args.log_level)
    
    config_path = 'config/config.json'
    try:
        config = load_config(config_path)
    except ConfigError as e:
        logging.error(f'Config error: {e}')
        sys.exit(1)
    except Exception as e:
        logging.error(f'Failed to load config: {e}')
        sys.exit(1)

    ch = config['cast_highlight']
    auth = ch['authentication']
    method = auth['method']
    company_id = auth.get('company_id')
    app_id = config['application_id']
    base_url = ch['api_url']
    username = auth.get('username')
    password = auth.get('password')
    api_key = auth.get('api_key')

    # Initialize API
    try:
        api = HighlightAPI(
            base_url=base_url,
            company_id=company_id,
            auth_method=method,
            username=username,
            password=password,
            api_key=api_key
        )
        logger.info("API client initialized successfully")
    except Exception as e:
        logger.error(f'Failed to initialize HighlightAPI: {e}')
        sys.exit(1)

    # Validate application
    app_name = None  # Initialize app_name to avoid UnboundLocalError
    try:
        apps = api.list_applications()
        if apps:
            app_ids = [str(app['id']) for app in apps]
            if str(app_id) not in app_ids:
                logger.warning(f'Application ID {app_id} not found in your company. Proceeding anyway...')
            else:
                app_name = next((app['name'] for app in apps if str(app['id']) == str(app_id)), None)
                logger.info(f'Validated Application ID {app_id}: {app_name}')
        else:
            logger.warning(f'Could not retrieve applications list. Proceeding with configured Application ID {app_id}')
    except Exception as e:
        logger.warning(f'Failed to validate application: {e}. Proceeding with configured Application ID {app_id}')

    # Fetch comprehensive SBOM data from multiple endpoints
    try:
        logger.info(f"Fetching comprehensive SBOM data for application {app_id}")
        comprehensive_data = api.get_comprehensive_sbom_data(app_id)
        
        if not comprehensive_data:
            logger.warning(f'No SBOM data found for application {app_id}.')
            sys.exit(1)
        
        # Log data availability
        data_sources = []
        if comprehensive_data.get('third_party'):
            data_sources.append("third-party components")
        if comprehensive_data.get('components'):
            data_sources.append("detailed components")
        if comprehensive_data.get('vulnerabilities'):
            data_sources.append("vulnerabilities")
        if comprehensive_data.get('licenses'):
            data_sources.append("licenses")
        
        logger.info(f"Retrieved data from: {', '.join(data_sources)}")
        
    except Exception as e:
        logger.error(f'Failed to fetch comprehensive SBOM data: {e}')
        sys.exit(1)

    # Build comprehensive SBOM
    try:
        logger.info("Building comprehensive SBOM from multiple data sources")
        # Add application name to the comprehensive data
        if app_name:
            if 'application_info' not in comprehensive_data:
                comprehensive_data['application_info'] = {}
            comprehensive_data['application_info']['name'] = app_name
        
        sbom_builder = SBOMBuilder(comprehensive_data)
        sbom = sbom_builder.build()
        
        component_count = len(sbom["components"])
        logger.info(f'SBOM built successfully with {component_count} components')
        
        # Log field coverage statistics
        _log_field_coverage(sbom)
        
    except Exception as e:
        logger.error(f'Failed to build SBOM: {e}')
        sys.exit(1)

    print("====================================")
    print("Generated SBOM data:")
    print(json.dumps(sbom, indent=2))
    print("====================================")

    # Export SBOM
    try:
        output_formats = config.get('sbom_settings', {}).get('output_formats', ['json'])
        default_output_prefix = config.get('sbom_settings', {}).get('default_output_prefix', 'sbom_sample')
        
        # Create Reports directory if it doesn't exist
        reports_dir = "Reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            logger.info(f'Created Reports directory: {reports_dir}')
        
        # Get application details for filename
        app_name_safe = app_name or "Unknown"
        safe_app_name = "".join(c for c in app_name_safe if c.isalnum() or c in (' ', '-', '_')).rstrip()
        safe_app_name = safe_app_name.replace(' ', '_')
        
        # Create filename with app name, ID, and timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"{safe_app_name}_ID{app_id}_{timestamp}"
        
        # Full path for output files
        output_path = os.path.join(reports_dir, filename_base)
        
        # Export in requested formats
        exported_files = []
        
        if 'json' in output_formats or 'all' in output_formats:
            SBOMExporter.export_json(sbom, f'{output_path}.json')
            exported_files.append(f'{filename_base}.json')
        
        if 'xlsx' in output_formats or 'all' in output_formats:
            SBOMExporter.export_xlsx(sbom, f'{output_path}.xlsx')
            exported_files.append(f'{filename_base}.xlsx')
        
        if 'csv' in output_formats or 'all' in output_formats:
            SBOMExporter.export_csv(sbom, f'{output_path}.csv')
            exported_files.append(f'{filename_base}.csv')
        
        if 'cyclonedx' in output_formats or 'all' in output_formats:
            SBOMExporter.export_cyclonedx(sbom, f'{output_path}_cyclonedx.json', 'json')
            exported_files.append(f'{filename_base}_cyclonedx.json')
        
        if 'docx' in output_formats or 'all' in output_formats:
            SBOMExporter.export_docx(sbom, f'{output_path}.docx')
            exported_files.append(f'{filename_base}.docx')
        
        if 'standard' in output_formats or 'all' in output_formats:
            SBOMExporter.export_standard_format(sbom, f'{output_path}_standard.xlsx', f'{output_path}_standard.csv')
            exported_files.extend([f'{filename_base}_standard.xlsx', f'{filename_base}_standard.csv'])
        
        logger.info(f'SBOM export complete. Files generated: {", ".join(exported_files)}')
        logger.info(f'Files saved in Reports directory with prefix: {filename_base}')
        
    except Exception as e:
        logger.error(f'Failed to export SBOM: {e}')
        sys.exit(1)
    
    # Clean up empty log files at the end of execution
    try:
        removed_files = cleanup_empty_log_files()
        if removed_files:
            logger.info(f"Cleanup: Removed {len(removed_files)} empty log files: {', '.join(removed_files)}")
        else:
            logger.info("Cleanup: No empty log files found to remove")
    except Exception as e:
        logger.warning(f"Failed to clean up empty log files: {e}")

def _log_field_coverage(sbom):
    """Log field coverage statistics for the generated SBOM"""
    components = sbom.get("components", [])
    if not components:
        logger.warning("No components found in SBOM")
        return
    
    # Count components with various fields
    total_components = len(components)
    components_with_licenses = sum(1 for c in components if c.get("licenses"))
    components_with_vulnerabilities = sum(1 for c in components if c.get("vulnerabilities"))
    components_with_properties = sum(1 for c in components if c.get("properties"))
    components_with_external_refs = sum(1 for c in components if c.get("externalReferences"))
    
    # Count total vulnerabilities and licenses
    total_vulnerabilities = sum(len(c.get("vulnerabilities", [])) for c in components)
    total_licenses = sum(len(c.get("licenses", [])) for c in components)
    
    # Count properties by type
    property_counts = {}
    for component in components:
        for prop in component.get("properties", []):
            prop_name = prop.get("name", "unknown")
            property_counts[prop_name] = property_counts.get(prop_name, 0) + 1
    
    logger.info("SBOM Field Coverage Statistics:")
    logger.info(f"   - Total Components: {total_components}")
    logger.info(f"   - Components with Licenses: {components_with_licenses} ({components_with_licenses/total_components*100:.1f}%)")
    logger.info(f"   - Components with Vulnerabilities: {components_with_vulnerabilities} ({components_with_vulnerabilities/total_components*100:.1f}%)")
    logger.info(f"   - Components with Properties: {components_with_properties} ({components_with_properties/total_components*100:.1f}%)")
    logger.info(f"   - Components with External References: {components_with_external_refs} ({components_with_external_refs/total_components*100:.1f}%)")
    logger.info(f"   - Total Vulnerabilities: {total_vulnerabilities}")
    logger.info(f"   - Total Licenses: {total_licenses}")
    
    if property_counts:
        logger.info("   - Property Coverage:")
        for prop_name, count in sorted(property_counts.items()):
            percentage = count / total_components * 100
            logger.info(f"     * {prop_name}: {count} components ({percentage:.1f}%)")

if __name__ == '__main__':
    main()