#!/usr/bin/env python3
"""
Configuration Setup Helper
This script helps users set up their CAST Highlight authentication configuration.
"""

import json
import getpass
import os
from pathlib import Path

def setup_configuration():
    """Interactive configuration setup"""
    
    print("CAST Highlight SBOM Generator - Configuration Setup")
    print("=" * 50)
    
    config = {
        "cast_highlight": {
            "api_url": "",
            "authentication": {
                "method": "",
                "username": "",
                "password": "",
                "company_id": "",
                "api_key": ""
            }
        },
        "sbom_settings": {
            "default_output_format": "json",
            "default_output_prefix": "sbom",
            "include_vulnerabilities": True,
            "include_licenses": True,
            "include_metadata": True
        },
        "compliance": {
            "sbom_version": "1.0",
            "tool_name": "CAST Highlight SBOM Generator",
            "tool_version": "1.0"
        }
    }
    
    # Get API URL
    print("\n1. CAST Highlight API Configuration")
    print("-" * 30)
    
    default_url = "https://rpa.casthighlight.com/api"
    api_url = input(f"Enter CAST Highlight API URL (default: {default_url}): ").strip()
    config["cast_highlight"]["api_url"] = api_url if api_url else default_url
    
    # Choose authentication method
    print("\n2. Authentication Method")
    print("-" * 30)
    print("Choose your authentication method:")
    print("1. Username/Password (Recommended)")
    print("2. API Key")
    
    while True:
        choice = input("Enter your choice (1 or 2): ").strip()
        if choice in ['1', '2']:
            break
        print("Please enter 1 or 2")
    
    if choice == '1':
        # Username/Password authentication
        config["cast_highlight"]["authentication"]["method"] = "credentials"
        
        username = input("Enter your CAST Highlight username: ").strip()
        if not username:
            print("Username is required!")
            return
        
        password = getpass.getpass("Enter your CAST Highlight password: ")
        if not password:
            print("Password is required!")
            return
        
        company_id = input("Enter your company ID (optional, press Enter to skip): ").strip()
        
        config["cast_highlight"]["authentication"]["username"] = username
        config["cast_highlight"]["authentication"]["password"] = password
        config["cast_highlight"]["authentication"]["company_id"] = company_id
        
    else:
        # API Key authentication
        config["cast_highlight"]["authentication"]["method"] = "api_key"
        
        api_key = getpass.getpass("Enter your CAST Highlight API key: ")
        if not api_key:
            print("API key is required!")
            return
        
        config["cast_highlight"]["authentication"]["api_key"] = api_key
    
    # SBOM Settings
    print("\n3. SBOM Generation Settings")
    print("-" * 30)
    
    output_format = input("Default output format (json/csv/spdx/all, default: json): ").strip()
    if output_format in ['json', 'csv', 'spdx', 'all']:
        config["sbom_settings"]["default_output_format"] = output_format
    
    output_prefix = input("Default output filename prefix (default: sbom): ").strip()
    if output_prefix:
        config["sbom_settings"]["default_output_prefix"] = output_prefix
    
    # Save configuration
    print("\n4. Save Configuration")
    print("-" * 30)
    
    config_file = "config/config.json"
    save_path = input(f"Configuration file path (default: {config_file}): ").strip()
    if save_path:
        config_file = save_path
    
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"\n✅ Configuration saved to {config_file}")
        
        # Show usage example
        print("\n📋 Usage Example:")
        if config["cast_highlight"]["authentication"]["method"] == "credentials":
            print(f"python sbom_generator.py \\")
            print(f"    --api-url \"{config['cast_highlight']['api_url']}\" \\")
            print(f"    --username \"{config['cast_highlight']['authentication']['username']}\" \\")
            print(f"    --password \"[your-password]\" \\")
            if config['cast_highlight']['authentication']['company_id']:
                print(f"    --company-id \"{config['cast_highlight']['authentication']['company_id']}\" \\")
            print(f"    --app-id \"your-application-id\"")
        else:
            print(f"python sbom_generator.py \\")
            print(f"    --api-url \"{config['cast_highlight']['api_url']}\" \\")
            print(f"    --api-key \"[your-api-key]\" \\")
            print(f"    --app-id \"your-application-id\"")
        
        print(f"\n💡 You can also use the configuration file in your scripts:")
        print(f"   from sbom_generator import CASTHighlightAPI, SBOMGenerator")
        print(f"   import json")
        print(f"   ")
        print(f"   with open('{config_file}', 'r') as f:")
        print(f"       config = json.load(f)")
        print(f"   ")
        print(f"   # Initialize API client using config")
        print(f"   # ... rest of your code")
        
    except Exception as e:
        print(f"❌ Error saving configuration: {e}")
        return

def load_config(config_file: str = "config/config.json"):
    """Load configuration from file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Configuration file {config_file} not found. Run setup first.")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON in configuration file {config_file}")
        return None

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "load":
        # Load and display configuration
        config = load_config()
        if config:
            print("Current Configuration:")
            print(json.dumps(config, indent=2))
    else:
        # Interactive setup
        setup_configuration()

if __name__ == "__main__":
    main() 