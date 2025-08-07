#!/usr/bin/env python3
"""
Test script to check /vulnerabilities/aggregated/ endpoint for specific application ID 481502
"""

import requests
import json
import sys
import os
from requests.auth import HTTPBasicAuth
from src.sbom_generator import load_config, CASTHighlightAPI, SBOMGenerator

def load_config(config_path: str = "config.json") -> dict:
    """Load configuration from JSON file"""
    if not os.path.exists(config_path):
        print(f"Config file {config_path} not found.")
        sys.exit(1)
    with open(config_path, 'r') as f:
        config = json.load(f)
    return config

def test_specific_application():
    """Test vulnerabilities endpoint for application ID 481502"""
    config = load_config('config/config.json')
    
    # Extract configuration from nested structure
    cast_config = config.get('cast_highlight', {})
    auth_config = cast_config.get('authentication', {})
    
    base_url = cast_config.get('api_url', '').rstrip('/')
    if not base_url.endswith('/WS2'):
        base_url = base_url + '/WS2'
    username = auth_config.get('username')
    password = auth_config.get('password')
    company_id = auth_config.get('company_id')
    
    # Specific application ID to test
    app_id = "481502"
    
    # Setup authentication
    auth = HTTPBasicAuth(username, password)
    headers = {'Content-Type': 'application/json'}
    
    print(f"Testing CAST Highlight API for specific application")
    print(f"Base URL: {base_url}")
    print(f"Company ID: {company_id}")
    print(f"Application ID: {app_id}")
    print(f"Username: {username}")
    print("-" * 50)
    
    # Test the aggregated vulnerabilities endpoint
    print("Testing /vulnerabilities/aggregated/ endpoint...")
    try:
        url = f"{base_url}/domains/{company_id}/applications/{app_id}/vulnerabilities/aggregated/"
        print(f"URL: {url}")
        
        response = requests.get(url, headers=headers, auth=auth)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success! Response type: {type(data)}")
            if isinstance(data, list):
                print(f"📊 Found {len(data)} aggregated vulnerability records")
                if data:
                    print(f"📋 Sample aggregated vulnerability: {json.dumps(data[0], indent=2)}")
                    if len(data) > 1:
                        print(f"📋 Second record: {json.dumps(data[1], indent=2)}")
            elif isinstance(data, dict):
                print(f"📊 Response keys: {list(data.keys())}")
                print(f"📋 Full response: {json.dumps(data, indent=2)}")
        else:
            print(f"❌ Error: {response.text}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")

if __name__ == "__main__":
    test_specific_application() 