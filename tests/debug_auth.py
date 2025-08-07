#!/usr/bin/env python3
"""
Debug script to test different authentication methods for CAST Highlight API.
"""

import requests
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_auth_endpoints():
    """Test different authentication endpoints"""
    
    base_url = "https://rpa.casthighlight.com"
    username = "abhishek.sinha+Sandbox@castsoftware.com"
    password = "P@55word!022"
    company_id = "10296"
    
    # Test different authentication endpoints
    auth_endpoints = [
        "/WS2/auth/login",
        "/WS2/auth",
        "/auth/login", 
        "/auth",
        "/api/auth/login",
        "/api/auth",
        "/login",
        "/api/login"
    ]
    
    for endpoint in auth_endpoints:
        logger.info(f"Testing endpoint: {endpoint}")
        
        try:
            auth_data = {
                "username": username,
                "password": password
            }
            
            if company_id:
                auth_data["companyId"] = company_id
            
            url = f"{base_url}{endpoint}"
            logger.info(f"URL: {url}")
            
            response = requests.post(url, json=auth_data, timeout=10)
            logger.info(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                logger.info("✅ SUCCESS! Found working authentication endpoint")
                logger.info(f"Response: {response.text[:200]}...")
                return endpoint, response.json()
            elif response.status_code == 401:
                logger.warning("❌ 401 Unauthorized")
            elif response.status_code == 404:
                logger.warning("❌ 404 Not Found")
            else:
                logger.warning(f"❌ Status {response.status_code}: {response.text[:100]}...")
                
        except Exception as e:
            logger.error(f"❌ Error: {e}")
    
    return None, None

def test_basic_auth():
    """Test basic HTTP authentication"""
    logger.info("Testing Basic HTTP Authentication")
    
    base_url = "https://rpa.casthighlight.com"
    username = "abhishek.sinha+Sandbox@castsoftware.com"
    password = "P@55word!022"
    company_id = "10296"
    
    # Test different endpoints with basic auth
    test_endpoints = [
        "/WS2/domains/{company_id}/applications/",
        "/domains/{company_id}/applications/",
        "/api/domains/{company_id}/applications/",
        "/applications/"
    ]
    
    for endpoint in test_endpoints:
        try:
            url = f"{base_url}{endpoint.format(company_id=company_id)}"
            logger.info(f"Testing: {url}")
            
            response = requests.get(url, auth=(username, password), timeout=10)
            logger.info(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                logger.info("✅ SUCCESS! Basic auth works")
                logger.info(f"Response: {response.text[:200]}...")
                return True
            elif response.status_code == 401:
                logger.warning("❌ 401 Unauthorized")
            elif response.status_code == 404:
                logger.warning("❌ 404 Not Found")
            else:
                logger.warning(f"❌ Status {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Error: {e}")
    
    return False

def test_api_key_auth():
    """Test API key authentication"""
    logger.info("Testing API Key Authentication")
    
    # Try with the old API key to see if it still works
    api_key = "3049a976-429f-42bb-aa2b-2393439c1588"
    base_url = "https://rpa.casthighlight.com"
    company_id = "10296"
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Accept': 'application/json'
    }
    
    try:
        url = f"{base_url}/WS2/domains/{company_id}/applications/"
        logger.info(f"Testing: {url}")
        
        response = requests.get(url, headers=headers, timeout=10)
        logger.info(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            logger.info("✅ SUCCESS! API key auth still works")
            logger.info(f"Response: {response.text[:200]}...")
            return True
        else:
            logger.warning(f"❌ Status {response.status_code}: {response.text[:100]}...")
            
    except Exception as e:
        logger.error(f"❌ Error: {e}")
    
    return False

def main():
    """Main function"""
    print("CAST Highlight API Authentication Debug")
    print("=" * 40)
    
    # Test 1: Different auth endpoints
    print("\n1. Testing different authentication endpoints...")
    working_endpoint, auth_response = test_auth_endpoints()
    
    if working_endpoint:
        print(f"\n✅ Found working authentication endpoint: {working_endpoint}")
        return
    
    # Test 2: Basic HTTP authentication
    print("\n2. Testing Basic HTTP Authentication...")
    if test_basic_auth():
        print("\n✅ Basic HTTP authentication works!")
        return
    
    # Test 3: API key authentication
    print("\n3. Testing API Key Authentication...")
    if test_api_key_auth():
        print("\n✅ API key authentication still works!")
        return
    
    print("\n❌ No authentication method worked.")
    print("Please check with CAST Highlight support for the correct authentication method.")

if __name__ == "__main__":
    main() 