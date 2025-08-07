#!/usr/bin/env python3
"""
Test script to verify CAST Highlight API authentication with user credentials.
This script will test the connection and list available applications.
"""

import json
import sys
import logging
from src.config_loader import load_config, ConfigError
from src.sbom_generator import CASTHighlightAPI

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_credentials_auth():
    """Test authentication using username/password credentials"""
    
    try:
        # Load configuration
        config = load_config('config/config.json')
        ch_conf = config.get('cast_highlight', {})
        auth_conf = ch_conf.get('authentication', {})
        
        # Check authentication method
        method = auth_conf.get('method', 'credentials')
        if method != 'credentials':
            logger.error(f"Authentication method is set to '{method}', but this script tests credentials authentication.")
            logger.info("Please update your config.json to use 'credentials' method.")
            return False
        
        # Get credentials
        username = auth_conf.get('username')
        password = auth_conf.get('password')
        company_id = auth_conf.get('company_id')
        api_url = ch_conf.get('api_url')
        
        # Validate required fields
        if not username or username == 'YOUR_USERNAME_HERE':
            logger.error("Username not set in config.json. Please update with your actual username.")
            return False
            
        if not password or password == 'YOUR_PASSWORD_HERE':
            logger.error("Password not set in config.json. Please update with your actual password.")
            return False
            
        if not company_id or company_id == 'YOUR_COMPANY_ID_HERE':
            logger.error("Company ID not set in config.json. Please update with your actual company ID.")
            return False
            
        if not api_url:
            logger.error("API URL not set in config.json.")
            return False
        
        logger.info(f"Testing authentication with:")
        logger.info(f"  API URL: {api_url}")
        logger.info(f"  Username: {username}")
        logger.info(f"  Company ID: {company_id}")
        logger.info(f"  Method: {method}")
        
        # Initialize API with credentials
        cast_api = CASTHighlightAPI(
            api_url,
            username=username,
            password=password,
            company_id=company_id
        )
        
        logger.info("✅ Successfully initialized CAST Highlight API with credentials")
        
        # Test getting applications
        logger.info("Testing application list retrieval...")
        applications = cast_api.get_applications()
        
        if applications:
            logger.info(f"✅ Successfully retrieved {len(applications)} applications:")
            for app in applications[:5]:  # Show first 5 applications
                logger.info(f"  - ID: {app.get('id')}, Name: {app.get('name', 'N/A')}")
            if len(applications) > 5:
                logger.info(f"  ... and {len(applications) - 5} more applications")
        else:
            logger.warning("⚠️  No applications found. This might be normal if you don't have access to any applications.")
        
        # Test getting components for the first application (if any)
        if applications:
            first_app = applications[0]
            app_id = first_app.get('id')
            app_name = first_app.get('name', 'Unknown')
            
            if app_id:
                logger.info(f"Testing component retrieval for application: {app_name} (ID: {app_id})")
                components = cast_api.get_components(str(app_id))
            else:
                logger.warning("⚠️  First application has no ID, skipping component test")
                components = []
            
            if components:
                logger.info(f"✅ Successfully retrieved {len(components)} components")
            else:
                logger.warning("⚠️  No components found for this application")
        
        logger.info("🎉 Credentials authentication test completed successfully!")
        return True
        
    except ConfigError as e:
        logger.error(f"Configuration error: {e}")
        return False
    except Exception as e:
        logger.error(f"Authentication test failed: {e}")
        return False

def main():
    """Main function"""
    print("CAST Highlight API Credentials Authentication Test")
    print("=" * 50)
    
    success = test_credentials_auth()
    
    if success:
        print("\n✅ Authentication test PASSED!")
        print("Your credentials are working correctly.")
        print("You can now run the main SBOM generator:")
        print("  python sbom_generator.py")
    else:
        print("\n❌ Authentication test FAILED!")
        print("Please check your configuration and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main() 