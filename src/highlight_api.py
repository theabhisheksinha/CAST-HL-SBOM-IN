import logging
import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, List, Optional
from logging_config import setup_module_logging

# Set up separated logging for highlight_api module
logger, log_files = setup_module_logging('highlight_api')

class HighlightAPI:
    def __init__(self, base_url, company_id, auth_method, username=None, password=None, api_key=None):
        self.company_id = company_id
        self.session = requests.Session()
        # Ensure base_url ends with /WS2
        self.base_url = base_url.rstrip('/')
        if not self.base_url.endswith('/WS2'):
            self.base_url = self.base_url + '/WS2'
        self.auth_method = auth_method
        self.username = username
        self.password = password
        self.api_key = api_key
        self._setup_auth()

    def _setup_auth(self):
        if self.auth_method == 'api_key' and self.api_key:
            self.session.headers['X-Api-Key'] = self.api_key
            self.session.headers['Accept'] = 'application/json'
        elif self.auth_method == 'credentials' and self.username and self.password:
            self.session.auth = HTTPBasicAuth(self.username, self.password)
            self.session.headers['Accept'] = 'application/json'
        else:
            raise ValueError('Unknown or incomplete authentication method/fields')

    def list_applications(self):
        """Get list of all applications in the domain"""
        url = f'{self.base_url}/domains/{self.company_id}/applications/'
        try:
            resp = self.session.get(url)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list applications: {e}")
            # Try alternative endpoint structure
            try:
                url_alt = f'{self.base_url}/domains/{self.company_id}/applications'
                resp_alt = self.session.get(url_alt)
                resp_alt.raise_for_status()
                return resp_alt.json()
            except requests.exceptions.RequestException as e2:
                logger.error(f"Alternative endpoint also failed: {e2}")
                return []

    def get_application_by_id(self, app_id):
        """Get detailed information about a specific application"""
        url = f'{self.base_url}/domains/{self.company_id}/applications/{app_id}'
        try:
            resp = self.session.get(url)
            if resp.status_code == 404:
                logger.warning(f"Application {app_id} not found")
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get application {app_id}: {e}")
            return None

    def get_third_party_data(self, app_id):
        """Get third-party component data (primary SBOM source)"""
        url = f'{self.base_url}/domains/{self.company_id}/applications/{app_id}/thirdparty'
        try:
            resp = self.session.get(url)
            if resp.status_code == 404:
                logger.warning(f"No third-party data found for application {app_id}")
                return None
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Retrieved third-party data for application {app_id}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get third-party data for {app_id}: {e}")
            return None

    def get_components_data(self, app_id):
        """Get detailed component information"""
        url = f'{self.base_url}/domains/{self.company_id}/applications/{app_id}/components'
        try:
            resp = self.session.get(url)
            if resp.status_code == 404:
                logger.warning(f"No component data found for application {app_id}")
                return None
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Retrieved component data for application {app_id}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get component data for {app_id}: {e}")
            return None

    def get_vulnerabilities(self, app_id):
        """Get security vulnerabilities for an application"""
        url = f'{self.base_url}/domains/{self.company_id}/applications/{app_id}/vulnerabilities'
        try:
            resp = self.session.get(url)
            if resp.status_code == 404:
                logger.warning(f"No vulnerability data found for application {app_id}")
                return []
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Retrieved vulnerability data for application {app_id}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get vulnerabilities for {app_id}: {e}")
            return []

    def get_licenses(self, app_id):
        """Get license information for an application"""
        url = f'{self.base_url}/domains/{self.company_id}/applications/{app_id}/licenses'
        try:
            resp = self.session.get(url)
            if resp.status_code == 404:
                logger.warning(f"No license data found for application {app_id}")
                return []
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Retrieved license data for application {app_id}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get licenses for {app_id}: {e}")
            return []

    def get_comprehensive_sbom_data(self, app_id):
        """Get comprehensive SBOM data from multiple endpoints"""
        logger.info(f"Fetching comprehensive SBOM data for application {app_id}")
        
        # Get all data sources
        third_party_data = self.get_third_party_data(app_id)
        components_data = self.get_components_data(app_id)
        vulnerabilities_data = self.get_vulnerabilities(app_id)
        licenses_data = self.get_licenses(app_id)
        
        # Combine and enrich the data
        combined_data = {
            'third_party': third_party_data,
            'components': components_data,
            'vulnerabilities': vulnerabilities_data,
            'licenses': licenses_data
        }
        
        logger.info(f"Comprehensive data collection completed for application {app_id}")
        return combined_data