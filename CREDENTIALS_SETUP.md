# CAST Highlight SBOM Generator: Credentials & Config Setup

This guide will help you set up the `config/config.json` file required for running the SBOM generator.

## 1. Locate Required Information

You will need:
- **API URL**: The base URL for your CAST Highlight instance (e.g., `https://rpa.casthighlight.com/WS2`)
- **Authentication Method**: Usually `credentials` (username/password) or `api_key`
- **Username & Password**: Your CAST Highlight login credentials (if using `credentials`)
- **API Key**: If using API key authentication (contact your CAST Highlight admin)
- **Company ID**: Your CAST Highlight company/domain ID (visible in the URL or from your admin)
- **Application ID**: The numeric ID of the application you want to generate an SBOM for (see below)

## 2. Example config/config.json

```
{
  "cast_highlight": {
    "api_url": "https://your-cast-highlight-url",
    "authentication": {
      "method": "credentials", // or "api_key"
      "username": "your-username",
      "password": "your-password",
      "company_id": "your-company-id"
      // "api_key": "your-api-key" // Only if using API key
    }
  },
  "application_id": "12345",
  "sbom_settings": {
    "output_formats": ["json", "xlsx", "cyclonedx", "docx", "csv"],
    "default_output_prefix": "sbom_sample"
  }
}
```

### Field Explanations
- **api_url**: The full base URL for the CAST Highlight API (usually ends with `/WS2`)
- **method**: `credentials` for username/password, or `api_key` for API key
- **username/password**: Your CAST Highlight login (do not share or commit these!)
- **company_id**: Numeric or alphanumeric company/domain ID
- **api_key**: Only needed if using API key authentication
- **application_id**: The ID of the application to generate the SBOM for (get this from the CAST Highlight UI or API)
- **output_formats**: List of formats to generate (choose any of: `json`, `xlsx`, `cyclonedx`, `docx`, `csv`)
- **default_output_prefix**: Prefix for generated SBOM files

## 3. How to Find Your Application ID
- Log in to CAST Highlight
- Go to your application dashboard
- The application ID is visible in the URL or via the API (see README for details)

## 4. Security Best Practices
- **Never commit your config/config.json with real credentials to version control!**
- Use environment variables or a secrets manager for production if possible
- Restrict access to the config directory

## 5. Troubleshooting
- **404 errors**: Check your API URL, company ID, and application ID
- **Authentication errors**: Double-check your username/password or API key
- **No SBOM generated**: Ensure your application has third-party data in CAST Highlight
- **Output format errors**: Only use supported formats in the `output_formats` list

## 6. More Information
- See the [README.md](README.md) for full usage, packaging, and advanced configuration details. 