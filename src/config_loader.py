import json
import os

class ConfigError(Exception):
    pass

def load_config(config_path):
    if not os.path.exists(config_path):
        raise ConfigError(f"Config file {config_path} not found.")
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    # Validate required fields
    try:
        ch = config['cast_highlight']
        auth = ch['authentication']
        method = auth['method']
        if method == 'api_key':
            if not auth.get('api_key'):
                raise ConfigError('API key is required for api_key authentication.')
        elif method == 'credentials':
            if not (auth.get('username') and auth.get('password') and auth.get('company_id')):
                raise ConfigError('username, password, and company_id are required for credentials authentication.')
        else:
            raise ConfigError('Unknown authentication method.')
        if not config.get('application_id'):
            raise ConfigError('application_id is required.')
    except KeyError as e:
        raise ConfigError(f'Missing required config field: {e}')
    return config 