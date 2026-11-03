"""Validate a downloaded Google Desktop client and save it locally, never in Git."""
import os
from pathlib import Path
import re
import shutil
import tempfile

from dotenv import set_key

ENV_PATH = Path(__file__).resolve().parents[2] / '.env'


def import_desktop_client(payload, env_path=None):
    if not isinstance(payload, dict) or not isinstance(payload.get('installed'), dict):
        raise ValueError('Choose the JSON file for a Google Desktop app client, not a Web application client.')
    installed = payload['installed']
    client_id, secret = installed.get('client_id'), installed.get('client_secret')
    if not isinstance(client_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,250}\.apps\.googleusercontent\.com', client_id):
        raise ValueError('This file does not contain a valid Google Desktop client ID.')
    if not isinstance(secret, str) or not 1 <= len(secret) <= 500 or any(ord(char) < 32 for char in secret):
        raise ValueError('This file does not contain valid Google client settings.')
    # Ignore file-supplied endpoint URLs: credentials go only to fixed Google URLs.
    updates = {'GOOGLE_CLIENT_ID': client_id, 'GOOGLE_CLIENT_SECRET': secret, 'GOOGLE_CLIENT_TYPE': 'desktop'}
    path = Path(env_path) if env_path is not None else ENV_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not path.with_name('.env.before-desktop').exists():
        shutil.copy2(path, path.with_name('.env.before-desktop'))
    descriptor, temporary = tempfile.mkstemp(prefix='.env.', suffix='.tmp', dir=path.parent)
    os.close(descriptor)
    try:
        if path.exists():
            shutil.copy2(path, temporary)
        for key, value in updates.items():
            set_key(temporary, key, value)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    os.environ.update(updates)
