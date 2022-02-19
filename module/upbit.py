import os
import config
import jwt
import uuid
import hashlib
from urllib.parse import urlencode

import requests

access_key = config.access_key
secret_key = config.secret_key
server_url = config.server_url

def coins() :
    payload = {
        'access_key': access_key,
        'nonce': str(uuid.uuid4()),
    }

    jwt_token = jwt.encode(payload, secret_key)
    authorize_token = 'Bearer {}'.format(jwt_token)
    headers = {"Authorization": authorize_token}

    res = requests.get(server_url + "/v1/accounts", headers=headers)

    print(res.json())


