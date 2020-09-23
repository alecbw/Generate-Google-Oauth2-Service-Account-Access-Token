import os
import time
import json 
import sys

import requests
import jwt

# import google.auth
# from google.auth import jwt


def open_private_key_json():
    json_files = [f for f in os.listdir('.') if ".json" in f and os.path.isfile(f)]
    if len(json_files) == 0:
        sys.exit("Make sure you have downloaded the .json private key from the API Console GUI")

    sa_keyfile = json_files[0]

    pwd = os.path.dirname(os.path.abspath(__file__))

    with open(pwd + "/" + sa_keyfile) as f_in:
        return(json.load(f_in, strict=False))


def generate_jwt(opened_private_key, sa_email, url):

    iat = time.time()
    exp = iat + 3600
    payload = {
        'iss': sa_email, # '123456-compute@developer.gserviceaccount.com',
        'sub': sa_email, #'123456-compute@developer.gserviceaccount.com',
        'aud': url, 
        'iat': iat,
        'exp': exp,
        "scope": "https://www.googleapis.com/auth/analytics",
    }

    additional_headers = {'kid': opened_private_key["private_key_id"]}
    signed_jwt = jwt.encode(
        payload, 
        opened_private_key["private_key"], 
        headers=additional_headers,
        algorithm='RS256'
    )
    return signed_jwt


def make_jwt_request(signed_jwt, url):
    """Makes an authorized request to the endpoint"""
    headers = {
        'Authorization': 'Bearer {}'.format(signed_jwt),
        'content-type': "application/x-www-form-urlencoded",
    }
    body = {
        'grant_type': "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt,
    }

    response = requests.post(url, headers=headers, data=body)
    response.raise_for_status()

    print(response.json()) #.get("access_token"))


if __name__ == '__main__':

    opened_private_key = open_private_key_json()

    google_oauth_endpoint = "https://oauth2.googleapis.com/token"
    
    jwt = generate_jwt(opened_private_key, os.environ["SA_EMAIL"], google_oauth_endpoint)

    make_jwt_request(jwt, google_oauth_endpoint)


