import os
import time
import json 

import requests
import google.auth
# from google.auth import jwt

import jwt

def generate_jwt(sa_keyfile,
                 sa_email='account@project-id.iam.gserviceaccount.com',
                 audience='your-service-name',
                 expiry_length=3600):

    """Generates a signed JSON Web Token using a Google API Service Account."""

    now = int(time.time())

    jwt_header = {"alg":"RS256","typ":"JWT"}
    # build payload
    jwt_payload = {
        'iat': now,
        # expires after 'expiry_length' seconds.
        "exp": now + expiry_length,
        # iss must match 'issuer' in the security configuration in your
        # swagger spec (e.g. service account email). It can be any string.
        'iss': sa_email,
        # aud must be either your Endpoints service name, or match the value
        # specified as the 'x-google-audience' in the OpenAPI document.
        'aud':  audience,
        # sub and email should match the service account's email address
        # 'sub': "abarrett.wilsdon@gmail.com", #sa_email,
        # 'email': sa_email,
        "scope": "https://www.googleapis.com/auth/analytics",

    }
    pwd = os.path.dirname(os.path.abspath(__file__))

    payload = '{}.{}'.format(jwt_header, jwt_payload)
    # sign with keyfile
    signer = google.auth.crypt.RSASigner.from_service_account_file(pwd + "/" + sa_keyfile)
    jwt = google.auth.jwt.encode(signer, payload)
    print(jwt)

    return jwt

def generate_jwt2(sa_keyfile,  foobar):
    """Generates a signed JSON Web Token using the Google App Engine default
    service account."""
    now = int(time.time())

    header_json = json.dumps({
        "typ": "JWT",
        "alg": "RS256"})

    payload_json = json.dumps({
        "iat": now,
        # expires after one hour.
        "exp": now + 3600,
        # iss is the service account email.
        "iss": SERVICE_ACCOUNT_EMAIL,
        # target_audience is the URL of the target service.
        "target_audience": TARGET_AUD,
        # aud must be Google token endpoints URL.
        "aud": "https://www.googleapis.com/oauth2/v4/token",


    })

    header_and_payload = '{}.{}'.format(
        base64.urlsafe_b64encode(header_json),
        base64.urlsafe_b64encode(payload_json))
    (key_name, signature) = app_identity.sign_blob(header_and_payload)
    signed_jwt = '{}.{}'.format(
        header_and_payload,
        base64.urlsafe_b64encode(signature))

    return signed_jwt


def open_private_key_json():
    json_files = [f for f in os.listdir('.') if ".json" in f and os.path.isfile(f)]
    if len(json_files) == 0:
        sys.exit("Make sure you have downloaded the .json private key from the API Console GUI")

    sa_keyfile = json_files[0]

    pwd = os.path.dirname(os.path.abspath(__file__))

    with open(pwd + "/" + sa_keyfile) as f_in:
        return(json.load(f_in, strict=False))


def generate_jwt_3(opened_private_key, sa_email, audience):

    iat = time.time()
    exp = iat + 3600
    payload = {
        'iss': sa_email, # '123456-compute@developer.gserviceaccount.com',
        'sub': sa_email, #'123456-compute@developer.gserviceaccount.com',
        'aud': audience, 
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
    print(signed_jwt)
    return signed_jwt


def make_jwt_request(signed_jwt, url):
    """Makes an authorized request to the endpoint"""
    headers = {
        'Authorization': 'Bearer {}'.format(signed_jwt),#.decode('utf-8'), #
        'content-type': "application/x-www-form-urlencoded", #application/json'
    }
    body = {
        'grant_type': "urn:ietf:params:oauth:grant-type:jwt-bearer",
        # "intent": "get",
        # "scope": "https://www.googleapis.com/auth/analytics",
        "assertion": signed_jwt,
    }
    response = requests.post(url, headers=headers, data=body)
    print(response.status_code, response.content)
    response.raise_for_status()


if __name__ == '__main__':

    opened_private_key = open_private_key_json()

    google_oauth_endpoint = "https://oauth2.googleapis.com/token" #'https://accounts.google.com/o/oauth2/token' #"https://www.googleapis.com/oauth2/v4/token" #'
    
    jwt = generate_jwt_3(opened_private_key, os.environ["SA_EMAIL"], google_oauth_endpoint)

    make_jwt_request(jwt, google_oauth_endpoint)


