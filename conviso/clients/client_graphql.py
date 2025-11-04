# conviso/clients/client_graphql.py
import os
import requests
from dotenv import load_dotenv
from conviso.core.logger import log

# Load environment variables from .env file
load_dotenv()

API_URL = "https://api.convisoappsec.com/graphql"
API_KEY = os.getenv("CONVISO_API_KEY")

if not API_KEY:
    raise EnvironmentError("⚠️ Missing CONVISO_API_KEY in .env file")

def graphql_request(query: str, variables: dict = None) -> dict:
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }

    payload = {"query": query, "variables": variables or {}}
    log(f"Sending GraphQL request to {API_URL}")
    response = requests.post(API_URL, json=payload, headers=headers)
    response.raise_for_status()

    data = response.json()
    if "errors" in data:
        raise Exception(f"GraphQL errors: {data['errors']}")

    return data["data"]
