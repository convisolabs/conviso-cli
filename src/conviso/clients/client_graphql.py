# conviso/clients/client_graphql.py
import os
import requests
import json
from dotenv import load_dotenv
import conviso.core.logger as logger

# Load environment variables from .env file
load_dotenv()

API_URL = "https://api.convisoappsec.com/graphql"
API_KEY = os.getenv("CONVISO_API_KEY")
DEFAULT_TIMEOUT = float(os.getenv("CONVISO_API_TIMEOUT", "30"))


def graphql_request(query: str, variables: dict = None, log_request: bool = True, verbose_only: bool = False) -> dict:
    """Perform a GraphQL request with optional logging and timeout."""
    api_key = API_KEY or os.getenv("CONVISO_API_KEY")
    if not api_key:
        raise EnvironmentError("⚠️ Missing CONVISO_API_KEY in environment or .env file")

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }

    payload = {"query": query, "variables": variables or {}}
    if log_request:
        logger.log(f"Sending GraphQL request to {API_URL}", verbose_only=verbose_only)
        if logger.VERBOSE:
            logger.log(f"GraphQL variables: {payload['variables']}", verbose_only=True)

    response = requests.post(API_URL, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT)
    response.raise_for_status()

    data = response.json()
    if "errors" in data:
        if logger.VERBOSE:
            logger.log(f"GraphQL error payload: {data}", style="red", verbose_only=True)
        raise Exception(f"GraphQL errors: {data['errors']}")

    return data["data"]


def graphql_request_upload(
    query: str,
    variables: dict,
    file_param: str,
    file_path: str,
    log_request: bool = True,
    verbose_only: bool = False,
) -> dict:
    """
    Perform a GraphQL multipart request (Upload scalar).
    file_param: name of the variable for the Upload (e.g., "file").
    file_path: path to the file to upload.
    """
    api_key = API_KEY or os.getenv("CONVISO_API_KEY")
    if not api_key:
        raise EnvironmentError("⚠️ Missing CONVISO_API_KEY in environment or .env file")

    headers = {
        "x-api-key": api_key,
    }

    if log_request:
        logger.log(f"Sending GraphQL multipart request to {API_URL}", verbose_only=verbose_only)
        if logger.VERBOSE:
            logger.log(f"GraphQL variables: {variables}", verbose_only=True)

    operations = {"query": query, "variables": variables}
    map_part = {"0": [f"variables.{file_param}"]}

    with open(file_path, "rb") as f:
        files = {"0": f}
        response = requests.post(
            API_URL,
            data={"operations": json.dumps(operations), "map": json.dumps(map_part)},
            files=files,
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
        )

    response.raise_for_status()
    data = response.json()
    if "errors" in data:
        if logger.VERBOSE:
            logger.log(f"GraphQL error payload: {data}", style="red", verbose_only=True)
        raise Exception(f"GraphQL errors: {data['errors']}")
    return data["data"]
