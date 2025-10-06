#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2025, CIRCL and Luciano Righetti
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the AGPL-3.0 license


import json
import os
import re
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_HASHES = 3
ERR_NO_RESPONSE_MISP = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
    from requests.exceptions import Timeout
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration:
# <integration>
#   <name>misp_file_hashes.py</name>
#   <hook_url>misp_url</hook_url> <!-- Replace with your MISP host -->
#   <api_key>API_KEY</api_key> <!-- Replace with your MISP API key -->
#   <group>syscheck</group>
#   <alert_format>json</alert_format>
#   <options>{
#       "timeout": 10,
#       "retries": 3,
#       "debug": false,
#       "tags": ["tlp:white", "tlp:clear", "malware"],
#       "push_sightings": true,
#       "sightings_source": "wazuh"
#   }</options>
# </integration>


# Global vars
debug_enabled = False
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log and socket path
LOG_FILE = f"{pwd}/logs/integrations.log"
SOCKET_ADDR = f"{pwd}/queue/sockets/queue"

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
MISP_URL_INDEX = 3
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7


def main(args):
    global debug_enabled
    global timeout
    global retries
    global json_options
    try:
        # Read arguments
        bad_arguments: bool = False
        msg = ""
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == "debug"

        # Logging the call
        with open(LOG_FILE, "a") as f:
            f.write(msg)

        if bad_arguments:
            debug("# Error: Exiting, bad arguments. Inputted: %s" % args)
            sys.exit(ERR_BAD_ARGUMENTS)
        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    global debug_enabled
    global timeout
    global retries
    global json_options
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug("# Running MISP File Hashes script")

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    misp_url: str = args[MISP_URL_INDEX]
    apikey: str = args[APIKEY_INDEX]
    options_file_location: str = ""

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == "options":
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")
    if "timeout" in json_options:
        if isinstance(json_options["timeout"], int) and json_options["timeout"] > 0:
            timeout = json_options["timeout"]
        else:
            debug("# Warning: Invalid timeout value. Using default")

    if "retries" in json_options:
        if isinstance(json_options["retries"], int) and json_options["retries"] >= 0:
            retries = json_options["retries"]
        else:
            debug("# Warning: Invalid retries value. Using default")
    if "debug" in json_options:
        if isinstance(json_options["debug"], bool):
            debug_enabled = json_options["debug"]
        else:
            debug("# Warning: Invalid debug value. Using default")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    # Request MISP info
    debug("# Requesting MISP information")
    msg: any = request_misp_info(json_alert, misp_url, apikey)

    if not msg:
        debug("# Error: Empty message")
        raise Exception

    send_msg(msg, json_alert["agent"])


def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


def request_hash_from_api(hashes, alert_output, misp_url, api_key):
    """Request information from an API using the provided alert and API key.

    Parameters
    ----------
    alert : dict
        The alert dictionary containing information for the API request.
    alert_output : dict
        The output dictionary where API response information will be stored.
    misp_url : str
        The MISP host URL.
    api_key : str
        The API key required for making the API request.

    Returns
    -------
    dict
        The response data received from the API.

    Raises
    ------
    Timeout
        If the API request times out.
    Exception
        If an unexpected exception occurs during the API request.
    """

    for attempt in range(retries + 1):
        try:
            misp_response_data = query_api(hashes, misp_url, api_key)
            return misp_response_data
        except Timeout:
            debug(
                "# Error: Request timed out. Remaining retries: %s"
                % (retries - attempt)
            )
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_MISP)

    debug("# Error: Request timed out and maximum number of retries was exceeded")
    alert_output["misp_file_hashes"]["error"] = 408
    alert_output["misp_file_hashes"]["description"] = "Error: API request timed out"
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_MISP)


def push_misp_sighting(misp_url: str, api_key: str, hashes: dict):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python library-client-Wazuh-MISP",
        "Authorization": api_key,
    }

    debug("# Querying MISP API")

    add_sighting_payload = {"values": list(hashes.values()), "source": "wazuh"}

    if "sightings_source" in json_options:
        if isinstance(json_options["sightings_source"], str):
            add_sighting_payload["source"] = json_options["sightings_source"]
        else:
            debug("# Warning: Invalid sightings_source value. Ignoring")

    debug("# MISP API request payload: %s" % (json.dumps(add_sighting_payload)))

    response = requests.post(
        f"{misp_url}/sightings/add",
        json=add_sighting_payload,
        headers=headers,
        timeout=timeout,
    )

    if response.status_code == 200:
        debug("# MISP Sighting pushed successfully")
    else:
        debug("# An error occurred pushing MISP sighting: %s" % (response.text))


def request_misp_info(alert: any, misp_url: str, api_key: str):
    """Generate the JSON object with the message to be send

    Parameters
    ----------
    alert : any
        JSON alert object.
    misp_url : str
        The MISP host URL.
    apikey : str
        The API key required for making the API request.

    Returns
    -------
    msg: str
        The JSON message to send
    """
    alert_output = {"misp_file_hashes": {}, "integration": "misp_file_hashes"}

    # If there is no syscheck block present in the alert. Exit.
    if "syscheck" not in alert:
        debug("# No syscheck block present in the alert")
        return None
    # If there is no hashes checksum present in the alert. Exit.
    if any(
        x not in alert["syscheck"] for x in ("md5_after", "sha1_after", "sha256_after")
    ):
        debug("# No md5, sha1 or sha256 checksums present in the alert")
        return None

    hashes = {}

    # If the md5_after field is not a md5 hash checksum. Skip.
    if not (
        isinstance(alert["syscheck"]["md5_after"], str) is True
        and len(
            re.findall(r"\b([a-f\d]{32}|[A-F\d]{32})\b", alert["syscheck"]["md5_after"])
        )
        == 1
    ):
        debug("# md5_after field in the alert is not a md5 hash checksum")
    else:
        hashes["md5"] = alert["syscheck"]["md5_after"]

    # If the sha1_after field is not a sha1 hash checksum. Skip.
    if not (
        isinstance(alert["syscheck"]["sha1_after"], str) is True
        and len(
            re.findall(
                r"\b([a-f\d]{40}|[A-F\d]{40})\b", alert["syscheck"]["sha1_after"]
            )
        )
        == 1
    ):
        debug("# sha1_after field in the alert is not a sha1 hash checksum")
    else:
        hashes["sha1"] = alert["syscheck"]["sha1_after"]

    # If the sha256_after field is not a sha256 hash checksum. Skip.
    if not (
        isinstance(alert["syscheck"]["sha256_after"], str) is True
        and len(
            re.findall(
                r"\b([a-f\d]{64}|[A-F\d]{64})\b", alert["syscheck"]["sha256_after"]
            )
        )
        == 1
    ):
        debug("# sha256_after field in the alert is not a sha256 hash checksum")
    else:
        hashes["sha256"] = alert["syscheck"]["sha256_after"]

    if not hashes.get("md5") and not hashes.get("sha1") and not hashes.get("sha256"):
        debug("# No valid hash checksum found in the alert")
        sys.exit(ERR_BAD_HASHES)

    # Request info using MISP API
    misp_response_data = request_hash_from_api(hashes, alert_output, misp_url, api_key)

    alert_output["misp_file_hashes"]["found"] = 0
    alert_output["misp_file_hashes"]["source"] = {
        "alert_id": alert["id"],
        "file": alert["syscheck"]["path"],
        "md5": alert["syscheck"]["md5_after"] or None,
        "sha1": alert["syscheck"]["sha1_after"] or None,
        "sha256": alert["syscheck"]["sha256_after"] or None,
    }

    # Check if MISP has any info about the hash
    if misp_response_data.get("response", {}).get("Attribute", []) != []:
        alert_output["misp_file_hashes"]["found"] = 1
    else:
        debug("# No information found in MISP for the provided hash(es)")
        return alert_output

    misp_attribute = misp_response_data.get("response").get("Attribute")[0]
    event_uuid = misp_attribute.get("Event").get("uuid")
    attribute_uuid = misp_attribute.get("uuid")

    # Info about the file found in MISP
    if alert_output["misp_file_hashes"]["found"] == 1:
        # Populate JSON Output object with MISP request
        alert_output["misp_file_hashes"].update(
            {
                "type": misp_attribute["type"],
                "value": misp_attribute["value"],
                "uuid": attribute_uuid,
                "timestamp": misp_attribute["timestamp"],
                "event_uuid": event_uuid,
                "permalink": f"{misp_url}/events/view/{event_uuid}/searchFor:{attribute_uuid}",
            }
        )

    if "push_sightings" in json_options and json_options["push_sightings"]:
        push_misp_sighting(misp_url, api_key, hashes)

    return alert_output


def query_api(hashes: dict, misp_url: str, api_key: str) -> any:
    """Send a request to MISP API and fetch information to build message

    Parameters
    ----------
    hash : str
        Hash need it for parameters
    apikey: str
        Authentication API

    Returns
    -------
    data: any
        JSON with the response

    Raises
    ------
    Exception
        If the status code is different than 200.
    """
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python library-client-Wazuh-MISP",
        "Authorization": api_key,
    }

    debug("# Querying MISP API")

    rest_search_payload = {
        "value": list(hashes.values()),
        "type": ["md5", "sha1", "sha256"],
        "to_ids": 1,
        "includeEventTags": 0,
        "includeProposals": 0,
        "includeContext": 0,
        "withAttachments": 0,
        "returnFormat": "json",
        "page": 1,
        "limit": 1,
    }

    if "tags" in json_options:
        if isinstance(json_options["tags"], list) and all(
            isinstance(tag, str) for tag in json_options["tags"]
        ):
            rest_search_payload["tags"] = json_options["tags"]
        else:
            debug("# Warning: Invalid tags value. Ignoring")

    debug("# MISP API request payload: %s" % (json.dumps(rest_search_payload)))

    response = requests.post(
        f"{misp_url}/attributes/restSearch",
        json=rest_search_payload,
        headers=headers,
        timeout=timeout,
    )

    if response.status_code == 200:
        json_response = response.json()
        misp_response_data = json_response

        return misp_response_data
    else:
        alert_output = {}
        alert_output["misp_file_hashes"] = {}
        alert_output["integration"] = "misp_file_hashes"

        if response.status_code == 429:
            alert_output["misp_file_hashes"]["error"] = response.status_code
            alert_output["misp_file_hashes"][
                "description"
            ] = "Error: API request rate limit reached"
            send_msg(alert_output)
            raise Exception("# Error: MISP API request rate limit reached")
        if response.status_code == 403:
            alert_output["misp_file_hashes"]["error"] = response.status_code
            alert_output["misp_file_hashes"]["description"] = "Error: Check credentials"
            send_msg(alert_output)
            raise Exception("# Error: MISP credentials, required privileges error")
        else:
            alert_output["misp_file_hashes"]["error"] = response.status_code
            alert_output["misp_file_hashes"]["description"] = "Error: API request fail"
            send_msg(alert_output)
            raise Exception("# Error: MISP credentials, required privileges error")


def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent["id"] == "000":
        string = "1:misp_file_hashes:{0}".format(json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(
            agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any"
        )
        location = location.replace("|", "||").replace(":", "|:")
        string = "1:{0}->misp_file_hashes:{1}".format(location, json.dumps(msg))

    debug("# Request result from MISP server: %s" % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug("# Error: Unable to open socket connection at %s" % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting JSON alert. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug("Failed getting JSON options. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == "__main__":
    main(sys.argv)
