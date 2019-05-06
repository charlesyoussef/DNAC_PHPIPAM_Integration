#!/usr/bin/env python
"""DNA Center and Phpipam IPAM Integration:

This script automatically syncs the DNAC host information inside the specified IPAM subnet.
It does so by:
1. Importing the host Database from DNAC and adding it to Phpipam.
2. Deleting any any stale hosts (addresses in IPAM terms) from the corresponding Phpipam subnet.

The RBAC control on the subnet management is natively built inside Phpipam,
which can be easily consumed from the Web interface of Phpipam.

"""

import json
import requests
import time
import env_lab

from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()

# DNAC Variables:
DNAC_HOST = env_lab.DNA_CENTER['host']
DNAC_USER = env_lab.DNA_CENTER['username']
DNAC_PASSWORD = env_lab.DNA_CENTER['password']
DNAC_PORT = env_lab.DNA_CENTER['port']

# IPAM Variables:
PHPIPAM_HOST = env_lab.PHPIPAM['host']
PHPIPAM_USER = env_lab.PHPIPAM['username']
PHPIPAM_PASSWORD = env_lab.PHPIPAM['password']
PHPIPAM_PORT = env_lab.PHPIPAM['port']
PHPIPAM_APPID = env_lab.PHPIPAM['app_id']
PHPIPAM_SUBNET_ID = int(env_lab.PHPIPAM['subnetId'])

# DNAC Functions:
def dnac_get_auth_token(controller_ip=DNAC_HOST, username=DNAC_USER, password=DNAC_PASSWORD, port=DNAC_PORT):
    """ Authenticates with controller and returns a token to be used in subsequent API invocations
    """

    login_url = "https://{0}:{1}/api/system/v1/auth/token".format(controller_ip, port)
    result = requests.post(url=login_url, auth=HTTPBasicAuth(username, password), verify=False)
    result.raise_for_status()

    token = result.json()["Token"]
    return {
        "controller_ip": controller_ip,
        "token": token
    }

def dnac_create_url(path, controller_ip=DNAC_HOST, port=DNAC_PORT):
    """ Helper function to create a DNAC API endpoint URL using v1 URI
    """

    return "https://%s:%s/api/v1/%s" % (controller_ip, port, path)

def dnac_create_url_v2(path, controller_ip=DNAC_HOST, port=DNAC_PORT):
    """ Helper function to create a DNAC API endpoint URL using v2 URI
    """

    return "https://%s:%s/api/v2/%s" % (controller_ip, port, path)

def dnac_get_url(url):
    """ Helper function to get data from a DNAC endpoint v1 URI
    """
    url = dnac_create_url(path=url)
    token = dnac_get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)

    return response.json()

def dnac_get_url_v2(url):
    """ Helper function to get data from a DNAC endpoint v2 URI
    """
    url = dnac_create_url_v2(path=url)
    token = dnac_get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)

    return response.json()

# IPAM Functions:
def ipam_get_auth_token(ipam_ip=PHPIPAM_HOST, port=PHPIPAM_PORT, username=PHPIPAM_USER, password=PHPIPAM_PASSWORD, app_id=PHPIPAM_APPID):
    """ Authenticates with IPAM and returns a token to be used in subsequent API invocations
    """
    login_url = "http://{0}:{1}/api/{2}/user/".format(ipam_ip, port, app_id)
    result = requests.post(url=login_url, auth=HTTPBasicAuth(username, password), verify=False)
    result.raise_for_status()

    token = result.json()["data"]["token"]
    return {
        "ipam_ip": ipam_ip,
        "token": token
    }

def ipam_create_url(path, ipam_ip=PHPIPAM_HOST, port=PHPIPAM_PORT, app_id=PHPIPAM_APPID):
    """ Helper function to create a PHPIPAM API endpoint URL
    """
    return "http://%s:%s/api/%s/%s" % (ipam_ip, port, app_id, path)

def ipam_get_url(url):
    """ Helper function to get data from a PHPIPAM endpoint URL
    """
    url = ipam_create_url(path=url)
    token = ipam_get_auth_token()
    headers = {'token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)

    return response.json()

# Executables:
def main():
    #pools = dnac_get_url_v2("ippool")
    #sites = dnac_get_url("group?groupType=SITE")

    # Get the current time, to be used to tag addresses inserted in IPAM:
    time_tag = int(time.time())

    # Get the list of hosts from DNAC:
    hosts_response = dnac_get_url("host")
    hosts_list = hosts_response["response"]

    # Authenticate/refresh the token to IPAM:
    ipam_token = ipam_get_auth_token()["token"]
    ipam_addresses_url = ipam_create_url("addresses")

    # Add the DNAC hosts to the IPAM subnet defined globally:
    for host in hosts_list:
        payload = {
            "subnetId": str(PHPIPAM_SUBNET_ID),
            "ip": host["hostIp"],
            "is_gateway": "0",
            "description": "Connected to %s port %s" % (host["connectedNetworkDeviceName"], host["connectedInterfaceName"]),
            "hostname": host["id"],
            "mac": host["hostMac"],
            "note": time_tag
        }

        # This is a sample host:
        """payload = {
            "subnetId": "9",
            "ip": "10.10.22.73",
            "is_gateway": "0",
            "description": "Connected to %s port %s" % ("catalyst9k1", "GigabitEthernet1/0/17"),
            "hostname": "server101",
            "mac": "00:00:11:22:33:44",
            "note": "1557128081"
        }"""

        # Add the host to the IPAM:
        ipam_response = requests.request("POST", ipam_addresses_url, data=json.dumps(payload), headers={'token': ipam_token, 'Content-Type': "application/json"})
        #print("response is:" + ipam_response.text)

        if ipam_response.status_code == 201:
            # The host was not present in IPAM DB, so it got newly added:
            print("Added host %s to IPAM DB" % (host["hostIp"]))
        elif ipam_response.status_code < 500:
            # The host already exists in IPAM DB, so we just need to update the "note" tag with the current time_tag:
            print("Host %s already exists in IPAM DB" % (host["hostIp"]))
            # Strip the "subnetId" and "ip" keys as they can't be sent in an address update call:
            payload.pop("subnetId")
            ip_address = payload.pop("ip")
            # Get the "id" of this host IP address:
            ipam_search_address_response = ipam_get_url("addresses/search/%s/" %(ip_address))
            ip_address_id = ipam_search_address_response["data"][0]["id"]
            # Send the update API call:
            ipam_address_update_url = "http://%s:%s/api/%s/addresses/%s/" % (PHPIPAM_HOST, PHPIPAM_PORT, PHPIPAM_APPID, ip_address_id)
            ipam_address_update_response = requests.request("PATCH", ipam_address_update_url, data=json.dumps(payload), headers={'token': ipam_token, 'Content-Type': "application/json"})
        else:
            # The IPAM server returned a 5xx status code: Error on server side:
            print("IPAM DB Server side error. Retry later.")
            sys.exit(1)

    # Now verify the IPAM subnet usage:
    ipam_subnet_response = ipam_get_url("subnets/%s/usage/" %(PHPIPAM_SUBNET_ID))
    #print(ipam_subnet_response)
    if ipam_subnet_response["success"]:
        print("{0:20}{1:20}{2:20}{3:20}{4:20}".
            format("Subnet ID","Used Hosts","Free Hosts",
            "Used Percent","Freehosts Percent"))
        print("{0:20}{1:20}{2:20}{3:20}{4:20}".
            format(str(PHPIPAM_SUBNET_ID), ipam_subnet_response["data"]["used"], ipam_subnet_response["data"]["freehosts"],
            str(ipam_subnet_response["data"]["Used_percent"]), str(ipam_subnet_response["data"]["freehosts_percent"])))
    else:
        print("Unable to get the subnet usage info from the IPAM.")
        sys.exit(1)

    # Now delete the non-existent hosts from IPAM DB, which are the ones that did not get a new time "note":
    subnet_addresses_response = ipam_get_url("subnets/%s/addresses/" %(PHPIPAM_SUBNET_ID))
    if subnet_addresses_response["success"]:
        for host in subnet_addresses_response["data"]:
            if host["note"] != time_tag:
                # If the tag does not match time_tag, the host was not updated in this run
                # so need to delete it. Else, do nothing
                ipam_address_delete_url = "http://%s:%s/api/%s/addresses/%s/" % (PHPIPAM_HOST, PHPIPAM_PORT, PHPIPAM_APPID, host["id"])
                ipam_address_delete_response = requests.request("DELETE", ipam_address_delete_url, headers={'token': ipam_token, 'Content-Type': "application/json"})
                if ipam_address_delete_response.status_code == 200:
                    print("Host %s was deleted from IPAM DB" %(host["ip"]))
                else:
                    print("Could not delete Host %s. Returned message from server: %s" %(host["ip"], ipam_address_delete_response.json()["message"]))
    else:
        # Could not get the addresses from the IPAM subnet
        print("Unable to get the subnet addresses from the IPAM.")
        sys.exit(1)


if __name__ == "__main__":
    main()
