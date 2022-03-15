#!/usr/bin/env python

from azure.identity import  CertificateCredential
from azure.mgmt.compute import ComputeManagementClient

from datetime import datetime, timedelta
from jinja2 import Template
from dateutil.parser import isoparse
import requests, json, os
import logging
import argparse

def define_vars():
    data = {
        'tenant_id'       : os.environ["AZURE_TENANT_ID"],
        'client_id'       : os.environ["AZURE_CLIENT_ID"],
        'subscription_id' : os.environ["AZURE_SUBSCRIPTION_ID"],
        'certificate_path': os.environ["AZURE_CERTIFICATE_PATH"],
        'my_ip'           : os.environ["MY_IP"],
        'my_id'           : os.environ["AZURE_ID"],
        'port_number'     : 22,
        'api_scope'       : "https://management.azure.com/.default"
    } 
    return data



def get_credential(data):
    try:
        credential = CertificateCredential(data['tenant_id'], data['client_id'], data['certificate_path'])
        return credential
    except:
        logger.critical("Unable to get a credential from Azure")
        exit(1)

 

def get_header(credential, api_scope):
    try:
        access_token = credential.get_token(api_scope)
        logger.debug("Successful login using certificates")
        logger.debug("Access token expires on {}".format(datetime.fromtimestamp(access_token.expires_on).isoformat()))
        headers = {   
            "Authorization": "Bearer {}".format(access_token.token), 
            "Content-Type":  "application/json" 
        }
        return headers
    except:
        logger.critical("Unsuccesful login")
        return {}


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


parser  = argparse.ArgumentParser()
parser.add_argument("--rg",      help="Resource Group of server")
parser.add_argument("--machine", help="Machine name to request JIT")
parser.add_argument("--ports",   help="List of ports to open for JIT")
ports = "22"
data               = define_vars()
try:
    args         = parser.parse_args()
    machine_name = args.machine
    if not args.rg:
        resource_group = os.environ["az_resource_group"]
    else:
        resource_group = args.rg
    if args.ports:
        ports = args.ports

    enable_ports = []
    initiate_ports = []
    for port in ports.split(','):
        enable_port = {}
        initiate_port = {}
        enable_port = {
            "number":  port,
            "protocol": "*",
            "allowedSourceAddressPrefix": data['my_ip'],
            "maxRequestAccessDuration":   "PT8H"
        }
        initiate_port = {
            "number": port,
            "duration": "PT8H",
            "allowedSourceAddressPrefix": data['my_ip']
        }
        enable_ports.append(enable_port)
        initiate_ports.append(initiate_port)
    
    data["enable_ports"]   = json.dumps(enable_ports)
    data["initiate_ports"] = json.dumps(initiate_ports)
except:
    print("Usage: ")
    print(f"       enable_jit.py [--rg resource_group_name ] '{'--machine NAME'}'")
    exit(1)

credential         = get_credential(data) 
try:
    compute_client     = ComputeManagementClient(credential, data['subscription_id']) 
    vm_details         = compute_client.virtual_machines.get(resource_group, machine_name)
except:
    logger.critical("Unable to get machine details from Azure")
    exit(1)

headers            = get_header(credential, data['api_scope'])

if headers:
    now                      = datetime.utcnow()
    delta                    = timedelta(seconds=1)
    data["start_time"]       = now.isoformat()
    data["end_time"]         = now.fromtimestamp(now.timestamp() + delta.seconds).isoformat()
    data["machine_id"]       = vm_details.id
    data["machine_location"] = vm_details.location

    jit_status_uri = "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Security/locations/{location}/jitNetworkAccessPolicies/{name}?api-version=2020-01-01".format(
                              subscription=data['subscription_id'],
                              rg=resource_group,
                              location=vm_details.location,
                              name=machine_name
                      )
    jit_status = requests.get(jit_status_uri, headers=headers)

    if jit_status.status_code != 404:
        try:
            jit_delete = requests.delete(jit_status_uri, headers=headers)
        except:
            logger.critical("Failed to delete existing JIT policy")
            logger.critital(jit_delete.text)
            exit(1)

    try:
        enable_jit_uri = "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Security/locations/{location}/jitNetworkAccessPolicies/{name}?api-version=2020-01-01".format(
                          subscription=data['subscription_id'],
                          rg=resource_group,
                          location=vm_details.location,
                          name=machine_name
                 )

        enable_jit_data = open("enable_jit.json").read()
        template = Template(enable_jit_data)
        payload  = json.loads(template.render(data=data))
        enable_jit_response = requests.put(enable_jit_uri, headers=headers, json=payload)
        logger.debug(enable_jit_response.json())
    except:
        logger.critical("Unable to create/update JIT policy")
        logger.error(enable_jit_response.json())
        exit(1)

else:
    exit(1)

try:
    initiate_jit_data = open("initiate_jit.json",).read()
    template = Template(initiate_jit_data)
    payload  = json.loads(template.render(data=data))
    initiate_jit_uri  = "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Security/locations/{location}/jitNetworkAccessPolicies/{name}/initiate?api-version=2020-01-01".format(
                              subscription=data['subscription_id'],
                              rg=resource_group,
                              location=vm_details.location,
                              name=machine_name
                     )

    initiate_jit_response = requests.post(initiate_jit_uri, headers=headers, json=payload)
    logger.debug(initiate_jit_response.json())
except:
    logger.error("Unable to initiate JIT policy for {machine}".format(machine=machine_name))
    logger.error(initate_jit_response.json())
    exit(1)
    
try:
    jit_status_uri = "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Security/locations/{location}/jitNetworkAccessPolicies/{name}?api-version=2020-01-01".format(
                              subscription=data['subscription_id'],
                              rg=resource_group,
                              location=vm_details.location,
                              name=machine_name
                      )
    jit_status = requests.get(jit_status_uri, headers=headers)
    logger.debug(jit_status.json())
except:
    logger.critical(jit_status.text)
    exit(1)

exit(0)

