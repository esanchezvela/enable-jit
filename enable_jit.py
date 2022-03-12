#!/usr/bin/env python

from azure.identity import  CertificateCredential
from azure.mgmt.compute import ComputeManagementClient

from datetime import datetime, timedelta
from jinja2 import Template
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
        logging.critical("Unable to get a credential from Azure")
        exit(1)

 

def get_header(credential, api_scope):
    try:
        access_token = credential.get_token(api_scope)
        logging.debug("Successful login using certificates")
        logging.debug("Access token expires on {}".format(datetime.fromtimestamp(access_token.expires_on).isoformat()))
        headers = {   
            "Authorization": "Bearer {}".format(access_token.token), 
            "Content-Type":  "application/json" 
        }
        return headers
    except:
        logging.critical("Unsuccesful login")
        return {}

parser  = argparse.ArgumentParser()
parser.add_argument("--rg",      help="Resource Group of server")
parser.add_argument("--machine", help="Machine name to request JIT")
args    = parser.parse_args()
try:
    if not args.rg:
        rg=os.environ["az_resource_group"]
    else:
        resource_group  = args.rg
        machine_name    = args.machine
except:
    print("Usage: ")
    print(f"       enable_jit.py [--rg resource_group_name ] '{'--machine NAME'}'")
    exit(1)

data               = define_vars()
credential         = get_credential(data) 
try:
    compute_client     = ComputeManagementClient(credential, data['subscription_id']) 
    vm_details         = compute_client.virtual_machines.get(resource_group, machine_name)
except:
    logging.critical("Unable to get machine details from Azure")
    exit(1)

headers            = get_header(credential, data['api_scope'])


if headers:
    now                      = datetime.now()
    delta                    = timedelta(hours=1)
    data["start_time"]       = now.utcnow().isoformat()
    data["end_time"]         = now.utcfromtimestamp(now.timestamp() + delta.seconds).isoformat()
    data["machine_id"]       = vm_details.id
    data["machine_location"] = vm_details.location

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
    logging.debug(enable_jit_response.json())
else:
    exit(1)




if enable_jit_response.status_code == 200:
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
    logging.debug(initiate_jit_response.json())
else: 
    logging.error("enable_jit_error")
    logging.error(enable_jit_response.json())


if initiate_jit_response.status_code == 202:
    jit_status_uri = "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Security/locations/{location}/jitNetworkAccessPolicies/{name}?api-version=2020-01-01".format(
                              subscription=data['subscription_id'],
                              rg=resource_group,
                              location=vm_details.location,
                              name=machine_name
                      )
    jit_status = requests.get(jit_status_uri, headers=headers)
    logging.debug(jit_status.json())
else:
    logging.critical(initiate_jit_response.json())
    exit(1)

exit(0)

