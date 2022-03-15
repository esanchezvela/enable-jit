
#Enable JIT Access to an Azure Machine on port 22.

#Requirements:  python >= 3.8 and Azure SDK.

#Usage:   enable-jit.py --rg machine_resource_group  --machine machine_name    --ports port1[,port2,port3] 
#Arguments:
        --rg Resource-group of Resource      - if not specified, takes value from enviromental variable az_resource_group
        --machine Virtual Machine name       - Required, name of virtual machine to access
        --ports  comma separated value of ports to enable,  - defaults to 22 if not specified


