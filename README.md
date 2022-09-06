# Workflow Optimization Script

## Table of contents
- [Quick start](#quick-start)
- [Usage](#usage)

## Quick start

Unzip the file and copy the directory WorkflowOptimization to /home/vcf/ directory on the SDDC Manager VM.

> Please note:
> - You are running the script in sddc-manager VM as vcf user.
> - Forward and reverse DNS settings for vCenter, NSX-T, VxRail Manager and ESXi components should be preconfigured.
> - If you choose DHCP as IP Allocation for TEP IPs option then make sure DHCP server must be configured for NSX-T VTEPS.
> - You must have run following pre-requisites before triggering script for Add Domain/Add Cluster workflow.
>   - Change VxRail Manager IP from static IP 192.168.10.200 to Management IP.
>   - Update VxRail Manager certificate with CN as valid VxRail Manager hostname.

## Usage

### Step by step input configuration for Add domain/Add cluster :

1. Add Domain
```python
vcf@dr22bsddc-1 [ ~/WorkflowOptimization ]$ python vxrail_workflow_optimization_automator.py
 Enter the SSO username: administrator@vsphere.local
 Enter the SSO password:


 Please choose one of the below option:
 1) Create Domain
 2) Add Cluster
 Enter your choice(number): 1


 Enter the domain name: wld-1


 ** ADVANCED_VXRAIL_SUPPLIED_VDS nic profile is supported only via VxRail JSON input
 Please choose one of the cluster configuration input options:
 1) VxRail JSON input
 2) Step by step input
 Enter your choice(number): 2


 Please enter vCenter details:
 vCenter FQDN: dr22bvc-2.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.40
 Gateway IP address: 172.18.58.253
 Subnet Mask(255.255.255.0):

 Enter root password:
 Confirm password:


 Enter Datacenter name: vxrail-datacenter


 Please enter cluster name: VxRail-Virtual-SAN-Cluster-WLD


 Please enter VxRail Manager FQDN: dr22b-vxrm-2.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.78


 Getting ssl and ssh thumbprint for VxRail Manager dr22b-vxrm-2.rainpole.local...


 Fetched ssl thumbprint: 58:1D:18:39:C4:F2:EC:05:1B:18:CA:6F:02:26:66:66:B4:48:59:D5:90:3F:0D:BA:79:28:C8:99:5D:5E:F7:E7
 Fetched ssh thumbprint: SHA256:uC0zLDfYZ3zGAkBx1iJ6pZSTF7TArSiQSTpZv9LAw18


 Do you want to trust the same?('yes' or 'no'): yes


 Discovering hosts by VxRail Manager...


 ** By Default primary node gets selected. Please select atleast two other nodes.
 Hosts discovered by the VxRail Manager are:
 VxRail Manager is detected on primary node : 7FTZHK20000000
 1) 7PGXWK20000000
 2) 7FVRHK20000000
 Enter your choices(minimum 2 numbers comma separated): 1,2


 Please enter host details for serial no 7FTZHK20000000:
 Enter FQDN: dr22b-005.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.60


 Please enter host details for serial no 7PGXWK20000000:
 Enter FQDN: dr22b-006.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.61


 Please enter host details for serial no 7FVRHK20000000:
 Enter FQDN: dr22b-007.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.62


 Please choose password option:
 1) Input one password that is applicable to all the hosts (default)
 2) Input password individually for each host
 Enter your choice(number): 1


 Enter root password for hosts:
 Confirm password:


 ** For e.g. vSAN Network VLAN ID: 1407, CIDR: 172.18.60.0/24,
    IP Range for hosts vSAN IP assignment: 172.18.60.55-172.18.60.60
 Please enter vSAN Network details:
 Enter VLAN Id: 1407
 Enter CIDR: 172.18.60.0/24
 Enter subnet mask(255.255.255.0):
 Enter gateway IP: 172.18.60.1
 Enter IP Range: 172.18.60.60-172.18.60.62


 ** For e.g. vMotion Network VLAN ID: 1406, CIDR: 172.18.59.0/24,
    IP Range for hosts vMotion IP assignment: 172.18.59.55-172.18.59.60
 Please enter vMotion Network details:
 Enter VLAN Id: 1406
 Enter CIDR: 172.18.59.0/24
 Enter subnet mask(255.255.255.0):
 Enter gateway IP: 172.18.59.1
 Enter IP Range: 172.18.59.60-172.18.59.64


 ** By default the tool takes Management domain mgmt network for Create Domain and Primary cluster mgmt network for Create Cluster
 Do you want to provide Management Network details?('yes' or 'no'): yes


 Please enter Management Network details:
 Enter VLAN Id: 1405
 Enter subnet mask(255.255.255.0):
 Enter gateway IP: 172.18.58.253


 ** ADVANCED_VXRAIL_SUPPLIED_VDS nic profile is supported only via VxRail JSON input
 Please select nic profile:
 1) TWO_HIGH_SPEED
 2) FOUR_HIGH_SPEED
 3) FOUR_EXTREME_SPEED
 Enter your choice(number): 2


 Select the DVS option to proceed:
 1) System DVS for Overlay
 2) Separate DVS for Overlay
 Enter your choice(number): 2


 Please enter DVS details:

 Enter System DVS name: dvs-1

 Enter portgroup name for type MANAGEMENT: Management Network-1
 Enter portgroup name for type VSAN: Virtual SAN-1
 Enter portgroup name for type VMOTION: vSphere vMotion-1

 Enter Overlay DVS name: dvs-2


 Please choose the nics for overlay traffic:
 -----id-----speed-----
 ----------------------
 1) vmnic4 - 10000
 2) vmnic5 - 10000
 Enter your choices(minimum 2 numbers comma separated): 1,2


 Getting shared NSX-T cluster information...
 ** No shared NSX-T instance was found, you need to create a new one


 Enter Geneve vLAN ID (0-4096): 1408


 Enter root password:
 Confirm password:


 Please Enter NSX-T VIP details:

 FQDN (IP address will be fetched from DNS): dr22bvip-2.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.45
 Gateway IP address: 172.18.58.253
 Subnet mask (255.255.255.0):


 Enter FQDN for 1st NSX-T Manager: dr22bnsxt-4.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.51


 Enter FQDN for 2nd NSX-T Manager: dr22bnsxt-5.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.52


 Enter FQDN for 3rd NSX-T Manager: dr22bnsxt-6.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.53


 Please choose IP Allocation for TEP IPs option:
 1) DHCP (default)
 2) Static IP Pool
 Enter your choice(number): 2


 Create New Static IP Pool
 Enter Pool Name: ip-pool-1
 Enter Description(Optional): IP_POOL


 Subnet #1
 Enter CIDR: 172.18.57.0/24
 ** Multiple IP Ranges are supported by comma separated
 Enter IP Range: 172.18.57.10-172.18.57.30
 Enter Gateway IP: 172.18.57.1


 Do you want to add another subnet ? (Enter 'yes' or 'no'): no


 Please enter VxRail Manager's root credentials:
 Enter password:
 Confirm password:


 Please enter VxRail Manager's admin credentials:
 Enter username (mystic):
 Enter password:
 Confirm password:


 Getting license information...


 Please choose a VSAN license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (ACTIVE)
 Enter your choice(number): 1


 Please choose a NSX-T license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


 Do you want to apply vSphere license('yes' or 'no'): yes


 ** Please make sure license has enough CPU slots required for the cluster
 Please choose a vSphere license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


{
  "computeSpec": {
    "clusterSpecs": [
      {
        "datastoreSpec": {
          "vsanDatastoreSpec": {
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          }
        },
        "hostSpecs": [
          {
            "hostName": "dr22b-005.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic4",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "dvs-2"
                }
              ]
            },
            "ipAddress": "172.18.58.60",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FTZHK20000000",
            "sshThumbprint": "SHA256:frgoy9B9ZYNYwVOHyF5YoSBopnOT3FTlEmV7hMfzhJs",
            "username": "root"
          },
          {
            "hostName": "dr22b-006.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic4",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "dvs-2"
                }
              ]
            },
            "ipAddress": "172.18.58.61",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7PGXWK20000000",
            "sshThumbprint": "SHA256:CQFPX1trUeTlaQq5pWjmYyKHTROOpTjr1UOyr5Yh96A",
            "username": "root"
          },
          {
            "hostName": "dr22b-007.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic4",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "dvs-2"
                }
              ]
            },
            "ipAddress": "172.18.58.62",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FVRHK20000000",
            "sshThumbprint": "SHA256:PSIS2Vxl8zAYLHlldyGxqXWuVyUalqhM5aPezAX0Yf0",
            "username": "root"
          }
        ],
        "name": "VxRail-Virtual-SAN-Cluster-WLD",
        "networkSpec": {
          "nsxClusterSpec": {
            "nsxTClusterSpec": {
              "geneveVlanId": "1408"
            }
          },
          "vdsSpecs": [
            {
              "isUsedByNsxt": false,
              "name": "dvs-1",
              "portGroupSpecs": [
                {
                  "name": "Management Network-1",
                  "transportType": "MANAGEMENT"
                },
                {
                  "name": "Virtual SAN-1",
                  "transportType": "VSAN"
                },
                {
                  "name": "vSphere vMotion-1",
                  "transportType": "VMOTION"
                }
              ]
            },
            {
              "isUsedByNsxt": true,
              "name": "dvs-2"
            }
          ]
        },
        "skipThumbprintValidation": false,
        "vxRailDetails": {
          "adminCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "mystic"
          },
          "dnsName": "dr22b-vxrm-2.rainpole.local",
          "ipAddress": "172.18.58.78",
          "networks": [
            {
              "gateway": "172.18.60.1",
              "ipPools": [
                {
                  "end": "172.18.60.62",
                  "start": "172.18.60.60"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.60.0/24",
              "type": "VSAN",
              "vlanId": 1407
            },
            {
              "gateway": "172.18.59.1",
              "ipPools": [
                {
                  "end": "172.18.59.64",
                  "start": "172.18.59.60"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.59.0/24",
              "type": "VMOTION",
              "vlanId": 1406
            },
            {
              "gateway": "172.18.58.253",
              "mask": "255.255.255.0",
              "type": "MANAGEMENT",
              "vlanId": 1405
            }
          ],
          "nicProfile": "FOUR_HIGH_SPEED",
          "rootCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "root"
          },
          "sshThumbprint": "SHA256:uC0zLDfYZ3zGAkBx1iJ6pZSTF7TArSiQSTpZv9LAw18",
          "sslThumbprint": "58:1D:18:39:C4:F2:EC:05:1B:18:CA:6F:02:26:66:66:B4:48:59:D5:90:3F:0D:BA:79:28:C8:99:5D:5E:F7:E7"
        }
      }
    ]
  },
  "domainName": "wld-1",
  "nsxTSpec": {
    "formFactor": "large",
    "ipAddressPoolSpec": {
      "description": "IP_POOL",
      "name": "ip-pool-1",
      "subnets": [
          {
              "cidr": "172.18.57.0/24",
              "gateway": "172.18.57.1",
              "ipAddressPoolRanges": [
                  {
                      "end": "172.18.57.30",
                      "start": "172.18.57.10"
                  }
              ]
          }
      ]
    },
    "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
    "nsxManagerSpecs": [
        {
            "name": "dr22bnsxt-4",
            "networkDetailsSpec": {
                "dnsName": "dr22bnsxt-4.rainpole.local",
                "gateway": "172.18.58.253",
                "ipAddress": "172.18.58.51",
                "subnetMask": "255.255.255.0"
            }
        },
        {
            "name": "dr22bnsxt-5",
            "networkDetailsSpec": {
                "dnsName": "dr22bnsxt-5.rainpole.local",
                "gateway": "172.18.58.253",
                "ipAddress": "172.18.58.52",
                "subnetMask": "255.255.255.0"
            }
        },
        {
            "name": "dr22bnsxt-6",
            "networkDetailsSpec": {
                "dnsName": "dr22bnsxt-6.rainpole.local",
                "gateway": "172.18.58.253",
                "ipAddress": "172.18.58.53",
                "subnetMask": "255.255.255.0"
            }
        }
    ],
    "vip": "172.18.58.45",
    "vipFqdn": "dr22bvip-2.rainpole.local"
  },
  "vcenterSpec": {
    "datacenterName": "vxrail-datacenter",
    "name": "dr22bvc-3",
    "networkDetailsSpec": {
      "dnsName": "dr22bvc-2.rainpole.local",
      "gateway": "172.18.58.253",
      "ipAddress": "172.18.58.40",
      "subnetMask": "255.255.255.0"
    },
    "rootPassword": "*******",
    "storageSize": "lstorage",
    "vmSize": "medium"
  }
}

 Enter to continue ...
 Validating the input....
 Validation started for create domain operation. The validation id is: 2cfac9f0-47d3-4221-9c35-9fa84e59e416
 Polling on validation api https://localhost/v1/domains/validations/2cfac9f0-47d3-4221-9c35-9fa84e59e416
 Validation IN_PROGRESS. It will take some time to complete. Please wait...
 Validation ended with status: SUCCEEDED

 Enter to create domain..
 Create domain triggered, monitor the status of the task(task-id:46c0cff3-9160-4c45-a67e-685361d1d0b8) from sddc-manager ui
```

2. Add Cluster
```python
vcf@dr22bsddc-1 [ ~/WorkflowOptimization ]$ python vxrail_workflow_optimization_automator.py
 Enter the SSO username: administrator@vsphere.local
 Enter the SSO password:


 Please choose one of the below option:
 1) Create Domain
 2) Add Cluster
 Enter your choice(number): 2


 Getting the domains...


 Please choose the domain to which cluster has to be added:
 1) MGMT
 2) wld-1
 Enter your choice(number): 2


 ** ADVANCED_VXRAIL_SUPPLIED_VDS nic profile is supported only via VxRail JSON input
 Please choose one of the cluster configuration input options:
 1) VxRail JSON input
 2) Step by step input
 Enter your choice(number): 2


 Please enter cluster name: VxRail-Virtual-SAN-Secondary-Cluster


 Please enter VxRail Manager FQDN: dr22b-vxrm-3.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.110


 Getting ssl and ssh thumbprint for VxRail Manager dr22b-vxrm-3.rainpole.local...


 Fetched ssl thumbprint: 32:87:6F:0C:73:31:0A:DE:64:01:90:FC:46:12:92:25:32:C5:D8:1B:71:12:D9:A8:BC:40:82:AB:AE:C0:48:1B
 Fetched ssh thumbprint: SHA256:Xq0sIAHivbDl6jtgEqBrDkWHux7F2J7M2WInGocrOuU


 Do you want to trust the same?('yes' or 'no'): yes


 Discovering hosts by VxRail Manager...


 ** By Default primary node gets selected. Please select atleast two other nodes.
 Hosts discovered by the VxRail Manager are:
 VxRail Manager is detected on primary node : 7FTZHK20000000
 1) 7PGXWK20000000
 2) 7FVRHK20000000
 Enter your choices(minimum 2 numbers comma separated): 1,2


 Please enter host details for serial no 7FTZHK20000000:
 Enter FQDN: dr22b-008.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.90


 Please enter host details for serial no 7PGXWK20000000:
 Enter FQDN: dr22b-009.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.91


 Please enter host details for serial no 7FVRHK20000000:
 Enter FQDN: dr22b-010.rainpole.local
 Resolving IP from DNS...
 Resolved IP address: 172.18.58.92


 Please choose password option:
 1) Input one password that is applicable to all the hosts (default)
 2) Input password individually for each host
 Enter your choice(number): 1


 Enter root password for hosts:
 Confirm password:


 ** For e.g. vSAN Network VLAN ID: 1407, CIDR: 172.18.60.0/24,
    IP Range for hosts vSAN IP assignment: 172.18.60.55-172.18.60.60
 Please enter vSAN Network details:
 Enter VLAN Id: 1407
 Enter CIDR: 172.18.60.0/24
 Enter subnet mask(255.255.255.0):
 Enter gateway IP: 172.18.60.1
 Enter IP Range: 172.18.60.60-172.18.60.62


 ** For e.g. vMotion Network VLAN ID: 1406, CIDR: 172.18.59.0/24,
    IP Range for hosts vMotion IP assignment: 172.18.59.55-172.18.59.60
 Please enter vMotion Network details:
 Enter VLAN Id: 1406
 Enter CIDR: 172.18.59.0/24
 Enter subnet mask(255.255.255.0):
 Enter gateway IP: 172.18.59.1
 Enter IP Range: 172.18.59.60-172.18.59.62


 ** By default the tool takes Management domain mgmt network for Create Domain and Primary cluster mgmt network for Create Cluster
 Do you want to provide Management Network details?('yes' or 'no'): yes


 Please enter Management Network details:
 Enter VLAN Id: 1405
 Enter subnet mask(255.255.255.0):
 Enter gateway IP: 172.18.58.253


 ** ADVANCED_VXRAIL_SUPPLIED_VDS nic profile is supported only via VxRail JSON input
 Please select nic profile:
 1) TWO_HIGH_SPEED
 2) FOUR_HIGH_SPEED
 3) FOUR_EXTREME_SPEED
 Enter your choice(number): 1


 Select the DVS option to proceed:
 1) System DVS for Overlay
 2) Separate DVS for Overlay
 Enter your choice(number): 2


 Please enter DVS details:

 Enter System DVS name: dvs-1

 Enter portgroup name for type MANAGEMENT: Management Network_sec_cluster
 Enter portgroup name for type VSAN: Virtual SAN_sec_cluster
 Enter portgroup name for type VMOTION: vSphere vMotion_sec_cluster

 Enter Overlay DVS name: overlay-sec-dvs


 Please choose the nics for overlay traffic:
 -----id-----speed-----
 ----------------------
 1) vmnic2 - 10000
 2) vmnic3 - 10000
 3) vmnic4 - 10000
 4) vmnic5 - 10000
 Enter your choices(minimum 2 numbers comma separated): 1,2,3,4


 Getting shared NSX-T cluster information...


 Enter Geneve vLAN ID (0-4096):  1408


 Found NSX-T instance : dr22bvip-2.rainpole.local


 Please choose IP Allocation for TEP IPs option:
 1) DHCP (default)
 2) Static IP Pool
 Enter your choice(number): 2


 Select the option for Static IP Pool:
 1) Create New Static IP Pool(default)
 2) Re-use an Existing Static Pool
 Enter your choice(number): 1


 Create New Static IP Pool
 Enter Pool Name: ip-pool-2
 Enter Description(Optional):


 Subnet #1
 Enter CIDR: 172.18.56.0/24
 ** Multiple IP Ranges are supported by comma separated
 Enter IP Range: 172.18.56.10-172.18.56.40
 Enter Gateway IP: 172.18.56.1


 Do you want to add another subnet ? (Enter 'yes' or 'no'): no


 Please enter VxRail Manager's root credentials:
 Enter password:
 Confirm password:


 Please enter VxRail Manager's admin credentials:
 Enter username (mystic):
 Enter password:
 Confirm password:


 Getting license information...


 Please choose a VSAN license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (ACTIVE)
 Enter your choice(number): 1


 Please choose a NSX-T license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


 Do you want to apply vSphere license('yes' or 'no'): yes


 ** Please make sure license has enough CPU slots required for the cluster
 Please choose a vSphere license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


{
  "computeSpec": {
    "clusterSpecs": [
      {
        "datastoreSpec": {
          "vsanDatastoreSpec": {
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          }
        },
        "hostSpecs": [
          {
            "hostName": "dr22b-008.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic2",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic3",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic4",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "overlay-sec-dvs"
                }
              ]
            },
            "ipAddress": "172.18.58.90",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FTZHK20000000",
            "sshThumbprint": "SHA256:frgoy9B9ZYNYwVOHyF5YoSBopnOT3FTlEmV7hMfzhJs",
            "username": "root"
          },
          {
            "hostName": "dr22b-009.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic2",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic3",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic4",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "overlay-sec-dvs"
                }
              ]
            },
            "ipAddress": "172.18.58.91",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7PGXWK20000000",
            "sshThumbprint": "SHA256:CQFPX1trUeTlaQq5pWjmYyKHTROOpTjr1UOyr5Yh96A",
            "username": "root"
          },
          {
            "hostName": "dr22b-010.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic2",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic3",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic4",
                  "vdsName": "overlay-sec-dvs"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "overlay-sec-dvs"
                }
              ]
            },
            "ipAddress": "172.18.58.92",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FVRHK20000000",
            "sshThumbprint": "SHA256:PSIS2Vxl8zAYLHlldyGxqXWuVyUalqhM5aPezAX0Yf0",
            "username": "root"
          }
        ],
        "name": "VxRail-Virtual-SAN-Secondary-Cluster",
        "networkSpec": {
          "nsxClusterSpec": {
            "nsxTClusterSpec": {
              "geneveVlanId": "1408",
                "ipAddressPoolSpec": {
                    "name": "ip-pool-2",
                    "subnets": [
                        {
                            "cidr": "172.18.56.0/24",
                            "gateway": "172.18.56.1",
                            "ipAddressPoolRanges": [
                                {
                                    "end": "172.18.56.40",
                                    "start": "172.18.56.10"
                                }
                            ]
                        }
                    ]
                }
            }
          },
          "vdsSpecs": [
            {
              "isUsedByNsxt": false,
              "name": "dvs-1",
              "portGroupSpecs": [
                {
                  "name": "Management Network_sec_cluster",
                  "transportType": "MANAGEMENT"
                },
                {
                  "name": "Virtual SAN_sec_cluster",
                  "transportType": "VSAN"
                },
                {
                  "name": "vSphere vMotion_sec_cluster",
                  "transportType": "VMOTION"
                }
              ]
            },
            {
              "isUsedByNsxt": true,
              "name": "overlay-sec-dvs"
            }
          ]
        },
        "skipThumbprintValidation": false,
        "vxRailDetails": {
          "adminCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "mystic"
          },
          "dnsName": "dr22b-vxrm-3.rainpole.local",
          "ipAddress": "172.18.58.110",
          "networks": [
            {
              "gateway": "172.18.60.1",
              "ipPools": [
                {
                  "end": "172.18.60.62",
                  "start": "172.18.60.60"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.60.0/24",
              "type": "VSAN",
              "vlanId": 1407
            },
            {
              "gateway": "172.18.59.1",
              "ipPools": [
                {
                  "end": "172.18.59.62",
                  "start": "172.18.59.60"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.59.0/24",
              "type": "VMOTION",
              "vlanId": 1406
            },
            {
              "gateway": "172.18.58.253",
              "mask": "255.255.255.0",
              "type": "MANAGEMENT",
              "vlanId": 1405
            }
          ],
          "nicProfile": "TWO_HIGH_SPEED",
          "rootCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "root"
          },
          "sshThumbprint": "SHA256:Xq0sIAHivbDl6jtgEqBrDkWHux7F2J7M2WInGocrOuU",
          "sslThumbprint": "32:87:6F:0C:73:31:0A:DE:64:01:90:FC:46:12:92:25:32:C5:D8:1B:71:12:D9:A8:BC:40:82:AB:AE:C0:48:1B"
        }
      }
    ]
  },
  "domainId": "792f61a9-cc6d-461a-8418-1ae9ef7958f1"
}

 Enter to continue ...
 Validating the input....
 Validation started for add cluster operation. The validation id is: 079b2a78-9314-481b-98bb-e91e484f0b9c
 Polling on validation api https://localhost/v1/clusters/validations/079b2a78-9314-481b-98bb-e91e484f0b9c
 Validation IN_PROGRESS. It will take some time to complete. Please wait...
 Validation ended with status: SUCCEEDED

 Enter to add cluster..
 Triggered add cluster, monitor the status of the task(task-id:870a523a-fc76-49f3-a8df-27fd0abfaed9) from sddc-manager ui
```

### VxRail JSON input configuration for Add domain/Add cluster :

1. Add Domain
```python
vcf@dr22bsddc-1 [ ~/WorkflowOptimization ]$ python vxrail_workflow_optimization_automator.py
 Enter the SSO username: administrator@vsphere.local
 Enter the SSO password:


 Please choose one of the below option:
 1) Create Domain
 2) Add Cluster
 Enter your choice(number): 1


 Enter the domain name: wld-2


 ** ADVANCED_VXRAIL_SUPPLIED_VDS nic profile is supported only via VxRail JSON input
 Please choose one of the cluster configuration input options:
 1) VxRail JSON input
 2) Step by step input
 Enter your choice(number): 1


 Please enter VxRail JSON location: /home/vcf/vxrail.json


 Enter Gateway IP address for vcenter dr22bvc-3.rainpole.local: 172.18.58.253
 Enter vCenter dr22bvc-3.rainpole.local root password:
 Confirm password:


 Getting ssl thumbprint for the passed VxRail Manager dr22b-vxrm-3.rainpole.local


 Fetched ssl thumbprint: 32:87:6F:0C:73:31:0A:DE:64:01:90:FC:46:12:92:25:32:C5:D8:1B:71:12:D9:A8:BC:40:82:AB:AE:C0:48:1B
 Fetched ssh thumbprint: SHA256:Xq0sIAHivbDl6jtgEqBrDkWHux7F2J7M2WInGocrOuU


 Do you want to trust the same?('yes' or 'no'): yes


 Getting ssh thumbprint for the hosts passed in Json
 Discovering hosts by VxRail Manager...


 Fetched ssh thumbprint for hosts passed in Json:
 --Serial Number--------------SSH Thumbprint--------------------------
 ---------------------------------------------------------------------
  7FTZHK20000000 : SHA256:frgoy9B9ZYNYwVOHyF5YoSBopnOT3FTlEmV7hMfzhJs
  7FVRHK20000000 : SHA256:PSIS2Vxl8zAYLHlldyGxqXWuVyUalqhM5aPezAX0Yf0
  7PGXWK20000000 : SHA256:CQFPX1trUeTlaQq5pWjmYyKHTROOpTjr1UOyr5Yh96A


 Select the DVS option to proceed:
 1) System DVS for Overlay
 2) Separate DVS for Overlay
 Enter your choice(number): 1


 Please enter DVS details:

 Enter System DVS name: dvs-1

 Enter portgroup name for type MANAGEMENT: Management Network_prim_cluster
 Enter portgroup name for type VSAN: Virtual SAN_prim_cluster
 Enter portgroup name for type VMOTION: vSphere vMotion_prim_cluster


 Getting shared NSX-T cluster information...


 Please choose NSX-T instance option:
 1) Create new NSX-T instance (default)
 2) Use existing NSX-T instance
 Enter your choice(number): 2


 Enter Geneve vLAN ID (0-4096):  1408


 Please select one NSX-T instance
 1) NSX-T vip: dr22bvip-2.rainpole.local
 Enter your choice(number): 1


 Please choose IP Allocation for TEP IPs option:
 1) DHCP (default)
 2) Static IP Pool
 Enter your choice(number): 1


 Getting license information...


 Please choose a VSAN license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (ACTIVE)
 Enter your choice(number): 1


 Please choose a NSX-T license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


 Do you want to apply vSphere license('yes' or 'no'): yes


 ** Please make sure license has enough CPU slots required for the cluster
 Please choose a vSphere license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


{
  "computeSpec": {
    "clusterSpecs": [
      {
        "datastoreSpec": {
          "vsanDatastoreSpec": {
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          }
        },
        "hostSpecs": [
          {
            "hostName": "dr22b-005.rainpole.local",
            "ipAddress": "172.18.58.60",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FTZHK20000000",
            "sshThumbprint": "SHA256:frgoy9B9ZYNYwVOHyF5YoSBopnOT3FTlEmV7hMfzhJs",
            "username": "root"
          },
          {
            "hostName": "dr22b-006.rainpole.local",
            "ipAddress": "172.18.58.61",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FVRHK20000000",
            "sshThumbprint": "SHA256:PSIS2Vxl8zAYLHlldyGxqXWuVyUalqhM5aPezAX0Yf0",
            "username": "root"
          },
          {
            "hostName": "dr22b-007.rainpole.local",
            "ipAddress": "172.18.58.62",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7PGXWK20000000",
            "sshThumbprint": "SHA256:CQFPX1trUeTlaQq5pWjmYyKHTROOpTjr1UOyr5Yh96A",
            "username": "root"
          }
        ],
        "name": "VxRail-Workload-Primary-Cluster",
        "networkSpec": {
          "nsxClusterSpec": {
            "nsxTClusterSpec": {
              "geneveVlanId": "1408"
            }
          },
          "vdsSpecs": [
            {
              "isUsedByNsxt": true,
              "name": "dvs-1",
              "portGroupSpecs": [
                {
                  "name": "Management Network_prim_cluster",
                  "transportType": "MANAGEMENT"
                },
                {
                  "name": "Virtual SAN_prim_cluster",
                  "transportType": "VSAN"
                },
                {
                  "name": "vSphere vMotion_prim_cluster",
                  "transportType": "VMOTION"
                }
              ]
            }
          ]
        },
        "skipThumbprintValidation": false,
        "vxRailDetails": {
          "adminCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "mystic"
          },
          "dnsName": "dr22b-vxrm-3.rainpole.local",
          "ipAddress": "172.18.58.110",
          "networks": [
            {
              "gateway": "172.18.60.1",
              "ipPools": [
                {
                  "end": "172.18.60.92",
                  "start": "172.18.60.90"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.60.0/24",
              "type": "VSAN",
              "vlanId": 1407
            },
            {
              "gateway": "172.18.59.1",
              "ipPools": [
                {
                  "end": "172.18.59.92",
                  "start": "172.18.59.90"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.59.0/24",
              "type": "VMOTION",
              "vlanId": 1406
            },
            {
              "gateway": "172.18.58.253",
              "mask": "255.255.255.0",
              "type": "MANAGEMENT",
              "vlanId": 1405
            }
          ],
          "nicProfile": "TWO_HIGH_SPEED",
          "rootCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "root"
          },
          "sshThumbprint": "SHA256:Xq0sIAHivbDl6jtgEqBrDkWHux7F2J7M2WInGocrOuU",
          "sslThumbprint": "32:87:6F:0C:73:31:0A:DE:64:01:90:FC:46:12:92:25:32:C5:D8:1B:71:12:D9:A8:BC:40:82:AB:AE:C0:48:1B"
        }
      }
    ]
  },
  "domainName": "wld-2",
  "nsxTSpec": {
    "formFactor": "large",
    "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
    "nsxManagerSpecs": [
      {
        "name": "dr22bnsxt-4",
        "networkDetailsSpec": {
          "dnsName": "dr22bnsxt-4.rainpole.local",
          "ipAddress": "172.18.58.51"
        }
      },
      {
        "name": "dr22bnsxt-5",
        "networkDetailsSpec": {
          "dnsName": "dr22bnsxt-5.rainpole.local",
          "ipAddress": "172.18.58.52"
        }
      },
      {
        "name": "dr22bnsxt-6",
        "networkDetailsSpec": {
          "dnsName": "dr22bnsxt-6.rainpole.local",
          "ipAddress": "172.18.58.53"
        }
      }
    ],
    "vip": "172.18.58.45",
    "vipFqdn": "dr22bvip-2.rainpole.local"
  },
  "vcenterSpec": {
    "datacenterName": "VxRail-Datacenter",
    "name": "dr22bvc-3",
    "networkDetailsSpec": {
      "dnsName": "dr22bvc-3.rainpole.local",
      "gateway": "172.18.58.253",
      "ipAddress": "172.18.58.49",
      "subnetMask": "255.255.255.0"
    },
    "rootPassword": "*******",
    "storageSize": "lstorage",
    "vmSize": "medium"
  }
}

 Enter to continue ...
 Validating the input....
 Validation started for create domain operation. The validation id is: f8a1beda-2782-4f20-a19d-9bed308361e4
 Polling on validation api https://localhost/v1/domains/validations/f8a1beda-2782-4f20-a19d-9bed308361e4
 Validation IN_PROGRESS. It will take some time to complete. Please wait...
 Validation ended with status: SUCCEEDED

 Enter to create domain...
 Create domain triggered, monitor the status of the task(task-id:36c0cff3-9160-4c45-a67e-685361d1d0b8) from sddc-manager ui
```

2. Add Cluster
```python
vcf@dr22bsddc-1 [ ~/WorkflowOptimization ]$ python vxrail_workflow_optimization_automator.py
 Enter the SSO username: administrator@vsphere.local
 Enter the SSO password:


 Please choose one of the below option:
 1) Create Domain
 2) Add Cluster
 Enter your choice(number): 2


 Getting the domains...


 Please choose the domain to which cluster has to be added:
 1) MGMT
 2) wld-1
 Enter your choice(number): 2


 ** ADVANCED_VXRAIL_SUPPLIED_VDS nic profile is supported only via VxRail JSON input
 Please choose one of the cluster configuration input options:
 1) VxRail JSON input
 2) Step by step input
 Enter your choice(number): 1


 Please enter VxRail JSON location: /home/vcf/vxrail.json


 Getting ssl thumbprint for the passed VxRail Manager dr22b-vxrm-3.rainpole.local


 Fetched ssl thumbprint: 32:87:6F:0C:73:31:0A:DE:64:01:90:FC:46:12:92:25:32:C5:D8:1B:71:12:D9:A8:BC:40:82:AB:AE:C0:48:1B
 Fetched ssh thumbprint: SHA256:Xq0sIAHivbDl6jtgEqBrDkWHux7F2J7M2WInGocrOuU


 Do you want to trust the same?('yes' or 'no'): yes


 Getting ssh thumbprint for the hosts passed in Json
 Discovering hosts by VxRail Manager...


 Fetched ssh thumbprint for hosts passed in Json:
 --Serial Number--------------SSH Thumbprint--------------------------
 ---------------------------------------------------------------------
  7FTZHK20000000 : SHA256:frgoy9B9ZYNYwVOHyF5YoSBopnOT3FTlEmV7hMfzhJs
  7FVRHK20000000 : SHA256:PSIS2Vxl8zAYLHlldyGxqXWuVyUalqhM5aPezAX0Yf0
  7PGXWK20000000 : SHA256:CQFPX1trUeTlaQq5pWjmYyKHTROOpTjr1UOyr5Yh96A


 Select the DVS option to proceed:
 1) System DVS for Overlay
 2) Separate DVS for Overlay
 Enter your choice(number): 2


 Please enter DVS details:

 Enter System DVS name: dvs-1

 Enter portgroup name for type MANAGEMENT: Management Network_sec_cluster
 Enter portgroup name for type VSAN: Virtual SAN_sec_cluster
 Enter portgroup name for type VMOTION: vSphere vMotion_sec_cluster

 Enter Overlay DVS name: dvs-2


 Please choose the nics for overlay traffic:
 -----id-----speed-----
 ----------------------
 1) vmnic2 - 10000
 2) vmnic3 - 10000
 3) vmnic4 - 10000
 4) vmnic5 - 10000
 Enter your choices(minimum 2 numbers comma separated): 1,2,3,4


 Getting shared NSX-T cluster information...


 Enter Geneve vLAN ID (0-4096):  1408


 Found NSX-T instance : dr22bvip-2.rainpole.local


 Please choose IP Allocation for TEP IPs option:
 1) DHCP (default)
 2) Static IP Pool
 Enter your choice(number): 1


 Getting license information...


 Please choose a VSAN license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (ACTIVE)
 Enter your choice(number): 11
 **Use first choice by default


 Please choose a NSX-T license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


 Do you want to apply vSphere license('yes' or 'no'): yes


 ** Please make sure license has enough CPU slots required for the cluster
 Please choose a vSphere license:
 1) XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (NEVER_EXPIRES)
 Enter your choice(number): 1


{
  "computeSpec": {
    "clusterSpecs": [
      {
        "datastoreSpec": {
          "vsanDatastoreSpec": {
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          }
        },
        "hostSpecs": [
          {
            "hostName": "dr22b-008.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic2",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic3",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic4",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "dvs-2"
                }
              ]
            },
            "ipAddress": "172.18.58.90",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FTZHK20000000",
            "sshThumbprint": "SHA256:frgoy9B9ZYNYwVOHyF5YoSBopnOT3FTlEmV7hMfzhJs",
            "username": "root"
          },
          {
            "hostName": "dr22b-009.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic2",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic3",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic4",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "dvs-2"
                }
              ]
            },
            "ipAddress": "172.18.58.91",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7FVRHK20000000",
            "sshThumbprint": "SHA256:PSIS2Vxl8zAYLHlldyGxqXWuVyUalqhM5aPezAX0Yf0",
            "username": "root"
          },
          {
            "hostName": "dr22b-010.rainpole.local",
            "hostNetworkSpec": {
              "vmNics": [
                {
                  "id": "vmnic2",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic3",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic4",
                  "vdsName": "dvs-2"
                },
                {
                  "id": "vmnic5",
                  "vdsName": "dvs-2"
                }
              ]
            },
            "ipAddress": "172.18.58.92",
            "licenseKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "password": "*******",
            "serialNumber": "7PGXWK20000000",
            "sshThumbprint": "SHA256:CQFPX1trUeTlaQq5pWjmYyKHTROOpTjr1UOyr5Yh96A",
            "username": "root"
          }
        ],
        "name": "VxRail-Workload-Sec-Cluster",
        "networkSpec": {
          "nsxClusterSpec": {
            "nsxTClusterSpec": {
              "geneveVlanId": "1408"
            }
          },
          "vdsSpecs": [
            {
              "isUsedByNsxt": false,
              "name": "dvs-1",
              "portGroupSpecs": [
                {
                  "name": "Management Network_sec_cluster",
                  "transportType": "MANAGEMENT"
                },
                {
                  "name": "Virtual SAN_sec_cluster",
                  "transportType": "VSAN"
                },
                {
                  "name": "vSphere vMotion_sec_cluster",
                  "transportType": "VMOTION"
                }
              ]
            },
            {
              "isUsedByNsxt": true,
              "name": "dvs-2"
            }
          ]
        },
        "skipThumbprintValidation": false,
        "vxRailDetails": {
          "adminCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "mystic"
          },
          "dnsName": "dr22b-vxrm-3.rainpole.local",
          "ipAddress": "172.18.58.110",
          "networks": [
            {
              "gateway": "172.18.60.1",
              "ipPools": [
                {
                  "end": "172.18.60.92",
                  "start": "172.18.60.90"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.60.0/24",
              "type": "VSAN",
              "vlanId": 1407
            },
            {
              "gateway": "172.18.59.1",
              "ipPools": [
                {
                  "end": "172.18.59.92",
                  "start": "172.18.59.90"
                }
              ],
              "mask": "255.255.255.0",
              "subnet": "172.18.59.0/24",
              "type": "VMOTION",
              "vlanId": 1406
            },
            {
              "gateway": "172.18.58.253",
              "mask": "255.255.255.0",
              "type": "MANAGEMENT",
              "vlanId": 1405
            }
          ],
          "nicProfile": "TWO_HIGH_SPEED",
          "rootCredentials": {
            "credentialType": "SSH",
            "password": "*******",
            "username": "root"
          },
          "sshThumbprint": "SHA256:Xq0sIAHivbDl6jtgEqBrDkWHux7F2J7M2WInGocrOuU",
          "sslThumbprint": "32:87:6F:0C:73:31:0A:DE:64:01:90:FC:46:12:92:25:32:C5:D8:1B:71:12:D9:A8:BC:40:82:AB:AE:C0:48:1B"
        }
      }
    ]
  },
  "domainId": "792f61a9-cc6d-461a-8418-1ae9ef7958f1"
}

 Enter to continue ...
 Validating the input....
 Validation started for add cluster operation. The validation id is: 73a54654-9c2c-47d2-a8be-53e8b42ca0a7
 Polling on validation api https://localhost/v1/clusters/validations/73a54654-9c2c-47d2-a8be-53e8b42ca0a7
 Validation IN_PROGRESS. It will take some time to complete. Please wait...
 Validation ended with status: SUCCEEDED

 Enter to add cluster...
 Triggered add cluster, monitor the status of the task(task-id:870a523a-fc76-49f3-a8df-27fd0abfaed9) from sddc-manager ui
```