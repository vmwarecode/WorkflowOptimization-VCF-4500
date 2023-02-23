# Copyright 2021 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: VxRail Json Converter

import functools
import ipaddress
import json
import os
import re
import requests
import subprocess
import yaml
from yaml.loader import SafeLoader
from utils.utils import Utils

__author__ = 'Hong.Yuan'

MANAGMENT = 'MANAGEMENT'

class VxRailJsonConverter:
    def __init__(self, args):
        self.description = "VxRail Manager JSON file conversion"
        self.utils = Utils(args)
        self.cluster_name = None
        self.vds_pg_map = {}
        self.vxm_payload = None
        self.host_spec = None
        self.error_message = []
        self.vxrail_config = None
        self.vxrm_version = None
        self.hostname = args[0]

    def __ip_comparator(self, ip1, ip2):
        ipsegs1 = ip1.split('.')
        ipsegs2 = ip2.split('.')
        for i in [0, 1, 2, 3]:
            res = int(ipsegs1[i]) - int(ipsegs2[i])
            if res == 0:
                continue
            return res
        return 0

    def __get_ip_range(self, ipsegs):
        ipnonemptysets = [ip for ip in ipsegs if self.__is_address_a_ip(ip)]
        if len(ipnonemptysets) == 0:
            return '', ''
        elif len(ipnonemptysets) < 2:
            return ipnonemptysets[0], ipnonemptysets[0]
        sortedips = sorted(ipnonemptysets, key=functools.cmp_to_key(self.__ip_comparator))
        return sortedips[0], sortedips[-1]

    def __is_address_a_ip(self, address):
        return re.match(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', address) is not None

    def __parse_fqdn_from_ip(self, address):
        rec, res = self.__local_run_command("nslookup {}".format(address))
        if rec > 0:
            self.__log_error("Failed to resolute FQDN according to IP {}".format(address))
            return None
        fqdn = None
        for onere in res.split("\n"):
            onere = onere.strip()
            if onere.find("name") > 0 and onere.find("=") > 0:
                fqdn = onere.split("=")[-1].strip()
                if fqdn.endswith("."):
                    fqdn = fqdn[0:-1]
        return fqdn

    def __parse_ip_from_fqdn(self, fqdn):
        rec, res = self.__local_run_command("nslookup {}".format(fqdn))
        if rec > 0:
            self.__log_error("Failed to resolve IP address from FQDN {}".format(fqdn))
            return None
        ipaddr = None
        isafter = False
        for onere in res.split("\n"):
            onere = onere.strip()
            if onere.startswith("Name"):
                fqdn = onere.split(":")[-1].strip()
                isafter = True
            elif onere.startswith("Address") and isafter:
                ipaddr = onere.split(":")[-1].strip()
                break
        return ipaddr

    def __log_error(self, msg):
        self.error_message.append(msg)

    def __local_run_command(self, cmd):
        sub_popen = subprocess.Popen(cmd,
                                     shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        output, err = sub_popen.communicate(None)
        if sub_popen.returncode > 0:
            # self.__log_error("Error to execute command: {}".format(cmd))
            output = err
        if type(output) == bytes:
            output = bytes.decode(output)
        return sub_popen.returncode, output

    def __netmask_to_cidr(self, netmask):
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def __get_ipfirst3_from_pools(self, ippools):
        for ip in ippools:
            if self.__is_address_a_ip(ip["start"]):
                ipseg = ip["start"].split(".")
                return "{}.{}.{}".format(ipseg[0], ipseg[1], ipseg[2])
        return "0.0.0"

    def __valid_resource_name(self, name, mystr):
        res = True
        if not name:
            self.__log_error("{} is Blank/Empty".format(mystr))
            res = False
        else:
            if len(name) > 80:
                self.__log_error("{} size should not be more than 80".format(mystr))
                res = False
        return res

    def parse(self, selected_domain_id, jsonfile, is_primary, existing_vcenters_fqdn=None):
        if not os.path.exists(jsonfile):
            self.__log_error("VxRail JSON file doesn't exists at {}".format(jsonfile))
        else:
            self.compute_spec = {}
            try:
                with open(jsonfile) as fp:
                    self.vxrail_config = json.load(fp)
                cluster_name = self.__get_attr_value(self.vxrail_config, ["vcenter", "cluster_name"])
                if self.__valid_resource_name(cluster_name, "Cluster Name"):
                    self.cluster_name = cluster_name
                if is_primary:
                    self.__convert_vcenter_spec(existing_vcenters_fqdn)
                else:
                    self.__validate_vcenter_vc_name_or_ip(existing_vcenters_fqdn)
                self.__convert_vxm_payload(selected_domain_id)
                self.__collect_pg_names()
                self.__convert_host_spec()
            except Exception as e:
                self.__log_error("VxRail JSON file is not in JSON format")
        return self.error_message if len(self.error_message) > 0 else None

    def __get_attr_value(self, jsonobj, attrs=None):
        if attrs is None:
            attrs = []
        if jsonobj is None:
            return None
        for attr in attrs:
            if type(attr) == int:
                if type(jsonobj) != list or len(jsonobj) <= attr:
                    return None
                jsonobj = jsonobj[attr]
            elif type(attr) == str:
                if type(jsonobj) != dict or attr not in jsonobj:
                    return None
                jsonobj = jsonobj[attr]
        return jsonobj

    # vlan could be 0 <= vlan <= 4096. Returning -1 if does not provided in vxrail json spec
    def __get_vlan(self, net_type):
        vdssets = self.__get_attr_value(self.vxrail_config, ["network", "vds"])
        for vdsset in vdssets:
            for pg in vdsset["portgroups"]:
                if pg["type"] == net_type:
                    return pg["vlan_id"]
        return -1

    def get_vmnics_mapped_to_system_dvs(self):
        vdssets = self.__get_attr_value(self.vxrail_config, ["network", "vds"])
        if len(vdssets) > 2:
            print("\033[91m More than two system dvs with ADVANCED_VXRAIL_SUPPLIED_VDS nic profile not supported\033["
                  "00m")
            exit(1)

        pg_types_to_vmnics = {}
        pg_types = ["MANAGEMENT", "VSAN", "VMOTION", "VXRAILSYSTEMVM", "VXRAILDISCOVERY"]
        for vdsset in vdssets:
            pg_types_per_vds = []
            for pg in vdsset["portgroups"]:
                if pg["type"] in pg_types:
                    pg_types_per_vds.append(pg["type"])
            if len(pg_types_per_vds) > 0:
                key = json.dumps(pg_types_per_vds)
                pg_types_to_vmnics[key] = self.__get_vmnics(vdsset)
        return pg_types_to_vmnics

    def __get_vmnics(self, vdsset):
        vmnics = []
        for nic_map in vdsset["nic_mappings"]:
            for vmnic_to_uplink in nic_map["uplinks"]:
                vmnics.append(vmnic_to_uplink["physical_nic"].lower())
        if len(vmnics) > 4:
            print("\033[91m More than four vmnics per system dvs is not supported with ADVANCED_VXRAIL_SUPPLIED_VDS "
                  "nic profile\033[00m")
            exit(1)
        return vmnics

    def get_vmnic_to_uplink_mapping_for_vdss(self):
        vdssets = self.__get_attr_value(self.vxrail_config, ["network", "vds"])
        pgtypes_to_vmnicuplink_mapping = {}
        pg_types = ["MANAGEMENT", "VSAN", "VMOTION", "VXRAILSYSTEMVM", "VXRAILDISCOVERY"]

        for vdsset in vdssets:
            vmnic_to_uplink_mapping = {}
            pg_types_per_vds = []
            for pg in vdsset["portgroups"]:
                if pg["type"] in pg_types:
                    pg_types_per_vds.append(pg["type"])
            for nic_map in vdsset["nic_mappings"]:
                for vmnic_to_uplink in nic_map["uplinks"]:
                    vmnic_to_uplink_mapping[vmnic_to_uplink["physical_nic"].lower()] = vmnic_to_uplink["name"]
            pgtypes_to_vmnicuplink_mapping[json.dumps(pg_types_per_vds)] = vmnic_to_uplink_mapping
        return pgtypes_to_vmnicuplink_mapping

    def get_portgroup_to_active_uplinks(self):
        if self.vxrail_config['version'] == "7.0.202":
            return None
        else:
            vdssets = self.__get_attr_value(self.vxrail_config, ["network", "vds"])
            pg_type_to_active_uplinks = {}
            pg_types = ["MANAGEMENT", "VSAN", "VMOTION", "VXRAILSYSTEMVM", "VXRAILDISCOVERY"]

            for vdsset in vdssets:
                for portgroup in vdsset["portgroups"]:
                    if portgroup["type"] in pg_types:
                        active_uplinks = []
                        for activeUplink in portgroup["failover_order"]["active"]:
                            active_uplinks.append(activeUplink)
                        # Adding standby uplink as active, in backend we will make it standby
                        for standbyUplink in portgroup["failover_order"]["standby"]:
                            active_uplinks.append(standbyUplink)
                        if len(active_uplinks) != 2:
                            print("\033[91m Please provide exact 2 uplinks for active/active or active/standby failover"
                                  " order for portgroups in VxRail Json Input\033[00m")
                            exit(1)
                        pg_type_to_active_uplinks[portgroup['type']] = active_uplinks
        return pg_type_to_active_uplinks

    def __get_ip_pools(self, net_type):
        hosts = self.__get_attr_value(self.vxrail_config, ["hosts"])
        pool = []
        if hosts is None:
            self.__log_error("Cannot find hosts field in VxRail JSON")
            return pool
        for h in hosts:
            tip = ""
            for nw in h["network"]:
                if nw["type"] == net_type:
                    tip = nw["ip"]
            pool.append(tip)
        ipstart, ipend = self.__get_ip_range(pool)
        return [{"start": ipstart, "end": ipend}]

    def __get_pg_name(self, net_type):
        vdssets = self.__get_attr_value(self.vxrail_config, ["network", "vds"])
        for vdsset in vdssets:
            for pg in vdsset["portgroups"]:
                if pg["type"] == net_type:
                    return pg["name"] if "name" in pg and len(pg["name"].strip()) > 0 else None
        return None

    def __validate_vcenter_vc_name_or_ip(self, selected_domain_vcenter_fqdn):
        if self.__get_attr_value(self.vxrail_config, ["vcenter", "customer_supplied"]):
            if self.vxrail_config['version'] == "7.0.202":
                # Perth
                address = self.__get_attr_value(self.vxrail_config, ["vcenter", "customer_supplied_vc_name_or_ip"])
            else:
                address = self.__get_attr_value(self.vxrail_config, ["vcenter", "customer_supplied_vc_name"])
            if address is None:
                self.__log_error("vCenter hostname or IP not specified")
            else:
                if self.__is_address_a_ip(address):
                    fqdn = self.__parse_fqdn_from_ip(address)
                else:
                    fqdn = address
                if fqdn not in selected_domain_vcenter_fqdn:
                    self.__log_error("vCenter IP/FQDN provided in json does not match with the selected domain vCenter")

    def __convert_vcenter_spec(self, existing_vcenters_fqdn):
        self.vcenter_spec = {"vmSize": "medium", "storageSize": "lstorage"}
        # only handles for external vc
        if self.__get_attr_value(self.vxrail_config, ["vcenter", "customer_supplied"]):
            if self.vxrail_config['version'] == "7.0.202":
                # Perth
                address = self.__get_attr_value(self.vxrail_config, ["vcenter", "customer_supplied_vc_name_or_ip"])
            else:
                address = self.__get_attr_value(self.vxrail_config, ["vcenter", "customer_supplied_vc_name"])
            if address is None:
                self.__log_error("vCenter hostname or IP not specified")
            else:
                # needs to check whether it is ok to count on the dns configured on sddc manager
                if self.__is_address_a_ip(address):
                    fqdn = self.__parse_fqdn_from_ip(address)
                    if fqdn is None:
                        self.__log_error("vCenter FQDN is not resolved successfully from ip {}".format(address))
                else:
                    topdomain = self.__get_attr_value(self.vxrail_config, ["global", "top_level_domain"])
                    if not address.endswith(topdomain):
                        self.__log_error("vCenter FQDN {} is not valid for an external address".format(address))
                    fqdn = address
                    address = self.__parse_ip_from_fqdn(address)
                    if address is None:
                        self.__log_error("vCenter IP is not resolved successfully from FQDN {}".format(fqdn))
                if fqdn in existing_vcenters_fqdn:
                    self.__log_error("Input vCenter with FQDN {} already exists as part of different domain. Please"
                                     " pass new vCenter IP/hostname for Create Domain".format(fqdn))
                self.vcenter_spec["name"] = fqdn.split(".")[0].lower()
                self.vcenter_spec["networkDetailsSpec"] = {
                    "ipAddress": address,
                    "dnsName": fqdn
                }
                self.vcenter_spec["rootPassword"] = ""  # needs to check where this come from
                datacenter_name = self.__get_attr_value(self.vxrail_config, ["vcenter", "datacenter_name"])
                if self.__valid_resource_name(datacenter_name, "Datacenter Name"):
                    self.vcenter_spec["datacenterName"] = datacenter_name
        else:
            self.__log_error("Target vCenter is not external one")

    def __convert_host_spec(self):
        self.host_spec = []
        topdomain = self.__get_attr_value(self.vxrail_config, ["global", "top_level_domain"])
        errors = []
        if len(self.__get_attr_value(self.vxrail_config, ["hosts"])) < 3:
            errors.append("Please pass 3-node cluster config scenario from VxRail Json input. We are not"
                          " supporting 2-node FC scenarios")
        for h in self.__get_attr_value(self.vxrail_config, ["hosts"]):
            hostonespec = {}
            hostonespec["hostName"] = "{}.{}".format(h["hostname"], topdomain)
            rec, res = self.__local_run_command("nslookup {}".format(hostonespec["hostName"]))
            if rec > 0:
                errors.append("Cannot resolve the hostname {} with the provided DNS server".format(hostonespec["hostName"]))
            else:
                ipaddress = self.__parse_ip_from_fqdn(hostonespec["hostName"])
                for nw in h["network"]:
                    if nw["type"] == "MANAGEMENT":
                        if ipaddress == nw["ip"]:
                            hostonespec["ipAddress"] = nw["ip"]
                            break
                        else:
                            errors.append("Input host IP address {} is not in [{}] that resolved from host name {}"
                                          .format(nw["ip"], ipaddress, hostonespec["hostName"]))
            hostonespec["username"] = "root"
            hostonespec["password"] = self.__get_attr_value(h, ["accounts", "root", "password"])
            hostonespec["sshThumbprint"] = ""
            hostonespec["serialNumber"] = h["host_psnt"]
            self.host_spec.append(hostonespec)
        if errors:
            self.__log_error(errors)

    def __collect_pg_names(self):
        self.vds_pg_map = {
            "MANAGEMENT": self.__get_pg_name("MANAGEMENT"),
            "VSAN": self.__get_pg_name("VSAN"),
            "VMOTION": self.__get_pg_name("VMOTION")
        }

    #This will compare the vxrail first run json with sample json based on vcf version
    def compare_json(self, vxrail_mapping, selected_domain_id):
        self.get_vxrm_version(selected_domain_id)
        for value in vxrail_mapping:
            if self.vxrm_version == value['version']:
                file_loc = value['path']
                with open(file_loc) as fp:
                    json_spec = json.load(fp)
                sample_json = json_spec  #old
                input_json = self.vxrail_config #new
                self.json_diff(sample_json, input_json, '')

    """
        This is a recursive function to find difference between two dictionaries.
        It finds out the properties which are there in input_json(json provided by user) but not in sample_json
        (sample json for a particular vxrail version).
        It checks the properties recursively.
        prev_key stores the hierarchy of the property which is there in input_json but not sample_json
        Ex. vcenter.accounts implies new property found at input_json["vcenter"]["accounts"]
    """
    def json_diff(self, sample_json, input_json, prev_key):
        cur_diff_list = []
        for k in input_json.keys() :
            cur_key = k if prev_key == '' else prev_key + '.' + k
            if k not in sample_json.keys():
                dtype = self.find_dtype(input_json[k])
                if input_json[k] and  dtype != 'UNSUPPORTED':
                    cur_diff_list.append({'attributeName':k, 'value':input_json[k], 'datatype':dtype})
            elif type(input_json[k]) is dict : # When a new attribute is found in input_json & is of type dict
                self.json_diff(sample_json[k], input_json[k], cur_key)
        if cur_diff_list:
            if "contextWithKeyValuePair" not in self.vxm_payload:
                self.vxm_payload["contextWithKeyValuePair"] = {}
            self.vxm_payload["contextWithKeyValuePair"][prev_key] = cur_diff_list

    def find_dtype(self, x):
        dtype = 'UNSUPPORTED'
        if isinstance(x, bool):
            dtype = "BOOLEAN"
        elif isinstance(x, int):
            dtype = "INTEGER"
        elif isinstance(x, str):
            dtype = "STRING"
        return dtype

    def __convert_vxm_payload(self, selected_domain_id):
        self.vxm_payload = {
            "rootCredentials": {
                "credentialType": "SSH",
                "username": "root",
                "password": self.__get_attr_value(self.vxrail_config,
                                                  ["vxrail_manager", "accounts", "root", "password"])
            },
            "adminCredentials": {
                "credentialType": "SSH",
                "username": self.__get_attr_value(self.vxrail_config,
                                                  ["vxrail_manager", "accounts", "service", "username"]),
                "password": self.__get_attr_value(self.vxrail_config,
                                                  ["vxrail_manager", "accounts", "service", "password"])
            },
            "networks": [
                {
                    "type": "VMOTION",
                    "vlanId": self.__get_vlan("VMOTION"),
                    "ipPools": self.__get_ip_pools("VMOTION"),
                    "mask": self.__get_attr_value(self.vxrail_config, ["global", "cluster_vmotion_netmask"])
                }
            ],
            "dnsName": "{}.{}".format(self.__get_attr_value(self.vxrail_config, ["vxrail_manager", "name"]),
                                      self.__get_attr_value(self.vxrail_config, ["global", "top_level_domain"])),
            "ipAddress": self.__get_attr_value(self.vxrail_config, ["vxrail_manager", "ip"]),
            "nicProfile": self.__get_attr_value(self.vxrail_config, ["network", "nic_profile"]),
            "sslThumbprint": "",  # leave it as empty
            "sshThumbprint": ""  # leave it as empty
        }

        properties_file = "data_passthrough_properties.yaml"
        if os.path.exists(properties_file):
            with open(properties_file) as f:
                try:
                    properties = yaml.load(f, Loader = SafeLoader)
                    if properties is not None:
                        if "data_passthrough" in properties:
                            if properties["data_passthrough"]:
                                self.compare_json(properties['vxrail_versions'], selected_domain_id)
                except yaml.YAMLError as e:
                    self.utils.printRed("Error parsing yaml file " + properties_file)
                    exit(1)

        cluster_type = self.__get_attr_value(self.vxrail_config, ["global", "cluster_type"])
        vsan_vlan = self.__get_vlan("VSAN")
        vsan_network_present = False
        for h in self.__get_attr_value(self.vxrail_config, ["hosts"]):
            for nw in h["network"]:
                if nw["type"] == "VSAN":
                    vsan_network_present = True
        if cluster_type == 'STANDARD' and vsan_vlan != -1 and vsan_network_present is True:
            vsan_network = {
                "type": "VSAN",
                "vlanId": self.__get_vlan("VSAN"),
                "ipPools": self.__get_ip_pools("VSAN"),
                "mask": self.__get_attr_value(self.vxrail_config, ["global", "cluster_vsan_netmask"])
            }
            self.vxm_payload["networks"].append(vsan_network)

        for nwk in self.vxm_payload["networks"]:
            ipfirst3 = self.__get_ipfirst3_from_pools(nwk["ipPools"])
            nwk["subnet"] = "{}.0/{}".format(ipfirst3, self.__netmask_to_cidr(nwk["mask"]))
            nwk["gateway"] = "{}.1".format(ipfirst3)

        mgmt_network = {
            "type": "MANAGEMENT",
            "vlanId": self.__get_vlan("MANAGEMENT"),
            "mask": self.__get_attr_value(self.vxrail_config, ["global", "cluster_management_netmask"]),
            "gateway": self.__get_attr_value(self.vxrail_config, ["global", "cluster_management_gateway"])
        }
        try:
            mgmt_network["subnet"] = str(ipaddress.IPv4Network((mgmt_network["gateway"], mgmt_network["mask"]), strict=False))
        except Exception as e:
            self.__log_error("Please check provided management gateway and netmask are valid")
        self.vxm_payload["networks"].append(mgmt_network)

    # Find VxRail Manager version for selected domain
    def get_vxrm_version(self, selected_domain_id):
        domain_id = None
        default_cluster_id = None

        if selected_domain_id is not None:
            domain_id = selected_domain_id
        else:
            domains_url = 'https://' + self.hostname + '/v1/domains'
            domains = self.utils.get_request(domains_url)
            for domain in domains['elements']:
                if domain['type'] == MANAGMENT:
                    domain_id = domain['id']

        get_cluster_url = 'http://' + self.hostname + '/inventory/clusters'
        header = {'Content-Type': 'application/json'}
        response = requests.get(get_cluster_url, headers=header, verify=False)
        if response.status_code == 200:
            data = json.loads(response.text)
            for cluster in data:
                if cluster['domainId'] == domain_id and cluster['isDefault']:
                    default_cluster_id = cluster['id']
        else:
            self.utils.printRed("Error executing API: {}, status code: {}".format(url, response.status_code))
            exit(1)

        vxrm_url = 'https://' + self.hostname + '/v1/vxrail-managers?domainID=' + domain_id + '&clusterID' + default_cluster_id
        vxrm_details = self.utils.get_request(vxrm_url)
        for vxrm in vxrm_details['elements']:
            self.vxrm_version = vxrm['version'].split("-")[0]

    def get_vxm_payload(self):
        return self.vxm_payload

    def get_vcenter_spec(self):
        return self.vcenter_spec

    def get_pg_name_map(self):
        return self.vds_pg_map

    def get_cluster_name(self):
        return self.cluster_name

    def get_host_spec(self):
        return self.host_spec

    # this is for dump test
    def to_string(self):
        fjson_obj = {
            "cluster_name": self.get_cluster_name(),
            "vxrail_details": self.get_vxm_payload(),
            "host_spec": self.get_host_spec()
        }
        return json.dumps(fjson_obj)
