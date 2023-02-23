# Copyright 2021 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Prepare VxRail Manager Spec
import ipaddress
import json
import os
import requests
import subprocess
from utils.utils import Utils

__author__ = 'virtis'


class VxRailAuthAutomator:
    def __init__(self, args):
        self.utils = Utils(args)
        self.description = "VxRail Manager authentication details"
        self.two_line_separator = ['', '']

    def main_func(self):
        self.utils.printCyan("Please enter VxRail Manager's root credentials:")
        root_user = "root"
        root_password = self.utils.handle_password_input("Enter password:")

        print(*self.two_line_separator, sep='\n')

        self.utils.printCyan("Please enter VxRail Manager's admin credentials:")
        admin_user = self.utils.valid_input("\033[1m Enter username (mystic): \033[0m", "mystic")
        admin_password = self.utils.handle_password_input("Enter password:")

        print(*self.two_line_separator, sep='\n')

        return {
            "rootCredentials": self.to_credential_obj(root_user, root_password),
            "adminCredentials": self.to_credential_obj(admin_user, admin_password)
        }

    def to_credential_obj(self, user, pwd):
        return {
            "credentialType": "SSH",
            "username": user,
            "password": pwd
        }

    def prepare_network_info_and_payload(self, hosts_spec_len, mgmt_network_details, vsan_storage):
        vsan_network_obj = None
        if vsan_storage:
            self.utils.printYellow("** For e.g. vSAN Network VLAN ID: 1407, CIDR: 172.18.60.0/24, \n    "
                                   "IP Range for hosts vSAN IP assignment: 172.18.60.55-172.18.60.60")
            self.utils.printCyan("Please enter vSAN Network details: ")
            vsan_vlan_id, vsan_cidr, vsan_subnet, vsan_gateway, vsan_ip_range = self.input_network_info(True, True, hosts_spec_len)
            print(*self.two_line_separator, sep='\n')
            vsan_network_obj = self.to_network_obj('VSAN', vsan_vlan_id, vsan_cidr, vsan_subnet, vsan_gateway, vsan_ip_range)

        self.utils.printYellow("** For e.g. vMotion Network VLAN ID: 1406, CIDR: 172.18.59.0/24, \n    "
                               "IP Range for hosts vMotion IP assignment: 172.18.59.55-172.18.59.60")
        self.utils.printCyan("Please enter vMotion Network details: ")
        vmotion_vlan_id, vmotion_cidr, vmotion_subnet, vmotion_gateway, vmotion_ip_range = \
            self.input_network_info(True, True, hosts_spec_len)
        print(*self.two_line_separator, sep='\n')

        network_payload = [self.to_network_obj('VMOTION', vmotion_vlan_id, vmotion_cidr, vmotion_subnet, vmotion_gateway,
                           vmotion_ip_range)]
        if vsan_network_obj is not None:
            network_payload.append(vsan_network_obj)

        if mgmt_network_details and ('vlanId' in mgmt_network_details) and ('subnet' in mgmt_network_details) \
                and ('mask' in mgmt_network_details) and ('gateway' in mgmt_network_details):
            self.utils.printYellow("** By default the tool takes Management domain mgmt network for Create Domain and "
                                   "Primary cluster mgmt network for Create Cluster")
            self.utils.printYellow("** Existing mgmt network details: VLAN ID: "
                                        + str(mgmt_network_details['vlanId'])
                                        + ", CIDR: " + mgmt_network_details['subnet'])
            select_option = input("\033[1m Do you want to provide Management Network details?('yes' or 'no'): \033[0m")
            print(*self.two_line_separator, sep='\n')
            if select_option.lower() == 'yes' or select_option.lower() == 'y':
                network_payload.append(self.input_mgmt_network_info(hosts_spec_len))
            else:
                mgmt_network_obj = self.to_network_obj('MANAGEMENT',
                                                        mgmt_network_details['vlanId'],
                                                        mgmt_network_details['subnet'],
                                                        mgmt_network_details['mask'],
                                                        mgmt_network_details['gateway'],
                                                        None)
                network_payload.append(mgmt_network_obj)
        else:
            network_payload.append(self.input_mgmt_network_info(hosts_spec_len))
        return network_payload

    def input_mgmt_network_info(self, hosts_spec_len):
        self.utils.printCyan("Please enter Management Network details: ")
        mgmt_vlan_id, mgmt_cidr, mgmt_subnet, mgmt_gateway, mgmt_ip_range = \
            self.input_network_info(True, False, hosts_spec_len)
        print(*self.two_line_separator, sep='\n')
        return self.to_network_obj('MANAGEMENT', mgmt_vlan_id, mgmt_cidr, mgmt_subnet, mgmt_gateway, mgmt_ip_range)

    def count_ip_pool_ranges(self, ip_range, cidr, hosts_spec_len):
        ips = ip_range.split('-')
        ip1 = int(ipaddress.IPv4Address(ips[0].strip()))
        ip2 = int(ipaddress.IPv4Address(ips[1].strip()))

        if ipaddress.ip_address(ip1) and ipaddress.ip_address(ip2) not in ipaddress.ip_network(cidr):
            self.utils.printRed("IP pool range ips are not in the same network {}".format(cidr))
            return False

        number_of_ips = ((ip2 - ip1)+1)
        if number_of_ips < hosts_spec_len:
            self.utils.printRed("Number of ips from ip range {} is {} but required minimum {} ips to match with "
                                "number of hosts".format(ip_range, number_of_ips, hosts_spec_len))
            return False
        return True

    def input_network_info(self, cidr_req, ip_range_req, hosts_spec_len):
        cidr = ip_range = None
        vlan_id = int(self.utils.valid_input("\033[1m Enter VLAN Id: \033[0m", None, self.utils.valid_vlan))
        if cidr_req:
            cidr = self.utils.valid_input("\033[1m Enter CIDR: \033[0m", None, self.utils.valid_cidr)
        subnet = self.utils.valid_input("\033[1m Enter subnet mask(255.255.255.0): \033[0m", "255.255.255.0",
                                        self.utils.valid_ip)
        gateway = self.utils.valid_input("\033[1m Enter gateway IP: \033[0m", None, self.utils.valid_ip)
        if ip_range_req:
            while True:
                ip_range = self.utils.valid_input("\033[1m Enter IP Range: \033[0m", None, self.utils.valid_ip_ranges)
                if self.count_ip_pool_ranges(ip_range, cidr, hosts_spec_len):
                    break
        return vlan_id, cidr, subnet, gateway, ip_range

    def to_network_obj(self, type, vlan_id, cidr, subnet, gateway, ip_range):
        network_obj = {
            "type": type,
            "vlanId": vlan_id,
            "mask": subnet,
            "gateway": gateway
        }
        if cidr is not None:
            network_obj['subnet'] = cidr
        if ip_range is not None:
            ips = ip_range.split('-')
            ip_pools = [
                {
                    "start": ips[0].strip(),
                    "end": ips[1].strip()
                }
            ]
            network_obj['ipPools'] = ip_pools
        return network_obj

    def get_ssh_thumbprint(self, fqdn):
        cmd = "ssh-keygen -lf <(ssh-keyscan -t rsa {} 2>/dev/null) | cut -d' ' -f2".format(fqdn)
        sub_popen = subprocess.Popen(cmd,
                                     shell=True,
                                     executable='/bin/bash',
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        output, err = sub_popen.communicate()
        if sub_popen.returncode > 0:
            self.utils.printRed("Error encountered when execute command locally - Command:{}".format(cmd))
            exit(1)
        if type(output) == bytes:
            output = bytes.decode(output)
        # eg. Output : SHA256:uC0zLDfYZ3zGAkBx1iJ6pZSTF7TArSiQSTpZv9LAw18
        return output.strip("\n")

    def get_ssl_thumbprint(self, fqdn):
        cmd = "openssl s_client -connect {}:443 < /dev/null 2>/dev/null | openssl x509 " \
              "-fingerprint -sha256 -noout -in /dev/stdin".format(fqdn)
        sub_popen = subprocess.Popen(cmd,
                                     shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        output, err = sub_popen.communicate()
        if sub_popen.returncode > 0:
            self.utils.printRed("Error encountered when execute command locally - Command:{}".format(cmd))
            self.utils.printRed("Please check reachability of {}".format(fqdn))
            exit(1)
        if type(output) == bytes:
            output = bytes.decode(output)
        # eg. Output : SHA256 Fingerprint=DD:23:37:A7:46:5F:DF:BA:3D:14:C0:AA:FB:F7:20:96:9E:2C:A7:9B:03:44:AA:96:1A
        # :5C:1C:91:27:AA:55:28
        return output.split("=")[1].strip()

    def select_nic_profile(self):
        nic_profile_list = ["TWO_HIGH_SPEED", "FOUR_HIGH_SPEED", "FOUR_EXTREME_SPEED"]
        self.utils.printYellow("** ADVANCED_VXRAIL_SUPPLIED_VDS nic profile is supported only via VxRail JSON input")
        self.utils.printCyan("Please select nic profile:")
        for nic_profile in nic_profile_list:
            self.utils.printBold("{}) {}".format(nic_profile_list.index(nic_profile) + 1, nic_profile))
        nic_selection = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", "1",
                                               self.utils.valid_option, ["1", "2", "3"])
        selected_nic_profile = nic_profile_list[int(nic_selection) - 1]
        return selected_nic_profile

    def check_reachability(self, vxrail_fqdn):
        response = os.system("ping -c 1 {} 2>&1 > /dev/null".format(vxrail_fqdn))
        if response != 0:
            print(*self.two_line_separator, sep='\n')
            self.utils.printRed("VxRail Manager {} is not reachable".format(vxrail_fqdn))
            self.utils.printRed("Please make sure you have provided correct VxRail Manager and had run prerequisites of"
                                " changing VxRail Manager static IP to management IP")
            exit(1)
