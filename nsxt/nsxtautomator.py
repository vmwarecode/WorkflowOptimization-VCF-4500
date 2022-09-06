# Copyright 2021 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Prepare NSX-T Spec

import ipaddress
import re

from utils.utils import Utils
import sys

__author__ = 'virtis'


class NsxtAutomator:
    def __init__(self, args):
        self.utils = Utils(args)
        self.description = "NSX-T instance deployment"
        self.hostname = args[0]
        self.two_line_separator = ['', '']

    # If current handling domain is management domain, is_primary must be False
    def prepare_nsxt_instance(self, selected_domain_id, is_primary=True, gateway=None, netmask=None):
        nsxt_instances, existing_nsxt_fqdns = self.get_nsxt_instances(selected_domain_id, is_primary)
        if is_primary:
            if len(nsxt_instances) > 0:
                print(*self.two_line_separator, sep='\n')
                self.utils.printCyan("Please choose NSX-T instance option:")
                self.utils.printBold("1) Create new NSX-T instance (default)")
                self.utils.printBold("2) Use existing NSX-T instance")
                theoption = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", "1",
                                                   self.utils.valid_option, ["1", "2"])
            else:
                self.utils.printYellow("** No shared NSX-T instance was found, you need to create a new one")
                theoption = "1"
        else:
            if len(nsxt_instances) == 0:
                # In a common situation, this is not possible
                self.utils.printRed("No shared NSX-T instance discovered in current domain")
                input("Enter to exit ...")
                sys.exit(1)
            else:
                theoption = "2"

        print(*self.two_line_separator, sep='\n')

        if theoption == "1":
            return self.option1_new_nsxt_instance(gateway, netmask, existing_nsxt_fqdns)

        return self.option2_existing_nsxt(nsxt_instances, is_primary)

    """
        In case of secondary cluster, the NSX-T cluster has to be the same as that of the primary cluster. 
        We don’t need to provide an option to create a new NSX-T cluster or list the NSX-T clusters that are not mapped to the primary cluster. 
        We can identify the NSX-T cluster based on the domain ID (as provided below).

        In case of primary cluster, the NSX-T cluster could be a new cluster or an existing one. 
        List only the NSX-T clusters that have the property isShareable as TRUE. 
        The management NSX-T cluster is dedicated to management domain and will have the isShareable property set to FALSE.
    """

    def get_nsxt_instances(self, selected_domain_id, is_primary=True):
        self.utils.printGreen("Getting shared NSX-T cluster information...")
        url = 'https://' + self.hostname + '/v1/nsxt-clusters'
        response = self.utils.get_request(url)
        nsxinstances = []
        existing_nsxt_fqdns = []
        for oneins in response["elements"]:
            existing_nsxt_fqdns.append(oneins["vipFqdn"])
            for node in oneins["nodes"]:
                existing_nsxt_fqdns.append(node["fqdn"])
            if is_primary and oneins["isShareable"]:
                nsxinstances.append(oneins)
            elif not is_primary:
                domainids = [onedomain["id"] for onedomain in oneins["domains"]]
                if selected_domain_id in domainids:
                    nsxinstances.append(oneins)
        return nsxinstances, existing_nsxt_fqdns

    def get_static_ip_pool(self, nsxt_cluster_id):
        self.utils.printGreen("Getting Static IP Pool information...")
        url = 'https://' + self.hostname + '/v1/nsxt-clusters/' + nsxt_cluster_id + '/ip-address-pools'
        response = self.utils.get_request(url)
        ip_address_pools = []
        for element in response['elements']:
            ip_address_pools.append(element)
        return ip_address_pools

    def __generate_ip_address_pool_ranges(self, inputstr):
        ip_ranges = [x.strip() for x in inputstr.split(',')]
        res = []
        for ip_range in ip_ranges:
            ips = ip_range.split('-')
            res.append({"start": ips[0], "end": ips[1]})
        return res

    def ip_pool_ranges_validation(self, inputstr, cidr):
        ip_ranges = [x.strip() for x in inputstr.split(',')]
        for ip_range in ip_ranges:
            ips = ip_range.split('-')
            ip1 = int(ipaddress.IPv4Address(ips[0].strip()))
            ip2 = int(ipaddress.IPv4Address(ips[1].strip()))
            if ipaddress.ip_address(ip1) and ipaddress.ip_address(ip2) not in ipaddress.ip_network(cidr):
                self.utils.printRed("IP address pool range ips are not in the same network {}".format(cidr))
                return False
        return True

    def check_overlap_subnets(self, cidrs, input_cidr):
        if cidrs:
            for c in cidrs:
                if ipaddress.IPv4Network(input_cidr).overlaps(ipaddress.IPv4Network(c)):
                    self.utils.printRed(
                        'Overlapping subnet {} with {}. Please enter valid subnet details...'.format(input_cidr, c))
                    return True
        return False

    def input_subnet(self, subnets, cidrs, count):
        print(*self.two_line_separator, sep='\n')
        self.utils.printCyan("Subnet #{}".format(count))
        cidr = self.utils.valid_input("\033[1m Enter CIDR: \033[0m", None, self.utils.valid_cidr)
        self.utils.printYellow("** Multiple IP Ranges are supported by comma separated")
        while True:
            ip_ranges = self.utils.valid_input("\033[1m Enter IP Range: \033[0m", None, self.utils.valid_ip_ranges)
            if self.ip_pool_ranges_validation(ip_ranges, cidr):
                break
        gateway_ip = self.utils.valid_input("\033[1m Enter Gateway IP: \033[0m", None, self.utils.valid_ip)

        if self.check_overlap_subnets(cidrs, cidr):
            self.input_subnet(subnets, cidrs, count)
        else:
            cidrs.append(cidr)
            subnet = {
                "ipAddressPoolRanges": self.__generate_ip_address_pool_ranges(ip_ranges),
                "cidr": cidr,
                "gateway": gateway_ip
            }
            subnets.append(subnet)
            print(*self.two_line_separator, sep='\n')
            select_option = input("\033[1m Do you want to add another subnet ? (Enter 'yes' or 'no'): \033[0m")
            if select_option.lower() == 'yes' or select_option.lower() == 'y':
                self.input_subnet(subnets, cidrs, count + 1)
            return subnets

    def create_static_ip_pool(self):
        self.utils.printCyan("Create New Static IP Pool")
        while True:
            pool_name = input("\033[1m Enter Pool Name: \033[0m")
            reg = "^[a-zA-Z0-9-_]+$"
            match_re = re.compile(reg)
            result = re.search(match_re, pool_name)
            if not result:
                self.utils.printRed("Invalid IP pool address name. The IP address pool name should contain only "
                                    "alphanumeric characters along with '-' or '_' without spaces")
            else:
                break
        description = input("\033[1m Enter Description(Optional): \033[0m")
        ip_address_pool_spec = {
            "name": pool_name,
            "subnets": self.input_subnet([], [], count=1)
        }
        if description:
            ip_address_pool_spec.update({"description": description})
        return ip_address_pool_spec

    def prepare_ip_address_pool(self, ip_address_pool):
        ip_address_pool_spec = {
            "name": ip_address_pool['name']
        }
        return ip_address_pool_spec

    def option2_existing_nsxt(self, nsxt_instances, is_primary):
        geneve_vlan = self.utils.valid_input("\033[1m Enter Geneve vLAN ID (0-4096): \033[0m ", None, self.utils.valid_vlan)
        print(*self.two_line_separator, sep='\n')

        selected_ins = None
        if is_primary:
            self.utils.printCyan("Please select one NSX-T instance")
            ct = 0
            nsxt_map = {}
            for nsxt_inst in nsxt_instances:
                idx = str(ct + 1)
                ct += 1
                nsxt_map[idx] = nsxt_inst
                self.utils.printBold("{0}) NSX-T vip: {1}".format(idx, nsxt_inst["vipFqdn"]))

            choiceidx = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", None, self.utils.valid_option,
                                               nsxt_map.keys())
            selected_ins = nsxt_map[choiceidx]
        else:
            selected_ins = nsxt_instances[0]
            self.utils.printGreen("Found NSX-T instance : {}".format(selected_ins["vipFqdn"]))

        print(*self.two_line_separator, sep='\n')
        self.utils.printCyan("Please choose IP Allocation for TEP IPs option:")
        self.utils.printBold("1) DHCP (default)")
        self.utils.printBold("2) Static IP Pool")
        selected_option = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", "1",
                                                 self.utils.valid_option,
                                                 ["1", "2"])
        print(*self.two_line_separator, sep='\n')

        ip_address_pool_spec = None
        if selected_option == "2":
            self.utils.printCyan("Select the option for Static IP Pool:")
            self.utils.printBold("1) Create New Static IP Pool(default)")
            self.utils.printBold("2) Re-use an Existing Static Pool")
            static_ip_pool_option = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", "1",
                                                           self.utils.valid_option,
                                                           ["1", "2"])
            print(*self.two_line_separator, sep='\n')

            if static_ip_pool_option == "1":
                ip_address_pool_spec = self.create_static_ip_pool()
            elif static_ip_pool_option == "2":
                ip_address_pools = self.get_static_ip_pool(selected_ins["id"])
                print(*self.two_line_separator, sep='\n')
                if not ip_address_pools:
                    self.utils.printRed("No existing Static IP Pools are getting discovered...")
                    input("\033[1m Enter to exit ...\033[0m")
                    sys.exit(1)
                self.utils.printCyan("Please select one static ip pool:")
                self.utils.printBold(
                    "-----Pool Name-------------------Subnets---------------------------Available IPs--")
                self.utils.printBold(
                    "----------------------------------------------------------------------------------")
                count = 0
                ip_pool_map = {}
                for ip_address_pool in ip_address_pools:
                    count += 1
                    pool_name = '{}) {} : '.format(count, ip_address_pool['name'])
                    self.utils.printBold(
                        '{} Static/Block Subnets {}: {}'.format(pool_name, 30 * ' ',
                                                                ip_address_pool['availableIpAddresses']))
                    if ip_address_pool['staticSubnets']:
                        self.utils.printBold('{} Static Subnets '.format(len(pool_name) * ' '))
                        print("{}\033[36m  -----CIDR-------------IP Ranges-----------".format(len(pool_name) * ' '))
                        for static_subnet in ip_address_pool['staticSubnets']:
                            ip_ranges = []
                            for ip_range in static_subnet['ipAddressPoolRanges']:
                                ip_ranges.append('{}-{}'.format(ip_range['start'], ip_range['end']))
                            print("\033[36m  {} {} : {}".format(len(pool_name) * ' ', static_subnet['cidr'], ip_ranges))

                    if 'blockSubnets' in ip_address_pool:
                        self.utils.printBold('{} Block Subnets '.format(len(pool_name) * ' '))
                        print("{}\033[36m  -----CIDR-------------Size----------------".format(len(pool_name) * ' '))
                        for block_subnet in ip_address_pool['blockSubnets']:
                            print("\033[36m  {} {} : {}".format(len(pool_name) * ' ', block_subnet['cidr'],
                                                                block_subnet['size']))
                    ip_pool_map[str(count)] = self.prepare_ip_address_pool(ip_address_pool)
                    print('\n')
                choice = self.utils.valid_input("\033[0;1m Enter your choice(number): \033[0m", None,
                                                self.utils.valid_option,
                                                ip_pool_map.keys())
                ip_address_pool_spec = ip_pool_map[choice]
            print(*self.two_line_separator, sep='\n')

        nsxClusterSpec = {
            'nsxTClusterSpec': {
                'geneveVlanId': geneve_vlan
            }
        }

        if is_primary:
            nsxTSpec = {
                "nsxManagerSpecs": [
                ],
                "vip": selected_ins["vip"],
                "vipFqdn": selected_ins["vipFqdn"]
            }
            for nsxnode in selected_ins["nodes"]:
                nsxTSpec["nsxManagerSpecs"].append(
                    {
                        "name": nsxnode["name"],
                        "networkDetailsSpec": {
                            "dnsName": nsxnode["fqdn"],
                            "ipAddress": nsxnode.get("ipAddress")
                        }
                    }
                )

            if ip_address_pool_spec is not None:
                nsxTSpec.update({"ipAddressPoolSpec": ip_address_pool_spec})
            return {"nsxTSpec": nsxTSpec, "nsxClusterSpec": nsxClusterSpec}
        else:
            if ip_address_pool_spec is not None:
                nsxClusterSpec['nsxTClusterSpec']['ipAddressPoolSpec'] = ip_address_pool_spec
            return {"nsxClusterSpec": nsxClusterSpec}

    def input_nsxt_fqdns(self, input_str, existing_nsxt_fqdns, entered_nsxt_fqdns):
        while True:
            nsxt_fqdn = self.utils.valid_input("\033[1m {} \033[0m".format(input_str), None, self.utils.valid_fqdn)
            if nsxt_fqdn in existing_nsxt_fqdns:
                self.utils.printRed("NSX-T FQDN {} already exists as part of different domain. Please pass new "
                                    "NSX-T FQDN".format(nsxt_fqdn))
            elif nsxt_fqdn in entered_nsxt_fqdns:
                self.utils.printRed("NSX-T FQDN {} already given for other NSX-T instances. Please pass new "
                                    "NSX-T FQDN".format(nsxt_fqdn))
            else:
                break
        print(*self.two_line_separator, sep='\n')
        return nsxt_fqdn

    def option1_new_nsxt_instance(self, gateway, netmask, existing_nsxt_fqdns):
        geneve_vlan = self.utils.valid_input("\033[1m Enter Geneve vLAN ID (0-4096): \033[0m", None,
                                             self.utils.valid_vlan)
        print(*self.two_line_separator, sep='\n')
        while True:
            admin_password = self.utils.handle_password_input("Enter NSX-T manager root password:")
            if len(admin_password) < 12:
                self.utils.printRed("Password should at least be 12 characters long")
            else:
                break
        print(*self.two_line_separator, sep='\n')

        self.utils.printCyan("Please Enter NSX-T details:")
        print()

        entered_nsxt_fqdns = []
        nsxt_vip_fqdn = self.input_nsxt_fqdns("Enter FQDN for NSX-T VIP:", existing_nsxt_fqdns, entered_nsxt_fqdns)

        entered_nsxt_fqdns.append(nsxt_vip_fqdn)
        nsxt_1_fqdn = self.input_nsxt_fqdns("Enter FQDN for 1st NSX-T Manager:", existing_nsxt_fqdns, entered_nsxt_fqdns)

        entered_nsxt_fqdns.append(nsxt_1_fqdn)
        nsxt_2_fqdn = self.input_nsxt_fqdns("Enter FQDN for 2nd NSX-T Manager:", existing_nsxt_fqdns, entered_nsxt_fqdns)

        entered_nsxt_fqdns.append(nsxt_2_fqdn)
        nsxt_3_fqdn = self.input_nsxt_fqdns("Enter FQDN for 3rd NSX-T Manager:", existing_nsxt_fqdns, entered_nsxt_fqdns)

        self.utils.printCyan("Please choose IP Allocation for TEP IPs option:")
        self.utils.printBold("1) DHCP (default)")
        self.utils.printBold("2) Static IP Pool")
        selected_option = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", "1",
                                                 self.utils.valid_option,
                                                 ["1", "2"])

        ip_address_pool_spec = None
        if selected_option == "2":
            print(*self.two_line_separator, sep='\n')
            ip_address_pool_spec = self.create_static_ip_pool()
        print(*self.two_line_separator, sep='\n')

        nsxTSpec = {
            "nsxManagerSpecs": [
                self.to_nsx_manager_obj(nsxt_1_fqdn, gateway, netmask),
                self.to_nsx_manager_obj(nsxt_2_fqdn, gateway, netmask),
                self.to_nsx_manager_obj(nsxt_3_fqdn, gateway, netmask)
            ],
            "vip": self.utils.nslookup_ip_from_dns(nsxt_vip_fqdn),
            "vipFqdn": nsxt_vip_fqdn,
            "nsxManagerAdminPassword": admin_password
        }

        if ip_address_pool_spec is not None:
            nsxTSpec.update({"ipAddressPoolSpec": ip_address_pool_spec})

        nsxClusterSpec = {
            'nsxTClusterSpec': {
                'geneveVlanId': geneve_vlan
            }
        }
        return {"nsxTSpec": nsxTSpec, "nsxClusterSpec": nsxClusterSpec}

    def to_nsx_manager_obj(self, fqdn, gateway, netmask):
        ip = self.utils.nslookup_ip_from_dns(fqdn)
        return {
            "name": fqdn.split('.')[0],
            "networkDetailsSpec": {
                "ipAddress": ip,
                "dnsName": fqdn,
                "gateway": gateway,
                "subnetMask": netmask
            }
        }
