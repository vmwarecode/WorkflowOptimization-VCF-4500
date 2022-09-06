# Copyright 2021 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Prepare Hosts Spec

import time
from typing import Dict, Any
from utils.utils import Utils

__author__ = 'virtis'


class HostsAutomator:
    def __init__(self, args):
        self.utils = Utils(args)
        self.hostname = args[0]
        self.two_line_separator = ['', '']
        self.password_map = {}

    def discover_hosts(self, vxrm_fqdn, vxrm_ssl_thumbprint):
        self.utils.printGreen("Discovering hosts by VxRail Manager...")
        print(*self.two_line_separator, sep='\n')
        post_url = 'https://' + self.hostname + '/v1/hosts/queries'
        payload = {
            "name": "UNMANAGED_HOSTS_IN_HCIMGR",
            "arguments": {
                "hciManagerFqdn": vxrm_fqdn,
                "hciManagerSslThumbprint": vxrm_ssl_thumbprint
            },
            "description": "Return all the unmanaged hosts discovered by HCI manager"
        }
        response = self.utils.post_request_for_host_discovery(payload, post_url)

        time.sleep(10)
        get_url = 'https://' + self.hostname + response.headers['Location']
        host_discovery_response = self.utils.poll_on_queries_for_host_discovery(get_url)

        discovered_hosts = []
        for element in host_discovery_response['elements']:
            if element['status'] == 'UNASSIGNED_USEABLE':
                discovered_hosts.append(
                    HostDiscovery(element['serialNumber'], element['sshThumbprint'], element['physicalNics'],
                                  element['isPrimary']))

        return discovered_hosts

    def input_hosts_details(self, discovered_hosts, vsan_storage):
        min_nodes_req = 3
        serialno_to_thumbprint = self.get_serialno_to_thumbprint_mapping(discovered_hosts)
        primary_node_serialno = self.get_primary_node_serialno(discovered_hosts)
        primary_node_thumbprint = serialno_to_thumbprint[primary_node_serialno]

        if len(serialno_to_thumbprint.keys()) < min_nodes_req:
            print(*self.two_line_separator, sep='\n')
            self.utils.printRed("Hosts discovered by the VxRail Manager are:")
            self.utils.printRed("{}".format(serialno_to_thumbprint.keys()))
            self.utils.printRed("Minimum {} nodes are required for initial configuration".format(min_nodes_req))
            exit(1)

        # Deleting primary node from dict to display other nodes only to the user
        del serialno_to_thumbprint[primary_node_serialno]

        self.utils.printYellow("** By Default primary node gets selected. Please select atleast two other nodes.")
        self.utils.printCyan("Hosts discovered by the VxRail Manager are:")
        self.utils.printBold("VxRail Manager is detected on primary node : {}".format(primary_node_serialno))
        for i, key in enumerate(serialno_to_thumbprint.keys()):
            self.utils.printBold("{}) {}".format(i + 1, key))

        while True:
            var = True
            host_options = input(
                "\033[1m Enter your choices(numbers by comma separated): \033[0m").strip().split(',')
            for host_option in host_options:
                if len(host_option.strip()) == 0:
                    self.utils.printRed("Please select atleast 2 other nodes as Minimum 3 nodes are required for "
                                        "initial configuration")
                    var = False
                if var:
                    if int(host_option.strip()) not in range(1, len(serialno_to_thumbprint) + 1):
                        self.utils.printRed("Please enter valid options for selecting hosts")
                        var = False
            if var and len(host_options) < (min_nodes_req - 1):
                self.utils.printRed("Please select atleast 2 other nodes as Minimum 3 nodes are required for "
                                    "initial configuration")
                var = False
            if var:
                break

        selected_hosts_serial_no = [primary_node_serialno]
        for index, element in enumerate(host_options):
            selected_hosts_serial_no.append(list(serialno_to_thumbprint.keys())[int(element) - 1])

        print(*self.two_line_separator, sep='\n')

        fqdn_to_serialno = {}
        for host_serial_no in selected_hosts_serial_no:
            self.utils.printCyan("Please enter host details for serial no {}:".format(host_serial_no))
            while True:
                fqdn = self.utils.valid_input("\033[1m Enter FQDN: \033[0m", None, self.utils.valid_fqdn)
                if fqdn_to_serialno and fqdn in fqdn_to_serialno.keys():
                    self.utils.printRed(
                        "Input host FQDN already given for other hosts. Please pass different host FQDN")
                else:
                    break
            fqdn_to_serialno[fqdn] = host_serial_no
            print(*self.two_line_separator, sep='\n')

        self.utils.printCyan("Please choose password option:")
        self.utils.printBold("1) Input one password that is applicable to all the hosts (default)")
        self.utils.printBold("2) Input password individually for each host")
        option = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", "1", self.utils.valid_option,
                                        ["1", "2"])

        print(*self.two_line_separator, sep='\n')

        # Adding primary node back to the dict
        serialno_to_thumbprint[primary_node_serialno] = primary_node_thumbprint

        hosts_spec = []
        if option == "1":
            password = self.utils.handle_password_input("Enter root password for hosts:")
            print(*self.two_line_separator, sep='\n')
            for host_fqdn in fqdn_to_serialno.keys():
                hosts_spec.append(self.to_hosts_spec_obj(host_fqdn, password, fqdn_to_serialno[host_fqdn],
                                                         serialno_to_thumbprint[fqdn_to_serialno[host_fqdn]]))
        else:
            for host_fqdn in fqdn_to_serialno.keys():
                password = self.utils.handle_password_input("Enter root password for host {}:".format(host_fqdn))
                print(*self.two_line_separator, sep='\n')
                hosts_spec.append(self.to_hosts_spec_obj(host_fqdn, password, fqdn_to_serialno[host_fqdn],
                                                         serialno_to_thumbprint[fqdn_to_serialno[host_fqdn]]))
        return hosts_spec

    def get_physical_nics(self, discovered_hosts):
        nics: Dict[Any, Any] = {}
        for nic in discovered_hosts[0].physical_nics:
            nics[nic['deviceName']] = nic['speed']
        return nics

    def get_serialno_to_thumbprint_mapping(self, discovered_hosts):
        serialno_to_thumbprint = {}
        for host in discovered_hosts:
            serialno_to_thumbprint[host.serial_no] = host.ssh_thumbprint
        return serialno_to_thumbprint

    def get_primary_node_serialno(self, discovered_hosts):
        primary_node = None
        for host in discovered_hosts:
            if host.is_primary:
                primary_node = host.serial_no
        if primary_node is None:
            self.utils.printRed("Primary node not found on which VxRail Manager would get discovered")
            self.utils.printRed("Please check on the nodes and VxRail Manager UI 192.168.10.200 is up")
            exit(1)
        return primary_node

    def to_hosts_spec_obj(self, fqdn, password, serial_no, ssh_thumbprint):
        return {
            "ipAddress": self.utils.nslookup_ip_from_dns(fqdn),
            "hostName": fqdn,
            "username": "root",
            "password": password,
            "sshThumbprint": ssh_thumbprint,
            "serialNumber": serial_no
        }


class HostDiscovery:
    def __init__(self, serial_no, ssh_thumbprint, physical_nics, is_primary):
        self.serial_no = serial_no
        self.ssh_thumbprint = ssh_thumbprint
        self.physical_nics = physical_nics
        self.is_primary = is_primary
