# Copyright 2021 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Prepare Network Spec - DVS Specs (Single/Multi DVS)
import json

from utils.utils import Utils

__author__ = 'virtis'


class NetworkAutomator:
    def __init__(self, args):
        self.utils = Utils(args)
        self.hostname = args[0]
        self.two_line_separator = ['', '']

    def prepare_dvs_info(self, physical_nics, nic_profile, input_mgmt_pg_name=None, input_vsan_pg_name=None,
                         input_vmotion_pg_name=None, pg_types_to_vmnics=None, pg_type_to_active_uplinks=None,
                         cluster_name=None, vsan_storage=None):
        self.utils.printCyan("Select the DVS option to proceed:")
        self.utils.printBold("1) System DVS for Overlay")
        self.utils.printBold("2) Separate DVS for Overlay")
        dvs_selection = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", "1",
                                               self.utils.valid_option, ["1", "2"])
        print(*self.two_line_separator, sep='\n')
        self.utils.printCyan("Please enter DVS details:")
        # print()
        dvs_payload = None
        vmnics = None

        is_multisystem_vds = False
        if nic_profile == 'ADVANCED_VXRAIL_SUPPLIED_VDS':
            if len(pg_types_to_vmnics) > 1:
                is_multisystem_vds = True

        if dvs_selection == "1":
            if not is_multisystem_vds:
                system_dvs_name, mgmt_pg_name, vsan_pg_name, vmotion_pg_name, system_vm_pg_name, host_discovery_pg_name\
                    = self.input_single_dvs_info(input_mgmt_pg_name, input_vsan_pg_name, input_vmotion_pg_name, nic_profile, cluster_name, vsan_storage)
                dvs_payload = self.prepare_dvs_payload(system_dvs_name, mgmt_pg_name, vsan_pg_name, vmotion_pg_name,
                                                       nic_profile, pg_type_to_active_uplinks, system_vm_pg_name, host_discovery_pg_name)
            else:
                system_dvs_to_pgs, pg_names_to_transport_types, vds_to_usedbynsxt_flag = \
                    self.input_multisystem_dvs_info(dvs_selection, pg_types_to_vmnics, input_mgmt_pg_name,
                                                    input_vsan_pg_name, input_vmotion_pg_name, cluster_name, vsan_storage)
                dvs_payload = self.prepare_dvs_payload_for_advanced_profile_multisystem(system_dvs_to_pgs,
                                                                                        pg_names_to_transport_types,
                                                                                        vds_to_usedbynsxt_flag,
                                                                                        pg_type_to_active_uplinks)
        elif dvs_selection == "2":
            if not is_multisystem_vds:
                system_dvs_name, mgmt_pg_name, vsan_pg_name, vmotion_pg_name, system_vm_pg_name, host_discovery_pg_name \
                    = self.input_single_dvs_info(input_mgmt_pg_name, input_vsan_pg_name, input_vmotion_pg_name, nic_profile, cluster_name, vsan_storage)
            else:
                system_dvs_to_pgs, pg_names_to_transport_types, vds_to_usedbynsxt_flag = \
                    self.input_multisystem_dvs_info(dvs_selection, pg_types_to_vmnics, input_mgmt_pg_name,
                                                    input_vsan_pg_name, input_vmotion_pg_name, cluster_name, vsan_storage)
            nics_used_for_system_vds = None
            if nic_profile == 'TWO_HIGH_SPEED':
                nics_used_for_system_vds = ['vmnic0', 'vmnic1']
            elif nic_profile in ['FOUR_HIGH_SPEED', 'FOUR_EXTREME_SPEED']:
                nics_used_for_system_vds = ['vmnic0', 'vmnic1', 'vmnic2', 'vmnic3']
            elif nic_profile == 'ADVANCED_VXRAIL_SUPPLIED_VDS':
                nics_used_for_system_vds = []
                for item in pg_types_to_vmnics.values():
                    nics_used_for_system_vds.extend(list(set(item)))

            for nic in nics_used_for_system_vds:
                del physical_nics[nic]
            if not is_multisystem_vds:
                vds_portgroups_list = [system_dvs_name, mgmt_pg_name, vsan_pg_name, vmotion_pg_name]
                vmnics = self.input_overlay_dvs_info(physical_nics, set(vds_portgroups_list))
                dvs_payload = self.prepare_dvs_payload(system_dvs_name, mgmt_pg_name, vsan_pg_name, vmotion_pg_name,
                                                       nic_profile, pg_type_to_active_uplinks, system_vm_pg_name,
                                                       host_discovery_pg_name, vmnics)
            else:
                vds_portgroups_list = []
                for key, value in system_dvs_to_pgs.items():
                    vds_portgroups_list.append(key)
                    vds_portgroups_list.extend(value)
                vmnics = self.input_overlay_dvs_info(physical_nics, set(vds_portgroups_list))
                dvs_payload = self.prepare_dvs_payload_for_advanced_profile_multisystem(system_dvs_to_pgs,
                                                                                        pg_names_to_transport_types,
                                                                                        vds_to_usedbynsxt_flag,
                                                                                        pg_type_to_active_uplinks, vmnics)
        return dvs_payload, vmnics

    def prepare_dvs_payload(self, system_dvs_name, mgmt_pg_name, vsan_pg_name, vmotion_pg_name, nic_profile,
                            pg_type_to_active_uplinks, system_vm_pg_name, host_discovery_pg_name, vmnics=None):
        dvsSpecs = []
        if nic_profile == 'ADVANCED_VXRAIL_SUPPLIED_VDS':
            if pg_type_to_active_uplinks is not None:
                portgroups = [self.to_portgroup_obj_advanced(mgmt_pg_name, "MANAGEMENT", pg_type_to_active_uplinks["MANAGEMENT"]),
                              self.to_portgroup_obj_advanced(vmotion_pg_name, "VMOTION", pg_type_to_active_uplinks["VMOTION"]),
                              self.to_portgroup_obj_advanced(host_discovery_pg_name, "HOSTDISCOVERY", pg_type_to_active_uplinks["VXRAILDISCOVERY"]),
                              self.to_portgroup_obj_advanced(system_vm_pg_name, "SYSTEMVM", pg_type_to_active_uplinks["VXRAILSYSTEMVM"])]
                if vsan_pg_name is not None:
                    portgroups.append(self.to_portgroup_obj_advanced(vsan_pg_name, "VSAN", pg_type_to_active_uplinks["VSAN"]))
            else:
                # Perth bits
                portgroups = [self.to_portgroup_obj(mgmt_pg_name, "MANAGEMENT"),
                              self.to_portgroup_obj(vmotion_pg_name, "VMOTION"),
                              self.to_portgroup_obj(host_discovery_pg_name, "HOSTDISCOVERY"),
                              self.to_portgroup_obj(system_vm_pg_name, "SYSTEMVM")]
                if vsan_pg_name is not None:
                    portgroups.append(self.to_portgroup_obj(vsan_pg_name, "VSAN"))
        else:
            portgroups = [self.to_portgroup_obj(mgmt_pg_name, "MANAGEMENT"),
                          self.to_portgroup_obj(vmotion_pg_name, "VMOTION")]
            if vsan_pg_name is not None:
                portgroups.append(self.to_portgroup_obj(vsan_pg_name, "VSAN"))
        dvsSpecs.append(self.to_system_dvs_obj(system_dvs_name, portgroups, False if vmnics is not None else True))

        if vmnics:
            overlay_dvs_spec = {
                "isUsedByNsxt": True,
                "name": vmnics[0]['vdsName']
            }
            dvsSpecs.append(overlay_dvs_spec)
        return dvsSpecs

    def prepare_dvs_payload_for_advanced_profile_multisystem(self, system_dvs_to_pgs, pg_names_to_transport_types,
                                                             vds_to_usedbynsxt_flag, pg_type_to_active_uplinks, vmnics=None):
        dvsSpecs = []
        for (key, value) in system_dvs_to_pgs.items():
            portgroups = []
            for pg in value:
                type = pg_names_to_transport_types[pg]
                if type == 'VXRAILSYSTEMVM':
                    type = 'SYSTEMVM'
                elif type == 'VXRAILDISCOVERY':
                    type = 'HOSTDISCOVERY'
                if pg_type_to_active_uplinks is None:
                    # Perth bits
                    portgroups.append(self.to_portgroup_obj(pg, type))
                else:
                    activeUplinks = pg_type_to_active_uplinks[pg_names_to_transport_types[pg]]
                    portgroups.append(self.to_portgroup_obj_advanced(pg, type, activeUplinks))

            dvsSpecs.append(self.to_system_dvs_obj(key, portgroups,
                                                   False if vmnics is not None else vds_to_usedbynsxt_flag[key]))
        if vmnics:
            overlay_dvs_spec = {
                "isUsedByNsxt": True,
                "name": vmnics[0]['vdsName']
            }
            dvsSpecs.append(overlay_dvs_spec)
        return dvsSpecs

    def to_system_dvs_obj(self, system_dvs_name, portgroups, isUsedByNsxt):
        return {
            "name": system_dvs_name,
            "isUsedByNsxt": isUsedByNsxt,
            "portGroupSpecs": portgroups
        }

    def to_portgroup_obj(self, pg_name, pg_type):
        return {
            "name": pg_name,
            "transportType": pg_type
        }

    def to_portgroup_obj_advanced(self, pg_name, pg_type, activeUplinks):
        return {
            "name": pg_name,
            "transportType": pg_type,
            "activeUplinks": activeUplinks
        }

    def input_single_dvs_info(self, input_mgmt_pg_name=None, input_vsan_pg_name=None, input_vmotion_pg_name=None,
                              nic_profile=None, cluster_name=None, vsan_storage=None):
        while True:
            print()
            system_dvs_name = self.utils.valid_input("\033[1m Enter System DVS name: \033[0m",
                                                     None, self.utils.valid_resource_name)
            if input_mgmt_pg_name is None:
                print()
                mgmt_pg_name = self.input_pg_name_and_check_prefix("MANAGEMENT", "Management Network")
            else:
                mgmt_pg_name = input_mgmt_pg_name

            # if vsan storage then only ask for vsan network details
            vsan_pg_name = None
            if vsan_storage:
                vsan_pg_name = self.utils.valid_input("\033[1m Enter portgroup name for type {}: \033[0m".format("VSAN"),
                                                      None, self.utils.valid_resource_name) \
                    if input_vsan_pg_name is None else input_vsan_pg_name

            vmotion_pg_name = self.utils.valid_input("\033[1m Enter portgroup name for type {}: \033[0m".format("VMOTION"),
                                                     None, self.utils.valid_resource_name) \
                if input_vmotion_pg_name is None else input_vmotion_pg_name

            vds_portgroups_list = [system_dvs_name, mgmt_pg_name, vmotion_pg_name]
            if vsan_storage:
                vds_portgroups_list.append(vsan_pg_name)

            system_vm_pg_name = host_discovery_pg_name = None
            if nic_profile == 'ADVANCED_VXRAIL_SUPPLIED_VDS':
                system_vm_pg_name = "vCenter Server Network-" + cluster_name
                host_discovery_pg_name = "VxRail Management-" + cluster_name
                vds_portgroups_list.extend([system_vm_pg_name, host_discovery_pg_name])

            vds_portgroups_set = set(vds_portgroups_list)
            if len(vds_portgroups_list) != len(vds_portgroups_set):
                print()
                duplicates = [x for n, x in enumerate(vds_portgroups_list) if x in vds_portgroups_list[:n]]
                self.utils.printRed("Input DVS and Portgroup names have duplicates {}. Please re-enter DVS details"
                                    .format(duplicates))
            else:
                break
        return system_dvs_name, mgmt_pg_name, vsan_pg_name, vmotion_pg_name, system_vm_pg_name, host_discovery_pg_name

    def input_pg_name_and_check_prefix(self, pg_type, prefix):
        while True:
            pg_name = self.utils.valid_input("\033[1m Enter portgroup name for type {}: \033[0m".format(pg_type),
                                             None, self.utils.valid_resource_name)
            if pg_name.startswith(prefix):
                break
            else:
                self.utils.printRed("{} type PG name should start with prefix '{}'".format(pg_type, prefix))
        return pg_name

    def input_multisystem_dvs_info(self, dvs_selection, pg_types_to_vmnics, input_mgmt_pg_name=None,
                                   input_vsan_pg_name=None, input_vmotion_pg_name=None, cluster_name=None, vsan_storage=None):
        while True:
            system_dvs_to_pgs = {}
            pg_names_to_transport_types = {}
            index = 1
            for pg_types in pg_types_to_vmnics.keys():
                pg_types_list = json.loads(pg_types)
                print()
                system_dvs_name = self.utils.valid_input(
                    "\033[1m Enter DVS name for System DVS {}: \033[0m".format(index),
                    None, self.utils.valid_resource_name)
                index = index + 1
                print()
                portgroups = []
                for pg_type in pg_types_list:
                    if pg_type == 'MANAGEMENT':
                        mgmt_pg_name = self.input_pg_name_and_check_prefix("MANAGEMENT", "Management Network") \
                            if input_mgmt_pg_name is None else input_mgmt_pg_name
                        portgroups.append(mgmt_pg_name)
                        pg_names_to_transport_types[mgmt_pg_name] = pg_type
                    else:
                        if pg_type == 'VSAN' and vsan_storage:
                            vsan_pg_name = self.utils.valid_input("\033[1m Enter portgroup name for type {}: \033[0m".format("VSAN"),
                                                                  None, self.utils.valid_resource_name) \
                                if input_vsan_pg_name is None else input_vsan_pg_name
                            portgroups.append(vsan_pg_name)
                            pg_names_to_transport_types[vsan_pg_name] = pg_type
                        elif pg_type == 'VMOTION':
                            vmotion_pg_name = self.utils.valid_input("\033[1m Enter portgroup name for type {}: \033[0m".format("VMOTION"),
                                                                     None, self.utils.valid_resource_name) \
                                if input_vmotion_pg_name is None else input_vmotion_pg_name
                            portgroups.append(vmotion_pg_name)
                            pg_names_to_transport_types[vmotion_pg_name] = pg_type
                        elif pg_type == 'VXRAILSYSTEMVM':
                            system_vm_pg_name = "vCenter Server Network-" + cluster_name
                            portgroups.append(system_vm_pg_name)
                            pg_names_to_transport_types[system_vm_pg_name] = pg_type
                        elif pg_type == 'VXRAILDISCOVERY':
                            host_discovery_pg_name = "VxRail Management-" + cluster_name
                            portgroups.append(host_discovery_pg_name)
                            pg_names_to_transport_types[host_discovery_pg_name] = pg_type
                system_dvs_to_pgs[system_dvs_name] = portgroups

            if len(system_dvs_to_pgs) != 2:
                print()
                self.utils.printRed("Duplicate names for input System DVS found. Please re-enter System DVS details")
            else:
                vds_portgroups_list = []
                for key, value in system_dvs_to_pgs.items():
                    vds_portgroups_list.append(key)
                    vds_portgroups_list.extend(value)
                vds_portgroups_set = set(vds_portgroups_list)
                if len(vds_portgroups_list) != len(vds_portgroups_set):
                    print()
                    duplicates = [x for n, x in enumerate(vds_portgroups_list) if x in vds_portgroups_list[:n]]
                    self.utils.printRed("Input DVS and Portgroup names have duplicates {}. Please re-enter DVS details"
                                        .format(duplicates))
                else:
                    break

        vds_to_usedbynsxt_flag = {}
        if dvs_selection == '1':
            print(*self.two_line_separator, sep='\n')
            self.utils.printCyan("Please choose one of the system dvs for overlay:")
            for i, (key, value) in enumerate(system_dvs_to_pgs.items()):
                self.utils.printBold("{}) {}".format(i + 1, key))
            input_selection = self.utils.valid_input("\033[1m Enter your choice(number): \033[0m", None,
                                                     self.utils.valid_option, ["1", "2"])
            input_selection_for_overlay_vds = list(system_dvs_to_pgs.keys())[int(input_selection) - 1]
            for i, (key, value) in enumerate(system_dvs_to_pgs.items()):
                if key == input_selection_for_overlay_vds:
                    vds_to_usedbynsxt_flag[key] = True
                else:
                    vds_to_usedbynsxt_flag[key] = False
        return system_dvs_to_pgs, pg_names_to_transport_types, vds_to_usedbynsxt_flag

    def input_overlay_dvs_info(self, physical_nics, vds_portgroups_set):
        while True:
            print()
            overlay_dvs_name = self.utils.valid_input("\033[1m Enter Overlay DVS name: \033[0m", None,
                                                      self.utils.valid_resource_name)

            if overlay_dvs_name in vds_portgroups_set:
                print()
                self.utils.printRed("Input Overlay DVS name is already given as part of System DVS/PGs. "
                                    "Please re-enter Overlay DVS details")
            else:
                break

        print(*self.two_line_separator, sep='\n')
        if not physical_nics:
            self.utils.printRed("Nodes does not have vmnics to choose for overlay. Please check on nodes.")
            exit(1)

        self.utils.printCyan("Please choose the nics for overlay traffic:")
        self.utils.printBold("-----id-----speed-----")
        self.utils.printBold("----------------------")
        for i, (key, value) in enumerate(physical_nics.items()):
            self.utils.printBold("{}) {} - {}"
                                 .format(i + 1, key, value))

        is_correct_vmnic_selection = True
        vmnics = []
        while is_correct_vmnic_selection:
            try:
                vmnic_options = list(map(int, input(
                    "\033[1m Enter your choices(minimum 2 numbers comma separated): \033[0m").strip().rstrip(",")
                                         .split(',')))
                while len(vmnic_options) < 2:
                    self.utils.printRed("Minimum of 2 vmnics required. Select minimum 2 vmnics")
                    vmnic_options = list(map(int, input(
                        "\033[1m Enter your choices(minimum 2 numbers comma separated): \033[0m").strip().rstrip(",")
                                             .split(',')))
                vmnics_down = []
                for index, elem in enumerate(vmnic_options):
                    key = list(physical_nics.keys())[elem - 1]
                    if physical_nics[key] == 0:
                        vmnics_down.append(key)
                if len(vmnics_down) > 0:
                    self.utils.printRed("vmnics {} are down. Please select other vmnics".format(vmnics_down))
                    is_correct_vmnic_selection = True
                else:
                    for index, elem in enumerate(vmnic_options):
                        vmnic_info = {'id': list(physical_nics.keys())[elem - 1],
                                      'vdsName': overlay_dvs_name}
                        vmnics.append(vmnic_info)
                        is_correct_vmnic_selection = False
            except:
                print(*self.two_line_separator, sep='\n')
                self.utils.printRed("Input a number between 1(included) and {}(included)"
                                    .format(str(len(physical_nics.items()))))
                is_correct_vmnic_selection = True
        return vmnics
