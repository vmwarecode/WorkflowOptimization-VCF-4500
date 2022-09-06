# Copyright 2021 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Fetch licenses and ask user to select

from utils.utils import Utils

__author__ = 'virtis'


class LicenseAutomator:
    def __init__(self, args):
        self.utils = Utils(args)
        self.description = "Select license"
        self.hostname = args[0]
        self.two_line_separator = ['', '']

    def main_func(self, vsan_storage):
        lcs = self.__get_licenses()
        print(*self.two_line_separator, sep='\n')
        selected = {}

        for k in lcs.keys():
            lcsls = lcs[k]
            if k in ['VSAN', 'NSX-T']:
                if not vsan_storage and k == "VSAN":
                    continue
                if len(lcsls) == 0:
                    self.utils.printRed("{} license not found. Please check/add the specific license".format(k))
                    exit(1)
                selected.update(self.input_license_info(lcsls, k))
            elif k == 'vSphere':
                select_option = input("\033[1m Do you want to apply vSphere license('yes' or 'no'): \033[0m")
                print(*self.two_line_separator, sep='\n')
                if select_option.lower() == 'yes' or select_option.lower() == 'y':
                    if len(lcsls) == 0:
                        self.utils.printRed("{} license not found. Please check/add the specific license".format(k))
                        exit(1)
                    self.utils.printYellow("** Please make sure license has enough CPU slots required for the cluster")
                    selected.update(self.input_license_info(lcsls, k))
        return selected

    def input_license_info(self, lcsls, licensekey):
        selected = {}
        self.utils.printCyan("Please choose a {} license:".format(licensekey))
        ct = 0
        lcsmap = {}
        for onelcs in lcsls:
            ct += 1
            self.utils.printBold("{}) {}".format(ct, self.__output_license_info(onelcs)))
            lcsmap[str(ct)] = onelcs
        selected[licensekey] = \
            lcsmap[self.__valid_option(input("\033[1m Enter your choice(number): \033[0m"), lcsmap.keys())]["key"]
        print(*self.two_line_separator, sep='\n')
        return selected

    def __output_license_info(self, licenseobj):
        return "{} ({})".format(licenseobj["key"], licenseobj["validity"])

    def __get_licenses(self):
        self.utils.printGreen("Getting license information...")
        url = 'https://' + self.hostname + '/v1/license-keys?productType=VSAN,NSXT,ESXI'
        response = self.utils.get_request(url)
        vsankeys = [{"key": ele["key"], "validity": ele["licenseKeyValidity"]["licenseKeyStatus"]} for ele in
                    response["elements"] if ele["productType"] == "VSAN"]
        nsxtkeys = [{"key": ele["key"], "validity": ele["licenseKeyValidity"]["licenseKeyStatus"]} for ele in
                    response["elements"] if ele["productType"] == "NSXT"]
        esxikeys = [{"key": ele["key"], "validity": ele["licenseKeyValidity"]["licenseKeyStatus"]} for ele in
                    response["elements"] if ele["productType"] == "ESXI"]
        return {"VSAN": vsankeys, "NSX-T": nsxtkeys, "vSphere": esxikeys}

    def __valid_option(self, inputstr, choices):
        choice = str(inputstr).strip().lower()
        if choice in choices:
            return choice
        self.utils.printYellow("**Use first choice by default")
        return list(choices)[0]
