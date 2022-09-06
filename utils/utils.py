# Copyright 2021 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Common utility methods

import collections
import json
import subprocess
import time
import requests
import urllib3
import getpass
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MASKED_KEYS = ['password', 'nsxManagerAdminPassword', 'rootPassword', 'ssoDomainPassword']
PROCESSING = 102

__author__ = 'virtis'


class Utils:
    def __init__(self, args):
        self.hostname = args[0]
        self.username = args[1]
        self.password = args[2]
        self.header = {'Content-Type': 'application/json'}
        self.token_url = 'https://' + self.hostname + '/v1/tokens'

    def get_token(self):
        payload = {"username": self.username, "password": self.password}
        response = self.post_request(payload=payload, url=self.token_url)
        token = response['accessToken']
        self.header['Authorization'] = 'Bearer ' + token

    def get_request(self, url):
        self.get_token()
        time.sleep(5)
        response = requests.get(url, headers=self.header, verify=False)
        if response.status_code == 200 or response.status_code == 202:
            data = json.loads(response.text)
        else:
            print("Error reaching the server.")
            exit(1)
        return data

    def post_request(self, payload, url):
        response = requests.post(url, headers=self.header, json=payload, verify=False)
        if response.status_code == 200 or response.status_code == 202:
            data = json.loads(response.text)
            return data
        else:
            print("Error reaching the server.")
            print(response.text)
            exit(1)

    def post_request_for_host_discovery(self, payload, url):
        self.get_token()
        response = requests.post(url, headers=self.header, json=payload, verify=False)
        if response.status_code in [200, 202]:
            return response
        else:
            failure_response = json.loads(response.text)
            self.printRed("Host discovery post api failed")
            if "errorCode" in failure_response:
                self.printRed("Errorcode: {}".format(failure_response["errorCode"]))
            if "message" in failure_response:
                self.printRed("Message: {}".format(failure_response["message"]))
            if "arguments" in failure_response and len(failure_response["arguments"]) > 0:
                self.printRed("Arguments: {}".format(failure_response["arguments"]))
            exit(1)

    def patch_request(self, payload, url):
        response = requests.patch(url, headers=self.header, json=payload, verify=False)
        if response.status_code == 202:
            data = json.loads(response.text)
            return data
        elif response.status_code == 200:
            return
        else:
            print("Error reaching the server from patch.")
            print(response.text)
            exit(1)

    def poll_on_id(self, url):
        key = 'executionStatus'
        response = self.get_request(url)
        status = response[key]
        while status in ['In Progress', 'IN_PROGRESS', 'Pending']:
            time.sleep(10)
            response = self.get_request(url)
            status = response[key]
        if status == 'COMPLETED':
            return response['resultStatus']
        else:
            self.printRed('Operation failed')
            exit(1)

    def poll_on_queries_for_host_discovery(self, url):
        response = self.get_request_for_host_discovery(url)
        status = response['queryInfo']['status']
        while status in ['In Progress', 'IN_PROGRESS', 'Pending']:
            response = self.get_request_for_host_discovery(url)
            status = response['queryInfo']['status']
            time.sleep(10)
        if status == 'COMPLETED':
            return response['result']
        else:
            self.print_errors(response)
            exit(1)

    def get_request_for_host_discovery(self, url):
        self.get_token()
        time.sleep(5)
        response = requests.get(url, headers=self.header, verify=False)
        while response.status_code == PROCESSING:
            time.sleep(5)
            response = requests.get(url, headers=self.header, verify=False)
        data = json.loads(response.text)
        return data

    def print_errors(self, response):
        if response['queryInfo']['status'] == 'FAILED':
            self.printRed("Host discovery get api failed")
            if "errorResponse" in response['queryInfo']:
                if "message" in response['queryInfo']['errorResponse']:
                    self.printRed("Errors: {}".format(response['queryInfo']['errorResponse']['message']))
                    if "remediationMessage" in response['queryInfo']['errorResponse']:
                        self.printRed("Remediation Message: {}".format(
                            response['queryInfo']['errorResponse']['remediationMessage']))
                    # VxRail API /rest/vxm/v1/system/initialize/nodes not there for <7.0.200 versions but API
                    # returning 200 status code and response coming as html for lower versions.So we need to handle this
                    if "Failed to de-serialize host discovery API response for VxRail Manager" in \
                            response['queryInfo']['errorResponse']['message']:
                        self.printRed("Please make sure VxRail version in imaged nodes are >= 7.0.200")

    def read_input(self, file):
        with open(file) as json_file:
            data = json.load(json_file)
        return data

    def print_validation_errors(self, url):
        validation_response = self.get_request(url)
        if "validationChecks" in validation_response:
            failed_tasks = list(
                filter(lambda x: x["resultStatus"] == "FAILED", validation_response["validationChecks"]))
            for failed_task in failed_tasks:
                self.printRed(failed_task['description'] + ' ' + 'failed')
                if "errorResponse" in failed_task and "message" in failed_task["errorResponse"]:
                    self.printRed(failed_task["errorResponse"]["message"])
                if "nestedValidationChecks" in failed_task:
                    for nested_task in failed_task["nestedValidationChecks"]:
                        if "errorResponse" in nested_task and "message" in nested_task["errorResponse"]:
                            self.printRed(nested_task["errorResponse"]["message"])

    def password_check(self, pwd, cannotbe=None):
        # rule: minlen = 8, maxlen = 32, at least 1 number, 1 upper, 1 lower, 1 special char
        minlen = 8
        maxlen = 32
        hasnum = True
        hasupper = True
        haslower = True
        hasspecial = True

        res = True

        if cannotbe is not None and pwd == cannotbe:
            self.print_error("Password cannot be same as you have inputed")
            return False

        if len(pwd) < minlen:
            self.print_error("Length should be at least {}".format(minlen))
            res = False
        elif len(pwd) > maxlen:
            self.print_error("Length should be less than {}".format(maxlen))
            res = False

        if hasnum and not any(c.isdigit() for c in pwd):
            self.print_error("Password should have at least one number")
            res = False
        if hasupper and not any(c.isupper() for c in pwd):
            self.print_error("Password should have at least one upper case letter")
            res = False
        if haslower and not any(c.islower() for c in pwd):
            self.print_error("Password should have at least one lower case letter")
            res = False

        if hasspecial and len(re.compile('[0-9 a-z A-Z]').sub('', pwd)) == 0:
            self.print_error("Password should contain at least one special character")
            res = False

        return res

    def print_error(self, msg):
        RED = '\033[1;31m'
        TAIL = '\033[0m'
        head = RED + "Error:" + TAIL
        print("{}{}".format(head, msg))

    def maskPasswords(self, obj):
        for k, v in obj.items():
            if isinstance(v, collections.abc.Mapping):
                obj[k] = self.maskPasswords(v)
            elif isinstance(v, list):
                for elem in v:
                    if isinstance(elem, dict) or isinstance(elem, list):
                        self.maskPasswords(elem)
            elif k in MASKED_KEYS:
                obj[k] = '*******'
            else:
                obj[k] = v
        return obj

    def valid_input(self, inputinfo, defaultvalue=None, validfunc=None, ext_args=None, is_password=False):
        while True:
            if is_password:
                inputstr = getpass.getpass(inputinfo)
            else:
                inputstr = input(inputinfo)
            if len(str(inputstr).strip()) == 0 and defaultvalue is not None:
                return defaultvalue
            if validfunc is not None:
                checkresult = validfunc(inputstr) if ext_args is None else validfunc(inputstr, ext_args)
                if checkresult:
                    return inputstr
                else:
                    self.printRed('Unable to validate the input')
            else:
                break
        return inputstr

    def valid_option(self, inputstr, choices):
        choice = str(inputstr).strip().lower()
        if choice in choices:
            return choice
        else:
            return
        # self.utils.printYellow("**Use first choice by default")
        # return list(choices)[0]

    def valid_vlan(self, inputstr):
        res = True
        if not str(inputstr).isdigit():
            self.printRed("VLAN id must be an integer value")
            res = False
        if res:
            if not (0 <= int(inputstr) <= 4096):
                self.printRed("VLAN must be a number in between 0-4096")
                res = False
        return res

    def valid_domain_name(self, inputstr):
        res = True
        if not inputstr:
            self.printRed("Domain name is Blank/Empty")
            res = False
        else:
            if not (3 <= len(inputstr) <= 20):
                self.printRed("Size of domain name should be between 3-20 characters")
                res = False
            if " " in inputstr:
                self.printRed("Domain name should not contain space")
                res = False
        return res

    def valid_resource_name(self, inputstr):
        res = True
        if not inputstr:
            self.printRed("Provided name is Blank/Empty")
            res = False
        else:
            if len(inputstr) > 80:
                self.printRed("Provided name size should not be more than 80")
                res = False
        return res

    def valid_fqdn(self, inputstr):
        res = True
        if len(inputstr) <= 3 or len(inputstr) > 255:
            res = False
        elif "." not in inputstr:
            res = False
        elif inputstr[0] == "." or inputstr[-1] == ".":
            res = False
        else:
            segmatch = re.compile("[0-9 a-z A-Z _ -]")
            res = all((len(segmatch.sub('', oneseg)) == 0 and len(oneseg) > 0) for oneseg in inputstr.split("."))
        if not res:
            self.printRed("FQDN format is not correct")
        else:
            self.printGreen("Resolving IP from DNS...")
            theip = self.nslookup_ip_from_dns(inputstr)
            if theip is not None:
                self.printGreen("Resolved IP address: {}".format(theip))
            else:
                res = False
                self.printRed("Hasn't found matched IP from DNS")

        return res

    def nslookup_ip_from_dns(self, fqdn):
        cmd = "nslookup {}".format(fqdn)
        sub_popen = subprocess.Popen(cmd,
                                     shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        output, err = sub_popen.communicate()
        if sub_popen.returncode > 0:
            return None

        thenext = False
        # byte feature only supported in python 3
        for aline in output.decode('utf8').split("\n"):
            if thenext and str(aline).lower().startswith("address:"):
                return aline.split(":")[-1].strip()
            if str(aline).lower().startswith("name:"):
                tail = aline.split(":")[-1].strip()
                if tail == fqdn:
                    thenext = True
        return None

    def valid_ip(self, inputstr):
        res = re.compile("(\d+\.\d+\.\d+\.\d+)$").match(inputstr) is not None and all(
            (0 <= int(seg) <= 255) for seg in inputstr.split("."))
        if not res:
            self.printRed("IP format is not correct")
        return res

    def valid_cidr(self, inputstr):
        pattern = r'(\d+\.\d+\.\d+\.\d+)\/([0-9]|[1-2][0-9]|3[0-2])$'
        res = re.match(pattern, inputstr) is not None and all((0 <= int(seg) <= 255)
                                                              for seg in
                                                              re.search(pattern, inputstr).group(1).split("."))
        if not res:
            self.printRed("CIDR format is not correct")
        return res

    # IP Ranges will be in form of eg.10.0.0.1-10.0.0.10, 10.0.0.20-10.0.0.30
    def valid_ip_ranges(self, inputstr):
        ip_ranges: List[Any] = [x.strip() for x in inputstr.split(',')]
        for ip_range in ip_ranges:
            try:
                start_ip, end_ip = ip_range.split('-')
            except ValueError:
                self.printRed("IP Range format is not correct")
                return None
            res = self.valid_ip(start_ip) and self.valid_ip(end_ip)
            if not res:
                return res
        return True

    # Password must contain no more than 20 charaters
    # Password should contain at least one lowercase character.
    # Password should contain at least one digit.
    # Password must contain at least 8 characters.
    # Password must not contain any spaces
    # Password should contain at least one special character.
    # Password should contain at least one uppercase character.
    def valid_vcenter_password(self, password):
        res = True
        if not password:
            self.printRed("Password should not be empty")
            res = False
        else:
            reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])(?!.*[\s]).{8,20}$"
            match_re = re.compile(reg)
            result = re.search(match_re, password)
            if not result:
                res = False
                self.printRed("Invalid Password")
                self.printRed("Make sure Password should be 8 to 20 characters long, it should contain atleast one "
                              "lowercase, one uppercase, one digit and one special characters and does not contain any "
                              "spaces")
        return res

    def handle_password_input(self, input=None):
        while True:
            if input:
                pwd = getpass.getpass("\033[1m {} \033[0m".format(input))
            else:
                pwd = getpass.getpass("\033[1m Enter root password: \033[0m")
            confirm_pwd = getpass.getpass("\033[1m Confirm password: \033[0m")
            if pwd != confirm_pwd:
                self.printRed("Passwords don't match")
            elif len(pwd.strip()) == 0:
                self.printRed("Password is empty/blank")
            else:
                break
        return pwd

    def printRed(self, message):
        print("\033[91m {}\033[00m".format(message))

    def printGreen(self, message):
        print("\033[92m {}\033[00m".format(message))

    def printYellow(self, message):
        print("\033[93m {}\033[00m".format(message))

    def printCyan(self, message):
        print("\033[96m {}\033[00m".format(message))

    def printBold(self, message):
        print("\033[95m {}\033[00m".format(message))
