#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on create and delete wireless network profile details 
in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["A Mohamed Rafeek, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: network_wireless_profile_workflow_manager
short_description: Resource module for managing network wireless profile in Cisco Catalyst Center
description: This module allows to create/delete the wireless profile in Cisco Catalyst Center.
    - It supports creating and deleting wireless profile.
    - This module interacts with Cisco Catalyst Center's to create profile name, SSID details,
      additinal interface details destination port and protcol.
    version_added: '6.31.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - A Mohamed Rafeek (@mabdulk2)
  - Madhan Sankaranarayanan (@madhansansel)

options:
  config_verify:
    description: |
      Set to `True` to enable configuration verification on Cisco Catalyst Center
      after applying the playbook config. This will ensure that the system validates
      the configuration state after the change is applied.
    type: bool
    default: False
  offset_limit:
    description: |
      Set the offset limit based on the API data limit for each pagination.
    type: int
    default: 500
  state:
    description: |
      Specifies the desired state for the configuration. If `merged`, the module
      will create or update the configuration, adding new settings or modifying existing
      ones. If `deleted`, it will remove the specified settings.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: A list containing the details for network wireless profile creation.
    type: list
    elements: dict
    required: true
    suboptions:
      profile_name:
        description: Name the wireless profile needs to be created.
        type: str
        required: true
      site_names:
        description: |
          Site name contains assign the site to profile. For example, ["Global/USA/New York/BLDNYC"].
        type: list
        elements: str
        required: false
      ssid_details:
        description: |
            Contains ssid details to update for the wireless network profile.
        type: list
        elements: dict
        required: false
        suboptions:
          ssid:
            description: SSID name of the wireless device name.
            type: str
            required: true
          dot11be_profile_name:
            description: This profile name contains 802.11be profile name which update for this SSID.
            type: str
            required: true
          enable_fabric:
            description: Boolean value to enable fabric device SSID.
            type: bool
            required: false
          vlan_group_name:
            description: Incase SSID configure under the VLAN group then name of vlan group.
            type: str
            required: false
          interface_name:
            description: Incase SSID configure under the Interface then name of interface.
            type: str
            required: false
          anchor_group_name:
            description: Incase need to anchor to SSID then update the anchor group name.
            type: str
            required: false
          local_to_vlan:
            description: vlan id should be numeric between 1 to 4094.
            type: int
            required: false
      ap_zones:
        description: |
            Contains AP zones need to be updated for wireless network profile.
        type: dict
        required: false
        suboptions:
          ap_zone_name:
            description: AP zone Name create for the the wireless device profile.
            type: str
            required: true
          device_tags:
            description: |
                A list of tag needs to be attached for the AP zone.
            type: list
                elements: str
                required: false
          rf_profile_name:
            description: |
                Specifies the Radio Frequency (RF) profile name for the wireless device.
                It can be one of the standard profiles "HIGH", "LOW", "TYPICAL",
                or a custom profile that has been created. For example, "HIGH".
            type: str
            required: false
      onboarding_templates:
        description: Onboarding list of template to be added to this profile.
        type: str
        required: false
      day_n_template:
        description: day n template list of template to be added to this profile.
        type: str
        required: false
      additional_interfaces:
        description: |
          Add one or more additional interfacess added for this wireless profile.
          new interface name and vlan id will be created if not exist.
        type: list
        required: false
        suboptions:
        - interface_name:
            description: Interface name for the additional interface .
            type: str
            required: true
          vlan_id:
            description: |
              vlan id should be numeric between 1 to 4094. This field required
              when the Vlan interface and ID not available.
            type: int
            required: true

requirements:
- dnacentersdk >= 2.9.3
- python >= 3.9
notes:
 - SDK Method used are
    wireless.create_wireless_profile ,
    wireless.update_application_policy,
    wireless.get_wireless_profile,
    site_design.assign_sites,
    wireless.get_interfaces_v1
    wireless.create_interface_v1

 - Paths used are
    GET dna/intent/api/v1/wirelessProfiles
    POST dna/intent/api/v1/wirelessProfiles/{
    GET /dna/intent/api/v1/app-policy-intent
    DELETE /dna/intent/api/v1/app-policy-intent
    GET /dna/intent/api/v1/wirelessSettings/interfaces
    POST /dna/intent/api/v1/wirelessSettings/interfaces
"""

EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: no
  connection: local
  tasks:
    - name: Create network profile for wireless
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        offset_limit: 500
        state: merged
        config:
          - profile_name: "test_wireless_1"
            site_names:
              - "Global/Chennai/LTTS/FLOOR2"
            ssid_details:
              - ssid: guest_ssid_1
                enable_fabric: false
                wlan_profile_name: guest_ssid_1_profile
                policy_profile_name: guest_ssid_1_profile
                vlan_group_name: "test_vlan_group_1"
              - ssid: open1-iac
                enable_fabric: false
                wlan_profile_name: open1-iac_profile
                policy_profile_name: open1-iac_profile
                interface_name: "management"
                local_to_vlan: 2001
            ap_zones:
              - ap_zone_name: APZone2
                rf_profile_name: "LOW"
                ssids:
                  - "guest_ssid_1"
            additional_interfaces:
              - interface_name: "test_interface_1"
                vlan_id: 20
              - interface_name: "test_interface_5"
                vlan_id: 22
            onboarding_templates:
              - "test_template"
            day_n_templates:
              - "WLC Template"

"""

RETURN = r"""

#Case 1: Successful creation/updatation of wireless profile
Response: Create
{
    "msg": "Wireless Profile created/updated successfully for '[{'profile_name': 'APISample3', 'status': 'Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] Successfully created'}]'.",
    "response": [
        {
            "profile_name": "APISample3",
            "status": "Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] created Successfully"
        }
    ],
    "status": "success"
}

#Case 2: Successfully deletion of wireless profile
Response: Delete
{
    "msg": "Wireless Profile deleted successfully for '[{'profile_name': 'APISample3', 'status': 'Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] Successfully Deleted'}]'.",
    "response": [
        {
            "profile_name": "APISample3",
            "status": "Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] Successfully Deleted"
        }
    ],
    "status": "success"
}
"""

import re
import requests
import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    validate_list_of_dicts,
    validate_str
)
from ansible_collections.cisco.dnac.plugins.module_utils.network_profiles import (
    NetworkProfileFunctions
)

class NetworkWirelessProfile(NetworkProfileFunctions):
    """Class containing member attributes for network profile workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.created, self.deleted, self.not_processed = [], [], []

        self.keymap = dict(
            profile_name = "wirelessProfileName",
            rf_profile_name = "rfProfileName",
            sites = "sites",
            ssid = "ssidName",
            wlan_profile_name = "wlanProfileName",
            dot11be_profile_name = "dot11beProfileId",
            vlan_group_name = "vlanGroupName",
            enable_fabric = "enableFabric",
            interface_name = "interfaceName",
            local_to_vlan = "localToVlan",
            anchor_group_name = "anchorGroupName",
            policy_profile_name = "policyProfileName",
            ap_zone_name = "apZoneName"
        )

        host_name = self.params["dnac_host"]
        self.dnac_url = "https://{0}".format(str(host_name))
        self.token_str = self.dnac.api.access_token
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Auth-Token": str(self.token_str)
        }

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config: If successful, validated version of 'config' parameter.
        """
        temp_spec = {
            'profile_name': {'type': 'str', 'required': True},
            'site_names': {'type': 'list', 'elements': 'str', 'required': False},
            'ssid_details': {
                'type': 'list',
                'elements': 'dict',
                'ssid': {'type': 'str', 'required': False},
                'dot11be_profile_name': {'type': 'str', 'required': False},
                'enable_fabric': {'type': 'bool', 'default': False},
                'vlan_group_name': {'type': 'str', 'required': False},
                'interface_name': {'type': 'str', 'required': False},
                'anchor_group_name': {'type': 'str', 'required': False},
                'local_to_vlan': {'type': 'int', 'range_min': 1, 'range_max': 4094, 'required': False}
            },
            'ap_zones': {
                'type': 'list',
                'elements': 'dict',
                'ap_zone_name': {'type': 'str', 'required': False},
                'rf_profile_name': {'type': 'str', 'required': False},
                'device_tags': {'type': 'list', 'elements': 'str', 'required': False},
                'ssids': {'type': 'list', 'elements': 'str', 'required': False},
            },
            'onboarding_templates': {'type': 'list', 'elements': 'str', 'required': False},
            'day_n_templates': {'type': 'list', 'elements': 'str', 'required': False},
            'additional_interfaces': {
                'type': 'list',
                'elements': 'dict',
                'interface_name': {'type': 'str', 'required': True},
                'vlan_id': {'type': 'int', 'range_min': 1, 'range_max': 4094, 'required': True}
            }
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Validate configuration against the specification
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params)
            self.result['response'] = self.msg
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using " +\
            "'validate_input': {0}".format(str(valid_temp))
        self.log(self.msg, "INFO")

        return self

    def input_data_validation(self, config):
        """
        Additional validation to check if the provided input wireless profile is correct
        and as per the UI Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing the wirelss profile details.

        Returns:
            list: List of invalid profile data with details.

        Description:
            Iterates through available profile details and Returns the list of invalid
            data for further action or validation.
        """
        errormsg = []

        profile_name = config.get("profile_name")
        if profile_name:
            param_spec = dict(type="str")
            validate_str(profile_name, param_spec, "profile_name", errormsg)
        else:
            errormsg.append("profile_name: Profile Name is missing in playbook.")

        if self.payload.get("state") == "deleted":
            return self

        site_names = config.get("site_names")
        if site_names and len(site_names) > 0:
            for sites in site_names:
                param_spec = dict(type="str")
                validate_str(sites, param_spec, "sites", errormsg)

        ssid_list = config.get("ssid_details")
        if ssid_list and len(ssid_list) > 0:
            self.validate_ssid_info(ssid_list, config, errormsg)

        onboarding_templates = config.get("onboarding_templates")
        if onboarding_templates and len(onboarding_templates) > 0:
            for template in onboarding_templates:
                param_spec = dict(type="str")
                validate_str(template, param_spec, "template", errormsg)

        day_n_template = config.get("day_n_templates")
        if day_n_template and len(day_n_template) > 0:
            for ntemplate in day_n_template:
                param_spec = dict(type="str")
                validate_str(ntemplate, param_spec, "ntemplate", errormsg)

        additional_interfaces = config.get("additional_interfaces")
        if additional_interfaces and len(additional_interfaces) > 0:
            for interface in additional_interfaces:
                interface_name = interface.get("interface_name")
                if interface_name:
                    param_spec = dict(type="str", length_max=31)
                    validate_str(interface_name, param_spec, "interface_name", errormsg)
                else:
                    errormsg.append("interface_name: additional_interfaces of Interface Name is missing in playbook.")

                vlan_id = interface.get("vlan_id")
                if vlan_id:
                    if vlan_id not in range(1, 4094):
                        errormsg.append("vlan_id: Invalid Additional Interfaces VLAN ID '{0}' in playbook."
                                        .format(vlan_id))
                else:
                    errormsg.append("vlan_id: VLAN ID of Interface is missing in playbook.")

        if len(errormsg) > 0:
            self.msg = "Invalid parameters in playbook config: '{0}' ".format(errormsg)
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        self.msg = "Successfully validated config params: {0}".format(str(config))
        self.log(self.msg, "INFO")
        return self

    def validate_ssid_info(self, ssid_list, config, errormsg):
        """
        This function extending the validation of SSID Details values

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ssid_list (list) - Contains list of dict contains SSID details to validate
            errormsg(list) - List contains error message any validation failure.

        Returns:
            errormsg(list) - List contains error message any validation failure.
        """
        for ssid_details in ssid_list:
            ssid = ssid_details.get("ssid")
            if ssid:
                param_spec = dict(type="str", length_max=32)
                validate_str(ssid, param_spec, "ssid", errormsg)
            else:
                errormsg.append("ssid: SSID is missing in playbook.")

            enable_fabric = ssid_details.get("enable_fabric")
            if enable_fabric and enable_fabric not in (True, False):
                errormsg.append("enable_fabric: Invalid Enable Fabric '{0}' in playbook. either true or false."
                                .format(enable_fabric))

            dot11be_profile_name = ssid_details.get("dot11be_profile_name")
            if dot11be_profile_name:
                param_spec = dict(type="str", length_max=32)
                validate_str(dot11be_profile_name, param_spec, "dot11be_profile_name", errormsg)

            if not enable_fabric:
                vlan_group_name = ssid_details.get("vlan_group_name")
                if vlan_group_name:
                    param_spec = dict(type="str", length_max=32)
                    validate_str(vlan_group_name, param_spec, "vlan_group_name", errormsg)

                interface_name = ssid_details.get("interface_name")
                if interface_name:
                    param_spec = dict(type="str", length_max=31)
                    validate_str(interface_name, param_spec, "interface_name", errormsg)

                anchor_group_name = ssid_details.get("anchor_group_name")
                if anchor_group_name:
                    param_spec = dict(type="str", length_max=32)
                    validate_str(anchor_group_name, param_spec, "anchor_group_name", errormsg)

                local_to_vlan = ssid_details.get("local_to_vlan")
                if local_to_vlan and local_to_vlan not in range(1, 4094) and interface_name:
                    errormsg.append("local_to_vlan: Invalid Local VLAN number '{0}' in playbook."
                                    .format(local_to_vlan))

                if not (vlan_group_name or interface_name):
                    errormsg.append("Either VLAN Group Name or Interface Name required in playbook.")

                if anchor_group_name:
                    if vlan_group_name and interface_name:
                        errormsg.append("If the SSID includes an AnchorGroupName, " +\
                                        "either VlanGroupName or InterfaceName must " +\
                                        "be specified, but not necessarily both")

                if vlan_group_name and interface_name:
                    errormsg.append("either VlanGroupName or InterfaceName must " +\
                                    "be specified, but not necessarily both")

                if vlan_group_name and local_to_vlan:
                    errormsg.append("Either VLAN Group Name or Local to VLAN must " +\
                                    "be specified, but not necessarily both")

                ap_zone_list = config.get("ap_zones")
                if ap_zone_list and len(ap_zone_list) > 0:
                    if len(ap_zone_list) > 100:
                        errormsg.append("ap_zones: AP Zones list is more than 100 in playbook.")
                        break
                    for ap_zones in ap_zone_list:
                        if ap_zones:
                            self.validate_ap_zone(ap_zones, ssid_list, errormsg)

    def validate_ap_zone(self, ap_zones, ssid_list, errormsg):
        """
        This function extending the validation of AP zone values

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ap_zones (dict) - Contains AP zone data given from playbook
            ssid_list (list) - Contains list of dict contains SSID details to validate AP
                               zone SSID

        Returns:
            errormsg(list) - List contains error message any validation failure.
        """
        ap_zone_name = ap_zones.get("ap_zone_name")
        if ap_zone_name:
            param_spec = dict(type="str", length_max=32)
            validate_str(ap_zone_name, param_spec, "ap_zone_name", errormsg)
        else:
            errormsg.append("ap_zone_name: AP Zone Name is missing in playbook.")

        rf_profile_name = ap_zones.get("rf_profile_name")
        if rf_profile_name:
            param_spec = dict(type="str", length_max=30)
            validate_str(rf_profile_name, param_spec, "rf_profile_name", errormsg)
        else:
            errormsg.append("rf_profile_name: RF Profile name is missing in playbook.")

        device_tags = ap_zones.get("device_tags")
        if device_tags and len(device_tags) > 0:
            for device_tag in device_tags:
                param_spec = dict(type="str", length_max=30)
                validate_str(device_tag, param_spec, "device_tag", errormsg)

        ssids = ap_zones.get("ssids")
        if ssids and len(ssids) > 0:
            if len(ssids) > 16:
                errormsg.append("ssids: AP Zone SSIDs list is more than 16 in playbook.")
                return
            for ap_ssid in ssids:
                param_spec = dict(type="str", length_max=32)
                validate_str(ap_ssid, param_spec, "ap_ssid", errormsg)
                ssid_exists = any(ap_ssid in zone.values() for zone in ssid_list)
                if not ssid_exists:
                    zone_msg = "ssids: AP Zone SSID: " +\
                    "{0} {1}not exist in ssid_details.".format(
                        ap_ssid, ssid_exists)
                    errormsg.append(zone_msg)

    def get_want(self, config):
        """
        Retrieve wireless network profile or delete profile from playbook configuration.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing network profile details.

        Returns:
            self: The current instance of the class with updated 'want' attributes.

        Raises:
            AnsibleFailJson: If an incorrect import type is specified.

        Description:
            This function parses the playbook configuration to extract information
            related to network profile. It stores these details in the 'want' dictionary
            for later use in the Ansible module.
        """
        want = {}
        self.input_data_validation(config).check_return_status()
        if config:
            want["wireless_profile"] = config
        self.want = want
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Get required details for the given profile config from Cisco Catalyst Center

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict) - Playbook details containing network profile

        Returns:
            self - The current object with ssid info, template validate site id
            information collection for profile update.
        """

        self.have["wireless_profile"], self.have["wireless_profile_list"] = [], []
        offset = 1
        limit = int(self.payload.get("offset_limit"))

        while True:
            profiles = self.get_network_profile("Wireless", offset, limit)
            if not profiles:
                self.log("No data received from API (Offset={0}). Exiting pagination.".
                            format(offset), "DEBUG")
                break

            self.log("Received {0} profile(s) from API (Offset={1}).".format(
                len(profiles), offset), "DEBUG")
            self.have["wireless_profile_list"].extend(profiles)

            if len(profiles) < limit:
                self.log("Received less than limit ({0}) results, assuming last page. Exiting pagination.".
                            format(limit), "DEBUG")
                break

            offset += limit  # Increment offset for pagination
            self.log("Incrementing offset to {0} for next API request.".format(offset),
                        "DEBUG")

        if self.have["wireless_profile_list"]:
            self.log("Total {0} profile(s) retrieved for 'Wireless': {1}.".format(
                len(self.have["wireless_profile_list"]),
                self.pprint(self.have["wireless_profile_list"])), "DEBUG")
        else:
            self.log("No existing wireless profile(s) found.", "WARNING")

        profile_info = {}
        profile_name = config.get("profile_name")
        if profile_name:
            profile_info["profile_info"] = self.get_wireless_profile(profile_name)
            self.log("Received the wireless profile info for {0}: {1}".
                     format(profile_name, profile_info["profile_info"]), "DEBUG")

        if self.payload.get("state") == "deleted":
            self.have["wireless_profile"].append(profile_info)

        self.log("Check the template exist for the config {0}".format(config), "DEBUG")
        self.check_site_template(config, profile_info)

        ssid_details = config.get("ssid_details")
        ssid_for_apzone = []
        if ssid_details and len(ssid_details) > 0:
            ssid_response = []

            for each_ssid in ssid_details:
                if each_ssid:
                    each_ssid_response = {}
                    self.log("Check Site ID exist in for global for SSID", "INFO")
                    site_exist, site_id = self.get_site_id("global")

                    if site_exist:
                        self.log("Collect SSID details for global: {0}".format(site_id), "INFO")
                        global_ssid_list = self.get_ssid_details(site_id, "global")

                        self.log("Check given ssid exist for: {0}".format(
                            each_ssid.get("ssid")), "INFO")
                        ssid_exist, ssid_info = \
                            self.check_ssid_details(each_ssid.get("ssid"), global_ssid_list)

                        each_ssid_response["ssid_exist"] = ssid_exist
                        each_ssid_response["ssid_response"] = ssid_info
                        each_ssid["wlan_profile_name"] = ssid_info["wlan_profile_name"]
                        each_ssid["policy_profile_name"] = ssid_info["policy_profile_name"]

                    ssid_response.append(each_ssid_response)
                    ssid_for_apzone.append(each_ssid["ssid"])

            if len(ssid_response) > 0:
                profile_info["ssid_response"] = ssid_response

        ap_zones = config.get("ap_zones")
        self.get_ap_zone_info(ap_zones, ssid_for_apzone, profile_info)

        additional_interfaces = config.get("additional_interfaces")
        self.get_additional_interface_info(additional_interfaces, profile_info)

        if profile_info["ssid_response"] and profile_info["profile_info"]:
            profile_stat, unmatched = self.compare_config_data(
                config, profile_info["profile_info"])
            profile_info["profile_compare_stat"] = profile_stat
            profile_info["profile_compare_unmatched"] = unmatched

        self.have["wireless_profile"] = profile_info

        if len(self.have["wireless_profile"]) < 1:
            self.msg = "No data found for wireless profile for the " +\
                "given config: {0}".format(config)

        self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
        self.msg = "Successfully retrieved the details from the system"
        self.status = "success"
        return self

    def get_ap_zone_info(self, ap_zones, ssid_for_apzone, profile_info):
        """
        This function extending the get have function to get details for AP Zone details

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ap_zones (list): A List of dict containing AP Zone name, rf profile and SSIDs.
            ssid_for_apzone (list): A List contains SSID list given on SSID section in playbook
            profile_info (dict): A dict contain AP zone informations

        Returns:
            profile_info : Contains the information about the AP zone details.
        """
        try:
            if ap_zones and len(ap_zones) > 0:
                apzone_response = []
                for each_ap_zone in ap_zones:
                    if each_ap_zone.get("ssids"):
                        each_apzone_response = []
                        for sub_ap_zone in each_ap_zone.get("ssids"):
                            if sub_ap_zone in ssid_for_apzone:
                                each_apzone_response.append(sub_ap_zone)
                        if len(each_apzone_response) == len(each_ap_zone.get("ssids")):
                            apzone_response.append(each_ap_zone.get("ssids"))
                if len(apzone_response) == len(ap_zones):
                    profile_info["apzone_change_required"] = False
                else:
                    profile_info["apzone_change_required"] = True
        except Exception as e:
            self.msg = 'An error occurred during get AP Zone: {0}'.format(str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

    def get_additional_interface_info(self, additional_interfaces, profile_info):
        """
        This function extending the get have function to get details for
        additional interface information

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            additional_interfaces (list): A List of dict containing interface names and Vlan ids.
            profile_info (dict): A dict contain additional interface information with status

        Returns:
            profile_info : Contains the information about the Additional interface status
        """
        self.log("Get the Additional interface details for: {0}".
                 format(additional_interfaces), "DEBUG")
        try:
            if additional_interfaces and len(additional_interfaces) > 0:
                all_interfaces = []
                for each_interface in additional_interfaces:
                    interface = each_interface.get("interface_name")
                    vlan_id = each_interface.get("vlan_id")
                    collect_interface = {}
                    if interface and vlan_id:
                        self.log("Check Additional Interface exist for {0}".
                                format(each_interface), "INFO")
                        check_response = self.additional_interface_check_or_create(
                            interface, vlan_id)

                        collect_interface["interface_name"] = interface
                        collect_interface["vlan_id"] = vlan_id
                        collect_interface["exist"] = False
                        if check_response:
                            collect_interface["exist"] = True
                        all_interfaces.append(collect_interface)
                profile_info["additional_interfaces"] = all_interfaces

        except Exception as e:
            self.msg = 'An error occurred during get Additional interface: {0}'.format(str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

    def additional_interface_check_or_create(self, interface, vlan_id):
        """
        This function used to check the interface and vlan exist if not exist
        then need to be created.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            interface (str): A string containing interface name.
            vlan_id (int): A integer contains Vlan ID from 1 to 4094

        Returns:
            matched (bool): Update True or False if input match with the have data
            dict or None: A dict contain unmatched kay value pair
        """
        self.log("Check the interface name: {0} vlan: {1}".
                 format(interface, vlan_id), "INFO")
        payload = {
            "limit": 500,
            "offset": 1,
            "interface_name": interface,
            "vlan_id": vlan_id
        }
        try:
            interfaces = self.execute_get_request("wireless", "get_interfaces_v1", payload)
            if interfaces and isinstance(interfaces.get("response"), list):
                return True
            else:
                self.log("Creating new Interface and Vlan : {0} Vlan: {1}".
                        format(interface, vlan_id), "INFO")
                payload = {
                    "interfaceName": interface,
                    "vlanId": vlan_id
                }
                task_details = self.execute_process_task_data("wireless", "create_interface_v1",
                                                            payload)
                if task_details:
                    return True
                else:
                    self.msg = "Unable to create below interface: {0}".format(payload)
                    self.log(self.msg, "ERROR")
                    self.fail_and_exit(self.msg)

        except Exception as e:
            self.msg = 'An error occurred during Additional interface Check: {0}'.format(str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

    def compare_config_data(self, input_config, have_prof_info):
        """
        This function used to compare the playbook input with the have data and 
        return the status and unmatch value

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            input_config (dict): A dict containing playbook config of wireless profile.
            have_prof_info (dict): A string contain the profile response from have function

        Returns:
            matched (bool): Update True or False if input match with the have data
            dict or None: A dict contain unmatched kay value pair
        """
        self.log("Compare the input config: {0} with have: {1}".
                 format(self.pprint(input_config), self.pprint(have_prof_info)), "INFO")
        unmatchkey = []

        for prof_key, prof_value in input_config.items():
            if prof_key == "ssid_details" and isinstance(prof_value, list):
                ssid_list = input_config[prof_key]
                for each_ssid in ssid_list:
                    for have_ssid in have_prof_info["ssidDetails"]:
                        if each_ssid.get("ssid") == have_ssid.get("name"):
                            ssid_stat, unmatch = self.compare_each_config_with_have(
                                each_ssid, have_ssid, prof_key)
                            if not ssid_stat:
                                unmatchkey.append(unmatch)

            if prof_key == "site_names" and isinstance(prof_value, list):
                have_sites = [item.lower() for item in have_prof_info["sites"]]
                want_sites = [item.lower() for item in input_config["site_names"]]
                if have_sites != want_sites:
                    self.log("SITE: {0} with have for {1}".
                        format(self.pprint(have_prof_info["sites"]),
                                input_config["site_names"]), "INFO")
                    unmatchkey.append(input_config["site_names"])

        if unmatchkey:
            return False, unmatchkey
        else:
            return True, None

    def get_wireless_profile(self, profile_name):
        """
        Get wireless profile from the given playbook data and response with
        wireless profile information with ssid details.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            profile_name (str): A string containing input data to get wireless profile
                                for given profile name.

        Returns:
            dict: A dict contains wireless profile information.

        Description:
            This function used to get the wireless profile from the input config.
        """

        self.log("Get wireless profile for : {0}".format(profile_name), "INFO")
        try:
            response = self.dnac._exec(
                family="wireless",
                function="get_wireless_profile",
                params={"profile_name": profile_name}
            )
            self.log("Response from get_wireless_profile API: {0}".
                     format(self.pprint(response)), "DEBUG")
            if response and isinstance(response, list):
                self.log("Received the wireless profile response: {0}".
                         format(self.pprint(response)), "INFO")
                return response[0].get("profileDetails")
            else:
                return None

        except Exception as e:
            self.msg = 'An error occurred during get wireless profile: {0}'.format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

    def get_ssid_details(self, site_id, site_name):
        """
        Get SSID details from the given playbook data and response with SSID information.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_id (str) : Site ID contain string of UUID for the global site
            site_name (str): A str containing Site name to collect the SSID information.

        Returns:
            global_ssids (list): Contains list of dict SSID details for the SSID validation

        Description:
            This function used to get the list of SSID informations for the given site.
        """

        self.log("Get SSID information for site {0}: {1}".format(site_name, site_id), "INFO")
        offset_limit = int(self.payload.get("offset_limit"))
        payload = {
            "site_id": site_id,
            "limit": offset_limit,
            "offset": 1
        }
        global_ssids = []
        try:
            while True:
                response = self.dnac._exec(
                    family="wireless",
                    function="get_ssid_by_site",
                    params=payload
                )
                self.log("Response from get_enterprise_ssid API: {0}".
                         format(self.pprint(response)), "DEBUG")

                if not response or not isinstance(response, dict):
                    self.log("Unexpected or empty response received from API, " +
                             "expected a non-empty dictionary.", "ERROR")
                    break

                self.log("Received the SSID details response: {0}".format(
                    self.pprint(response.get("response"))), "INFO")
                response_list = response.get("response")

                if not response_list:
                    self.log("No data received from API (Offset={0}). Exiting pagination.".
                             format(payload["offset"]), "DEBUG")
                    break

                self.log("Received {0} SSID detail(s) from API (Offset={1}).".format(
                    len(response_list), payload["offset"]), "DEBUG")
                global_ssids.extend(response_list)

                if len(response_list) < offset_limit:
                    self.log("Received less than limit ({0}) results, assuming last page. Exiting pagination.".
                             format(offset_limit), "DEBUG")
                    break

                payload["offset"] += offset_limit
                self.log("Incrementing offset to {0} for next API request.".format(
                    payload["offset"]), "DEBUG")

            if global_ssids:
                self.log("Total {0} SSID detail(s) retrieved for the site: '{1}'.".
                         format(len(global_ssids), site_name), "DEBUG")
                return global_ssids

        except Exception as e:
            self.msg = 'An error occurred during get wireless profile: {0}'.format(str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

    def check_ssid_details(self, ssid_name, ssid_list):
        """
        Check the SSID Name is available in the SSID list collected based on the site id.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ssid_name (str): A str containing input data of SSID name.
            ssid_list (list): A list of dict contains SSID name and other details.

        Returns:
            bool: Update True or False if SSID exist
            dict: A string contains SSID information.

        Description:
            This function used to get the SSID information from the input config.
        """

        self.log("Check SSID information match ssid list for {0}: {1}".
                 format(ssid_name, ssid_list), "INFO")
        try:
            ssid_details = {}
            global_ssids = []

            for each_ssid in ssid_list:
                global_ssids.append(each_ssid["ssid"])
                if ssid_name == each_ssid.get("ssid"):
                    ssid_details["ssid"] = ssid_name
                    ssid_details["wlan_profile_name"] = each_ssid.get("profileName")
                    ssid_details["policy_profile_name"] = each_ssid.get("policyProfileName")
                    self.msg = "Verified SSID: {0} exist in Global SSID list.".format(ssid_name)
                    self.log(self.msg, "INFO")
                    return True, ssid_details

            if not ssid_details:
                self.msg = "Given SSID: {0} not in the Global SSID list: {1}.".format(
                    ssid_name, global_ssids)
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

        except Exception as e:
            self.msg = 'An error occurred during ssid checking: {0}'.format(str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

    def parse_input_data_for_payload(self, wireless_data, payload_data):
        """
        This function used to parse data to payload for the profile creation and
        updation.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            wireless_data (dict): A dictionary containing input config data from playbook.
            payload_data (dict): A dictionary contain parsed data for the payload.

        Returns:
            payload_data: A dictionary contain input data for the profile creation and updation.
        """
        try:
            for key, value in wireless_data.items():
                exclude_keys = ["site_names", "feature_templates",
                                "onboarding_templates", "day_n_templates",
                                "provision_group"]
                if value is not None:
                    mapped_key = self.keymap.get(key, key)
                    if key not in exclude_keys:
                        if key == "ssid_details" and isinstance(value, list):
                            payload_data["ssidDetails"] = []
                            ssid_details = wireless_data[key]
                            if ssid_details and len(ssid_details) > 0:
                                for each_ssid in ssid_details:
                                    ssid_data = {}
                                    for ssid_key, ssid_value in each_ssid.items():
                                        mapped_ssidkey = self.keymap.get(ssid_key, ssid_key)
                                        if ssid_key not in ("policy_profile_name"):
                                            if ssid_key == "local_to_vlan" and ssid_value:
                                                ssid_data["flexConnect"] = dict(enableFlexConnect=True,
                                                                                localToVlan=ssid_value)
                                            ssid_data[mapped_ssidkey] = ssid_value
                                    if ssid_data.get("enableFabric"):
                                        remove_keys = ["aflexConnect", "localToVlan"
                                                    "interfaceName", "anchorGroupName",
                                                    "vlanGroupName"]
                                        for rm_key in remove_keys:
                                            ssid_data.pop(rm_key, None)
                                    ssid_data.pop("localToVlan", None)
                                    payload_data["ssidDetails"].append(ssid_data)

                        elif key == "ap_zones" and isinstance(value, list):
                            payload_data["apZones"] = []
                            ap_zones = wireless_data[key]
                            if ap_zones and len(ap_zones) > 0:
                                for ap_zone in ap_zones:
                                    ap_zone_data = {}
                                    for zone_key, zone_value in ap_zone.items():
                                        mapped_zonekey = self.keymap.get(zone_key, zone_key)
                                        if zone_key not in ["device_tags"]:
                                            if ssid_key == "ssids" and len(zone_value) > 0:
                                                ap_zone_data["ssids"] = zone_value
                                            ap_zone_data[mapped_zonekey] = zone_value
                                    payload_data["apZones"].append(ap_zone_data)

                        elif key == "additional_interfaces" and isinstance(value, list):
                            payload_data["additionalInterfaces"] = []
                            addi_interfaces = wireless_data[key]
                            if addi_interfaces and len(addi_interfaces) > 0:
                                for interface in addi_interfaces:
                                    if interface.get("interface_name") is not None:
                                        payload_data["additionalInterfaces"].append(
                                            interface.get("interface_name"))
                        else:
                            payload_data[mapped_key] = value

        except Exception as e:
            self.msg = 'An error occurred during Parsing for payload: {0}'.format(str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

    def create_update_wireless_profile(self, wireless_data, profile_id=None):
        """
        Create/Update the wireless profile for the given config with site and SSID details.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            wireless_data (dict): A dictionary containing input config data from playbook.

        Returns:
            dict: A dictionary of execution task details.

        Description:
            This function create/update the wireless profile with the site the and SSID details.
        """
        payload_data = {}
        self.log("Parse the input playbook to payload for: {0}".format(wireless_data), "INFO")
        self.parse_input_data_for_payload(wireless_data, payload_data)

        function_name = "create_wireless_profile_connectivity_v1"
        profile_exist = self.value_exists(self.have.get("wireless_profile"),
                                          "name", payload_data.get("wirelessProfileName"))
        profile_payload = {}

        if profile_exist:
            function_name = "update_wireless_profile_connectivity_v1"
            have_profile = self.have.get("wireless_profile")
            if have_profile and isinstance(have_profile, list):
                for profile in have_profile:
                    if profile.get("profile_info", {}).get("name") == \
                        payload_data.get("wirelessProfileName"):
                        profile_id = profile.get("profile_info", {}).get("instanceUuid")
                        profile_payload = {"id": profile_id, "payload": payload_data}
                        self.log("Updating wireless profile with parameters: {0}".format(
                            self.pprint(payload_data)), "INFO")
        elif profile_id:
            function_name = "update_wireless_profile_connectivity_v1"
            profile_payload = {"id": profile_id, "payload": payload_data}
            self.log("Updating wireless profile for template with parameters: {0}".format(
                self.pprint(payload_data)), "INFO")
        else:
            profile_payload = payload_data
            self.log("Creating wireless profile with parameters: {0}".format(
                self.pprint(payload_data)), "INFO")

        return self.execute_process_task_data("wireless", function_name, profile_payload)

    def compare_each_config_with_have(self, input_data, have_data, type_of):
        """
        compare each config data of ssid info and ap zone data and return the 
        boolean and unmatch data

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            input_data (dict): A dict containing playbook config of ssid info and ap zone data.
            have_data (dict): A dict contain the data exist with specific ssid retrived data
            type_of (str): A string contain the ssid details or ap_zone for check data

        Returns:
            matched (bool): Update True or False if input match with the have data
            dict: A dict contain unmatch data 

        Description:
            This function used to compare the data same have and input config data.
        """
        if type_of == "ssid_details":
            un_match_data = {}
            for ssid_key in input_data.keys():
                if ssid_key == "ssid":
                    if input_data[ssid_key] != have_data.get("name"):
                        un_match_data[ssid_key] = input_data[ssid_key]
                elif ssid_key in ["wlan_profile_name", "interface_name",
                                  "enable_fabric",
                                  "anchor_group_name", "dot11be_profile_name",
                                  "policy_profile_name"]:
                    if input_data[ssid_key] != have_data.get(self.keymap[ssid_key]):
                        un_match_data[ssid_key] = input_data[ssid_key]
                elif ssid_key ==  "local_to_vlan":
                    if str(input_data[ssid_key]) != have_data.get(
                        "flexConnect", {}).get(self.keymap[ssid_key]):
                        un_match_data[ssid_key] = input_data[ssid_key]

            if not un_match_data:
                return True, None
            else:
                self.log("Found the unmatched data {0}".format(self.pprint(
                    un_match_data)), "INFO")
                return False, un_match_data

        if type_of == "ap_zones":
            un_match_data = {}

    def assign_wirelss_template(self, ob_template, dn_template, profile_id, prefile_name):
        """
        This function used to assign onboarding templates and day n templates to the
        wireless profile.
    
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ob_template (list) - List of string contains onboarding template names.
            ob_template (list) - List of string contains day n template names.
            profile_id (str): A string containing profile id to update the wireless profile.
            prefile_name (str): A string containing profile name to update the wireless profile.

        Returns:
            dict or None: A dict contains Task details of the profile assigned status.

        Note:
            API and SDK not available to assign templates to wireless profile, once received
            this need to be replaced.
        """
        target_url = f"{self.dnac_url}/api/v1/siteprofile"
        response = {}
        ob_template_ids, dn_template_ids = [], []
        profile_attributes = []

        if ob_template and len(ob_template) > 0:
            for each_template in ob_template:
                if each_template.get("template_exist"):
                    ob_template_ids.append(dict(
                        key="template.id",
                        value=each_template.get("template_id")
                        ))

        if dn_template and len(dn_template) > 0:
            for each_template in dn_template:
                if each_template.get("template_exist"):
                    dn_template_ids.append(dict(
                        key="template.id",
                        value=each_template.get("template_id")
                        ))

        if len(ob_template_ids) > 0:
            profile_attributes.append(dict(
                key="day0.templates",
                attribs=ob_template_ids
            ))

        if len(dn_template_ids) > 0:
            profile_attributes.append(dict(
                key="cli.templates",
                attribs=dn_template_ids
            ))

        payload = {
                    "name": prefile_name,
                    "namespace": "wlan",
                    "profileAttributes": profile_attributes
                }

        self.log("Assigning wireless profile template with parameters: {0}".format(
            self.pprint(payload)), "INFO")
    
        try:
            response = None
            if profile_id:
                target_url = target_url + "/" + profile_id
                response = requests.put(
                target_url, headers=self.headers, json=payload,
                verify=False, timeout=10
            )

            if response.status_code in [200, 202]:
                response_json = response.json()
                self.log("Wireless profile templates updated successfully: {0}".format(
                    self.pprint(response_json)), "INFO")
                task_id = response_json.get("response", {}).get("taskId")
                return self.execute_process_task_data("profile", target_url,
                                                payload, task_id)
            else:
                self.log("Failed to create switch profile: {0} - {1}".
                        format(response.status_code, str(response.text)), "ERROR")

        except Exception as e:
            self.msg = 'An error occurred during create Switch profile: {0}'.format(
                str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        return None

    def get_diff_merged(self, config):
        """
        Create or update the wireless profile in Cisco Catalyst Center based on the playbook

        Parameters:
            config (dict) - Playbook details containing wireless profile information.

        Returns:
            self - The current object with create or update message with task response.
        """
        self.msg = ""
        self.changed = False
        self.status = "failed"
        profile_no = 0

        unmatch_stat = self.have["wireless_profile"].get("profile_compare_stat")
        if any(profile["name"] == config.get("profile_name")
               for profile in self.have["wireless_profile_list"]) and unmatch_stat:
            self.msg = "No changes required, profile(s) are already exist"
            self.log(self.msg, "INFO")
            self.set_operation_result("success", False, self.msg, "INFO").check_return_status()
            return self

        task_details = None
        if not unmatch_stat:
            self.log("", "INFO")
            task_details = self.create_update_wireless_profile(config)

        if task_details:
            profile_response = dict(profile_name=config["profile_name"],
                                    status=task_details["progress"])
            uuid_pattern = \
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
            match = re.search(uuid_pattern, task_details["progress"])
            if match:
                profile_id = match.group()
                have_site = self.have["wireless_profile"].get("site_response")
                site_id_list = []
                if have_site and isinstance(have_site, list) and len(have_site) > 0:
                    for each_site in have_site:
                        if each_site["site_exist"]:
                            site_id_list.append(each_site["site_id"])

                if len(site_id_list) > 0:
                    assign_response = []
                    for site in site_id_list:
                        assign_response.append(self.assign_site_to_network_profile(
                            profile_id, site))

                ob_template = self.have["wireless_profile"].get("onboarding_templates")
                dn_template = self.have["wireless_profile"].get("day_n_templates")

                self.assign_wirelss_template(ob_template, dn_template, profile_id,
                                             config["profile_name"])
                self.create_update_wireless_profile(config, profile_id)

            profile_no += 1
            self.created.append(profile_response)
            self.msg = "Wireless Profile created/updated successfully for '{0}'.".format(
                str(self.created))
            self.changed = True
            self.status = "success"
        else:
            self.not_processed.append(config)
            self.msg = "Unable to create wireless profile: '{0}'.".format(
                str(self.not_processed))

        self.log(self.msg, "INFO")
        self.set_operation_result(self.status, self.changed, self.msg, "INFO",
                                self.created).check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Verify the merged status(Creation/Updation) of wireless profile in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by
            retrieving the current state (have) and desired state (want) of the configuration,
            logs the states, and validates whether the specified profiles exists in the Catalyst
            Center.
        """

        self.msg = ""
        success_profile = []
        self.changed = False
        self.status = "failed"

        if len(self.created) > 0:
            for each_created in self.created:
                if each_created.get("profile_name") == config["profile_name"]:
                    success_profile.append(each_created["profile_name"])

        if len(success_profile) == 0 and len(self.not_processed) == 0:
            self.msg = "No changes required, profile(s) are already exist"
            self.changed = False
            self.status = "success"
        elif success_profile:
            self.msg = "Profile created/updated are verified successfully for '{0}'.".format(
                str(success_profile))
            self.changed = True
            self.status = "success"
        else:
            self.msg = self.msg + "\n Unable to create profile '{0}'.".format(
                str(self.not_processed))

        self.log(self.msg, "INFO")
        self.set_operation_result(self.status, self.changed, self.msg, "INFO",
                            self.created).check_return_status()
        return self

    def get_diff_deleted(self, config):
        """
        Delete Network profile based on the given profile ID
        Network configurations in Cisco Catalyst Center based on the playbook details

        Parameters:
            - config (dict): The configuration details to be deleted from the Cisco Catalyst Center

        Returns:
            self - The current object with deleted status and return response with task details.
        """
        self.changed = False
        self.status = "failed"
        each_profile = config
        if not any(profile["name"] == each_profile["profile_name"]
                   for profile in self.have["wireless_profile_list"]):
            self.msg = "No changes required, profile(s) are already deleted"
            self.log(self.msg, "INFO")
            self.set_operation_result("success", False, self.msg, "INFO").check_return_status()

        each_have = self.have.get("wireless_profile")
        have_profile_name = each_have.get("profile_info")
        if not have_profile_name:
            self.msg = "No changes required, profile(s) not exist or already deleted"
            self.log(self.msg, "INFO")
            self.set_operation_result("success", False, self.msg, "INFO").check_return_status()
        else:
            have_profile_name = each_have.get("profile_info", {}).get("name")

        if have_profile_name == each_profile.get("profile_name"):
            have_profile_id = each_have.get("profile_info", {}).get("instanceUuid")
            sites = each_have.get("profile_info", {}).get("sites")
            if sites and len(sites) > 0:
                unassign_site = []
                for each_site in sites:
                    site_exist, site_id = self.get_site_id(each_site)
                    unassign_response = self.unassign_site_to_network_profile(
                        have_profile_id, site_id)
                    unassign_site.append(unassign_response)

                if len(unassign_site) == len(sites):
                    self.log("Sites unassigned successfully {0}".format(
                        sites), "INFO")

            task_details = None
            if have_profile_id:
                task_details = self.delete_network_profiles(have_profile_id)

            if task_details:
                profile_response = dict(profile_name=each_profile["profile_name"],
                                        status=task_details["progress"])
                self.deleted.append(profile_response)
                self.msg = "Wireless Profile deleted successfully for '{0}'.".format(
                    str(self.deleted))
                self.changed = True
                self.status = "success"
            else:
                self.not_processed.append(config)
                self.msg = "Unable to delete profile: '{0}'.".format(
                    str(self.not_processed))
                self.log(self.msg, "INFO")
                self.fail_and_exit(self.msg)

        self.log(self.msg, "INFO")
        self.set_operation_result(self.status, self.changed, self.msg, "INFO",
                                  each_profile).check_return_status()
        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of wireless network profile in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.

        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified profile exists in the Cisco Catalyst Center.
        """
        self.msg = ""
        deleted_success = []
        deleted_unsuccess = []

        self.get_have(config)
        self.log("Get have function response {0}".format(self.pprint(
            self.have["wireless_profile"])), "INFO")

        #for each_profile in self.have.get("wireless_profile"):
        each_profile = self.have.get("wireless_profile")
        profile_info = each_profile.get("profile_info")
        if profile_info:
            self.msg = "Unable to delete below wireless profile '{0}'.".format(
                profile_info.get("name"))
            deleted_unsuccess.append(profile_info.get("name"))
            self.log(self.msg, "INFO")
            self.set_operation_result("failed", False, self.msg, "INFO",
                                        deleted_unsuccess).check_return_status()
        else:
            self.msg = "Wireless profile deleted and verified successfully"
            deleted_success.append(self.msg)
            self.log(self.msg, "INFO")
            self.set_operation_result("success", True, self.msg, "INFO",
                                      deleted_success).check_return_status()

        return self

    def final_response_message(self, state):
        """
        To show the final message with Wireless profile response

        Parameters:
            configs (list of dict) - Playbook config contains Wireless profile
            playbook information.

        Returns:
            self - Return response as verified created/updated/deleted
            Wireless profile messages
        """
        if state == "merged":
            if (len(self.created) > 0 and len(self.not_processed) > 0) or (
               len(self.created) > 0 and len(self.not_processed) == 0):
                self.msg = "Wireless profile created and verified successfully for '{0}'.".format(
                    str(self.created))
                if len(self.not_processed) > 0:
                    self.msg = self.msg + " Unable to create below wireless profile : {0}".format(
                        self.not_processed)
                self.log(self.msg, "INFO")
                self.set_operation_result("success", True, self.msg, "INFO",
                                          self.created).check_return_status()
            elif len(self.created) == len(self.not_processed) == 0:
                self.msg = "No changes required, profile(s) are already exist"
                self.log(self.msg, "INFO")
                self.set_operation_result("success", False, self.msg, "INFO").check_return_status()
            else:
                self.msg = "\n Unable to create below profile '{0}'.".format(
                    str(self.not_processed))
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR",
                                          self.not_processed).check_return_status()
        else:
            if len(self.deleted) > 0 and len(self.not_processed) > 0:
                self.msg = "Wireless profile deleted and verified successfully for '{0}'.".format(
                    self.deleted)
                self.msg = self.msg + "\n Unable to delete below profile '{0}'.".format(
                    str(self.not_processed))
                self.set_operation_result("success", True, self.msg,
                                          "INFO").check_return_status()
            elif len(self.deleted) > 0 and len(self.not_processed) == 0:
                self.msg = "Wireless profile deleted and verified successfully for '{0}'.".format(
                    self.deleted)
                self.log(self.msg, "INFO")
                self.set_operation_result("success", True, self.msg,
                                          "INFO", self.deleted).check_return_status()
            elif len(self.deleted) == 0 and len(self.not_processed) > 0:
                self.msg = "Unable to delete below profile '{0}'.".format(
                    str(self.not_processed))
                self.set_operation_result("failed", False, self.msg, "ERROR",
                                          self.not_processed).check_return_status()
            else:
                self.msg = "Wireless profile already deleted for '{0}'.".format(self.config)
                self.set_operation_result("success", False, self.msg,
                                          "INFO").check_return_status()

        return self


def main():
    """main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": 'str', "required": True},
        "dnac_port": {"type": 'str', "default": '443'},
        "dnac_username": {"type": 'str', "default": 'admin', "aliases": ['user']},
        "dnac_password": {"type": 'str', "no_log": True},
        "dnac_verify": {"type": 'bool', "default": 'True'},
        "dnac_version": {"type": 'str', "default": '2.3.7.6'},
        "dnac_debug": {"type": 'bool', "default": False},
        "dnac_log": {"type": 'bool', "default": False},
        "dnac_log_level": {"type": 'str', "default": 'WARNING'},
        "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
        "dnac_log_append": {"type": 'bool', "default": True},
        "config_verify": {"type": 'bool', "default": False},
        "dnac_api_task_timeout": {"type": 'int', "default": 1200},
        "dnac_task_poll_interval": {"type": 'int', "default": 2},
        "offset_limit": {"type": 'int', "default": 500},
        "config": {"type": 'list', "required": True, "elements": 'dict'},
        "state": {"default": 'merged', "choices": ['merged', 'deleted']},
        "validate_response_schema": {"type": 'bool', "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec,
                            supports_check_mode=False)
    ccc_wireless_profile = NetworkWirelessProfile(module)
    state = ccc_wireless_profile.params.get("state")

    if ccc_wireless_profile.compare_dnac_versions(
        ccc_wireless_profile.get_ccc_version(), "2.3.7.9") < 0:
        ccc_wireless_profile.status = "failed"
        ccc_wireless_profile.msg = (
            "The specified version '{0}' does not support the network profile workflow feature."
            "Supported version(s) start from '2.3.7.9' onwards.".
            format(ccc_wireless_profile.get_ccc_version())
        )
        ccc_wireless_profile.log(ccc_wireless_profile.msg, "ERROR")
        ccc_wireless_profile.check_return_status()

    if state not in ccc_wireless_profile.supported_states:
        ccc_wireless_profile.status = "invalid"
        ccc_wireless_profile.msg = "State {0} is invalid".format(state)
        ccc_wireless_profile.check_return_status()

    ccc_wireless_profile.validate_input().check_return_status()
    config_verify = ccc_wireless_profile.params.get("config_verify")

    for config in ccc_wireless_profile.validated_config:
        if not config:
            ccc_wireless_profile.msg = "Playbook configuration is missing."
            ccc_wireless_profile.log(ccc_wireless_profile.msg, "ERROR")
            ccc_wireless_profile.fail_and_exit(ccc_wireless_profile.msg)

        ccc_wireless_profile.reset_values()
        ccc_wireless_profile.get_want(config).check_return_status()
        ccc_wireless_profile.get_have(config).check_return_status()
        ccc_wireless_profile.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_wireless_profile.verify_diff_state_apply[state](config).check_return_status()

    ccc_wireless_profile.final_response_message(state).check_return_status()
    module.exit_json(**ccc_wireless_profile.result)

if __name__ == "__main__":
    main()
