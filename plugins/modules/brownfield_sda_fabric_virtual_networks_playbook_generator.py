#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to manage Extranet Policy Operations in SD-Access Fabric in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Abhishek Maheshwari, Madhan Sankaranarayanan"

DOCUMENTATION = r"""
---
module: brownfield_sda_fabric_virtual_networks_playbook_generator
short_description: Generate YAML playbook for 'brownfield_sda_fabric_virtual_networks_playbook_generator' module.
description:
- Generates YAML configurations compatible with the `brownfield_sda_fabric_virtual_networks_playbook_generator`
  module, reducing the effort required to manually create Ansible playbooks and
  enabling programmatic modifications.
- The YAML configurations generated represent the fabric vlans, virtual networks and anycast
  gateways configured on the Cisco Catalyst Center.
version_added: 6.17.0
extends_documentation_fragment:
- cisco.dnac.workflow_manager_params
author:
- Abhishek Maheshwari (@abmahesh)
- Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center after applying the playbook config.
    type: bool
    default: false
  state:
    description: The desired state of Cisco Catalyst Center after module execution.
    type: str
    choices: [merged]
    default: merged
  config:
    description:
    - A list of filters for generating YAML playbook compatible with the `brownfield_sda_fabric_virtual_networks_playbook_generator`
      module.
    - Filters specify which components to include in the YAML configuration file.
    - If "components_list" is specified, only those components are included, regardless of the filters.
    type: list
    elements: dict
    required: true
    suboptions:
      generate_all_components:
        description:
        - If true, all components are included in the YAML configuration file i.e fabric_vlan,
          virtual_networks, and anycast_gateways.
        - If false, only the components specified in "components_list" are included.
        type: bool
      file_path:
        description:
        - Path where the YAML configuration file will be saved.
        - If not provided, the file will be saved in the current working directory with
          a default file name  "<module_name>_playbook_<DD_Mon_YYYY_HH_MM_SS_MS>.yml".
        - For example, "brownfield_sda_fabric_virtual_networks_playbook_generator_playbook_22_Apr_2025_21_43_26_379.yml".
        type: str
      component_specific_filters:
        description:
        - Filters to specify which components to include in the YAML configuration
          file.
        - If "components_list" is specified, only those components are included,
          regardless of other filters.
        type: dict
        suboptions:
          components_list:
            description:
            - List of components to include in the YAML configuration file.
            - Valid values are
              - Fabric VLANs "fabric_vlan"
              - Virtual Networks "virtual_networks"
              - Anycast Gateways "anycast_gateways"
            - If not specified, all components are included.
            - For example, ["fabric_vlan", "virtual_networks", "anycast_gateways"].
            type: list
            elements: str
          fabric_vlan:
            description:
            - Fabric VLANs to filter fabric vlans by vlan name or vlan id.
            type: list
            elements: dict
            suboptions:
              vlan_name:
                description:
                - VLAN name to filter fabric vlans by vlan name.
                type: str
              vlan_id:
                description:
                - VLAN ID to filter fabric vlans by vlan id.
                type: int
          virtual_networks:
            description:
            - Virtual Networks to filter virtual networks by VN name.
            type: list
            elements: dict
            suboptions:
              vn_name:
                description:
                - Virtual Network name to filter virtual networks by VN name.
                type: str
          anycast_gateways:
            description:
            - Anycast Gateways to filter anycast gateways by VN name, VLAN name,
              VLAN ID, or IP Pool name.
            type: list
            elements: dict
            suboptions:
              vn_name:
                description:
                - Virtual Network name to filter anycast gateways by VN name.
                type: str
              vlan_name:
                description:
                - VLAN name to filter anycast gateways by VLAN name.
                type: str
              vlan_id:
                description:
                - VLAN ID to filter anycast gateways by VLAN ID.
                type: int
              ip_pool_name:
                description:
                - IP Pool name to filter anycast gateways by IP Pool name.
                type: str
requirements:
- dnacentersdk >= 2.10.10
- python >= 3.9
notes:
- SDK Methods used are
    - sites.Sites.get_site - site_design.SiteDesigns.get_sites
    - sda.Sda.get_layer2_virtual_networks
    - sda.Sda.get_layer3_virtual_networks
    - sda.Sda.get_anycast_gateways
    - sda.Sda.get_fabric_sites
    - sda.Sda.get_fabric_zones
    - sda.Sda.get_fabric_sites_by_id
    - sda.Sda.get_fabric_zones_by_id
- Paths used are
    - GET /dna/intent/api/v1/sites
    - GET /dna/intent/api/v1/sda/layer2-virtual-networks
    - GET /dna/intent/api/v1/sda/layer3-virtual-networks
    - GET /dna/intent/api/v1/sda/anycast-gateways
    - GET /dna/intent/api/v1/sda/fabric-sites
    - GET /dna/intent/api/v1/sda/fabric-zones
    - GET /dna/intent/api/v1/sda/fabric-sites/{id}
    - GET /dna/intent/api/v1/sda/fabric-zones/{id}
"""

EXAMPLES = r"""
- name: Generate YAML Configuration with File Path specified
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
- name: Generate YAML Configuration with specific fabric vlan components only
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["fabric_vlan"]
- name: Generate YAML Configuration with specific virtual networks components only
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["virtual_networks"]
- name: Generate YAML Configuration with specific anycast gateways components only
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["anycast_gateways"]
- name: Generate YAML Configuration for fabric vlans with vlan name filter
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["fabric_vlan"]
          fabric_vlan:
            - vlan_name: "vlan_1"
            - vlan_name: "vlan_2"
- name: Generate YAML Configuration for virtual networks with VN name filter
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["virtual_networks"]
          virtual_networks:
            - vn_name: "vn_1"
            - vn_name: "vn_2"
- name: Generate YAML Configuration for anycast gateways with multiple filters
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["anycast_gateways"]
          anycast_gateways:
            - vn_name: "vn_1"
            - ip_pool_name: "ip_pool_1"
- name: Generate YAML Configuration for fabric vlans and virtual networks with multiple filters
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["fabric_vlan", "virtual_networks"]
          fabric_vlan:
            - vlan_name: "vlan_1"
            - vlan_name: "vlan_2"
          virtual_networks:
            - vn_name: "vn_1"
            - vn_name: "vn_2"
- name: Generate YAML Configuration for all components with no filters
  cisco.dnac.brownfield_sda_fabric_virtual_networks_playbook_generator:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - file_path: "/tmp/catc_virtual_networks_components_config.yaml"
        component_specific_filters:
          components_list: ["fabric_vlan", "virtual_networks", "anycast_gateways"]
"""


RETURN = r"""
# Case_1: Success Scenario
response_1:
  description: A dictionary with  with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response":
        {
          "response": String,
          "version": String
        },
      "msg": String
    }
# Case_2: Error Scenario
response_2:
  description: A string with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.brownfield_helper import (
    BrownFieldHelper,
)
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
import time
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    yaml = None
from collections import OrderedDict


if HAS_YAML:
    class OrderedDumper(yaml.Dumper):
        def represent_dict(self, data):
            return self.represent_mapping("tag:yaml.org,2002:map", data.items())

    OrderedDumper.add_representer(OrderedDict, OrderedDumper.represent_dict)
else:
    OrderedDumper = None


class VirtualNetworksPlaybookGenerator(DnacBase, BrownFieldHelper):
    """
    A class for generator playbook files for infrastructure deployed within the Cisco Catalyst Center using the GET APIs.
    """

    values_to_nullify = ["NOT CONFIGURED"]

    def __init__(self, module):
        """
        Initialize an instance of the class.
        Args:
            module: The module associated with the class instance.
        Returns:
            The method does not return a value.
        """
        self.supported_states = ["merged"]
        super().__init__(module)
        self.module_mapping = self.virtual_networks_workflow_manager_mapping()
        self.site_id_name_dict = self.get_site_id_name_mapping()
        self.module_name = "virtual_networks_design_workflow_manager"

    def validate_input(self):
        """
        Validates the input configuration parameters for the playbook.
        Returns:
            object: An instance of the class with updated attributes:
                self.msg: A message describing the validation result.
                self.status: The status of the validation (either "success" or "failed").
                self.validated_config: If successful, a validated version of the "config" parameter.
        """
        self.log("Starting validation of input configuration parameters.", "DEBUG")

        # Check if configuration is available
        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        # Expected schema for configuration parameters
        temp_spec = {
            "file_path": {"type": "str", "required": False},
            "component_specific_filters": {"type": "dict", "required": False},
            "global_filters": {"type": "dict", "required": False},
        }

        # Validate params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Set the validated configuration and update the result with success status
        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validated_input': {0}".format(
            str(valid_temp)
        )
        self.set_operation_result("success", False, self.msg, "INFO")
        return self

    def virtual_networks_workflow_manager_mapping(self):
        """
        Description:
            Constructs and returns a structured mapping for managing various virtual network elements
            such as fabric VLANs, virtual networks, and anycast gateways. This mapping includes
            associated filters, temporary specification functions, API details, and fetch function references
            used in the virtual network workflow orchestration process.

        Args:
            self: Refers to the instance of the class containing definitions of helper methods like
                `fabric_vlan_temp_spec`, `get_fabric_vlans`, etc.

        Return:
            dict: A dictionary with the following structure:
                - "network_elements": A nested dictionary where each key represents a network component
                (e.g., 'fabric_vlan', 'virtual_networks', 'anycast_gateways') and maps to:
                    - "filters": List of filter keys relevant to the component.
                    - "temp_spec_function": Reference to the function that generates temp specs for the component.
                    - "api_function": Name of the API to be called for the component.
                    - "api_family": API family name (e.g., 'sda').
                    - "get_function_name": Reference to the internal function used to retrieve the component data.
                - "global_filters": An empty list reserved for global filters applicable across all network elements.
        """

        return {
            "network_elements": {
                "fabric_vlan": {
                    "filters": ["vlan_name", "vlan_id"],
                    "temp_spec_function": self.fabric_vlan_temp_spec,
                    "api_function": "get_layer2_virtual_networks",
                    "api_family": "sda",
                    "get_function_name": self.get_fabric_vlans,
                },
                "virtual_networks": {
                    "filters": ["vn_name"],
                    "temp_spec_function": self.virtual_network_temp_spec,
                    "api_function": "get_layer3_virtual_networks",
                    "api_family": "sda",
                    "get_function_name": self.get_virtual_networks,
                },
                "anycast_gateways": {
                    "filters": ["vn_name", "vlan_name", "ip_pool_name"],
                    "temp_spec_function": self.anycast_gateway_temp_spec,
                    "api_function": "get_anycast_gateways",
                    "api_family": "sda",
                    "get_function_name": self.fetch_anycast_gateways_from_ccc,
                },
            },
            "global_filters": [],
        }

    def transform_fabric_site_locations(self, vlan_details):
        """
        Transforms fabric site-related information for a given VLAN by extracting and mapping
        the site hierarchy and fabric type based on the fabric ID.

        Args:
            vlan_details (dict): A dictionary containing VLAN-specific information, including the 'fabricId' key.

        Returns:
            list: A list containing a single dictionary with the following keys:
                - "site_name_hierarchy" (str): The hierarchical name of the site (e.g., "Global/Site/Building").
                - "fabric_type" (str): The type of fabric, such as "fabric_site" or "fabric_zone".
        """

        self.log(
            "Transforming fabric site locations for VLAN details: {0}".format(vlan_details),
            "DEBUG"
        )
        fabric_id = vlan_details.get("fabricId")
        site_id, fabric_type = self.analyse_fabric_site_or_zone_details(fabric_id)
        site_name_hierarchy = self.site_id_name_dict.get(site_id, None)

        return [{
            "site_name_hierarchy": site_name_hierarchy,
            "fabric_type": fabric_type
        }]

    def transform_fabric_vn_site_locations(self, vn_details):
        """
        Transforms virtual network (VN) details by mapping fabric IDs to their corresponding
        site hierarchy names and fabric types.

        Args:
            vn_details (dict): A dictionary containing virtual network information,
                            expected to include a list of fabric IDs under the 'fabricIds' key.

        Returns:
            list: A list of dictionaries, each containing:
                - "site_name_hierarchy" (str): The hierarchical name of the site
                (e.g., "Global/Site/Building/Floor").
                - "fabric_type" (str): The type of fabric, such as "fabric_site" or "fabric_zone".
        """

        self.log(
            "Transforming fabric site locations for VN details: {0}".format(vn_details),
            "DEBUG"
        )
        fabric_ids = vn_details.get("fabricIds")
        fabric_site_list = []
        if not fabric_ids:
            self.log(
                "No fabric IDs found in VN details: {0}".format(vn_details),
                "DEBUG"
            )
            return fabric_site_list

        for fabric_id in fabric_ids:
            site_id, fabric_type = self.analyse_fabric_site_or_zone_details(fabric_id)
            site_name_hierarchy = self.site_id_name_dict.get(site_id, None)
            self.log(
                "Transformed fabric site name {0} for VN details: {1}".format(
                    site_name_hierarchy, vn_details
                ),
                "DEBUG"
            )
            site_dict = {
                "site_name_hierarchy": site_name_hierarchy,
                "fabric_type": fabric_type
            }
            fabric_site_list.append(site_dict)

        return fabric_site_list

    def transform_anycast_fabric_site_location(self, anycast_details):
        """
        Transforms anycast gateway details by extracting the site hierarchy and fabric type
        using the provided fabric ID.

        Args:
            anycast_details (dict): A dictionary containing anycast gateway information,
                                    expected to include the key 'fabricId'.

        Returns:
            dict or None: A dictionary containing:
                - "site_name_hierarchy" (str): The hierarchical name of the site
                (e.g., "Global/Site/Building/Floor").
                - "fabric_type" (str): The type of fabric, such as "fabric_site" or "fabric_zone".
        """

        self.log(
            "Transforming anycast gateway details for: {0}".format(anycast_details),
            "DEBUG"
        )
        fabric_id = anycast_details.get("fabricId")
        if not fabric_id:
            self.log(
                "No fabric ID found in anycast gateway details: {0}".format(anycast_details),
                "DEBUG"
            )
            return None

        site_id, fabric_type = self.analyse_fabric_site_or_zone_details(fabric_id)
        site_name_hierarchy = self.site_id_name_dict.get(site_id, None)
        self.log(
            "Transformed fabric site name {0} for anycast gateway details: {1}".format(
                site_name_hierarchy, anycast_details
            ),
            "DEBUG"
        )
        return {
            "site_name_hierarchy": site_name_hierarchy,
            "fabric_type": fabric_type
        }

    def transform_anchored_site_name(self, vn_details):
        """
        Transforms the anchored site name for a given virtual network (VN) by extracting
        the site hierarchy and fabric type from the VN details.

        Args:
            vn_details (dict): A dictionary containing virtual network information,
                               expected to include the key 'anchoredSiteId'.

        Returns:
            str or None: The hierarchical name of the anchored site if found, otherwise None.
        """

        self.log(
            "Transforming anchored site name for VN details: {0}".format(vn_details),
            "DEBUG"
        )
        fabric_id = vn_details.get("anchoredSiteId")
        if not fabric_id:
            self.log(
                "No anchored site ID found in VN details: {0}".format(vn_details),
                "DEBUG"
            )
            return None

        site_id, fabric_type = self.analyse_fabric_site_or_zone_details(fabric_id)
        site_name_hierarchy = self.site_id_name_dict.get(site_id, None)
        self.log(
            "Transformed anchored site name {0} for VN details: {1}".format(
                site_name_hierarchy, vn_details
            ),
            "DEBUG"
        )
        return site_name_hierarchy

    def fabric_vlan_temp_spec(self):
        """
        Constructs a temporary specification for fabric VLANs, defining the structure and types of attributes
        that will be used in the YAML configuration file. This specification includes details such as VLAN name,
        VLAN ID, fabric site locations, traffic type, and various flags related to wireless and resource management.

        Returns:
            OrderedDict: An ordered dictionary defining the structure of fabric VLAN attributes.
        """

        self.log("Generating temporary specification for fabric VLANs.", "DEBUG")
        fabric_vlan = OrderedDict(
            {
                "vlan_name": {"type": "str", "source_key": "vlanName"},
                "vlan_id": {"type": "str", "source_key": "vlanId"},
                "fabric_site_locations": {
                    "type": "list",
                    "elements": "dict",
                    "special_handling": True,
                    "transform": self.transform_fabric_site_locations,
                    "site_name_hierarchy": {"type": "str"},
                    "fabric_type": {"type": "str"},
                },
                "traffic_type": {"type": "str", "source_key": "trafficType"},
                "fabric_enabled_wireless": {"type": "bool", "source_key": "isFabricEnabledWireless"},
                "associated_layer3_virtual_network": {"type": "str", "source_key": "associatedLayer3VirtualNetworkName"},
                "is_wireless_flooding_enable": {"type": "bool", "source_key": "isWirelessFloodingEnabled"},
                "is_resource_guard_enable": {"type": "bool", "source_key": "isResourceGuardEnabled"},
                "flooding_address_assignment": {"type": "str", "source_key": "floodingAddressAssignment"},
                "flooding_address": {"type": "str", "source_key": "floodingAddress"},
            }
        )
        return fabric_vlan

    def virtual_network_temp_spec(self):
        """
        Constructs a temporary specification for virtual networks, defining the structure and types of attributes
        that will be used in the YAML configuration file. This specification includes details such as virtual network name,
        anchored site name, fabric site locations, and other relevant attributes.

        Returns:
            OrderedDict: An ordered dictionary defining the structure of virtual network attributes.
        """

        self.log("Generating temporary specification for virtual networks.", "DEBUG")
        virtual_network = OrderedDict(
            {
                "vn_name": {"type": "str", "source_key": "virtualNetworkName"},
                "anchored_site_name": {
                    "type": "str",
                    "special_handling": True,
                    "transform": self.transform_anchored_site_name,
                },
                "fabric_site_locations": {
                    "type": "list",
                    "elements": "dict",
                    "special_handling": True,
                    "transform": self.transform_fabric_vn_site_locations,
                    "site_name_hierarchy": {"type": "str"},
                    "fabric_type": {"type": "str"},
                },
            }
        )
        return virtual_network

    def anycast_gateway_temp_spec(self):
        """
        Constructs a temporary specification for anycast gateways, defining the structure and types of attributes
        that will be used in the YAML configuration file. This specification includes details such as virtual network name,
        IP pool name, TCP MSS adjustment, VLAN name, VLAN ID, traffic type, pool type, security group name,
        and various flags related to wireless and resource management.

        Returns:
            OrderedDict: An ordered dictionary defining the structure of anycast gateway attributes.
        """

        self.log("Generating temporary specification for anycast gateways.", "DEBUG")
        anycast_gateway = OrderedDict(
            {
                "vn_name": {"type": "str", "source_key": "virtualNetworkName"},
                "ip_pool_name": {"type": "str", "source_key": "ipPoolName"},
                "tcp_mss_adjustment": {"type": "int", "source_key": "tcpMssAdjustment"},
                "vlan_name": {"type": "str", "source_key": "vlanName"},
                "vlan_id": {"type": "int", "source_key": "vlanId"},
                "traffic_type": {"type": "str", "source_key": "trafficType"},
                "pool_type": {"type": "str", "source_key": "poolType"},
                "security_group_name": {"type": "str", "source_key": "securityGroupName"},
                "is_critical_pool": {"type": "bool", "source_key": "isCriticalPool"},
                "layer2_flooding_enabled": {"type": "bool", "source_key": "isLayer2FloodingEnabled"},
                "fabric_enabled_wireless": {"type": "bool", "source_key": "isWirelessPool"},
                "is_wireless_flooding_enable": {"type": "bool", "source_key": "isWirelessFloodingEnabled"},
                "is_resource_guard_enable": {"type": "bool", "source_key": "isResourceGuardEnabled"},
                "ip_directed_broadcast": {"type": "bool", "source_key": "isIpDirectedBroadcast"},
                "intra_subnet_routing_enabled": {"type": "bool", "source_key": "isIntraSubnetRoutingEnabled"},
                "multiple_ip_to_mac_addresses": {"type": "bool", "source_key": "isMultipleIpToMacAddresses"},
                "supplicant_based_extended_node_onboarding": {"type": "bool", "source_key": "isSupplicantBasedExtendedNodeOnboarding"},
                "group_policy_enforcement_enabled": {"type": "bool", "source_key": "isGroupBasedPolicyEnforcementEnabled"},

                "fabric_site_location": {
                    "type": "dict",
                    "special_handling": True,
                    "transform": self.transform_anycast_fabric_site_location,
                    "site_name_hierarchy": {"type": "str"},
                    "fabric_type": {"type": "str"},
                },
            }
        )
        return anycast_gateway

    def get_fabric_vlans(self, network_element, component_specific_filters=None):
        """
        Retrieves fabric VLANs based on the provided network element and component-specific filters.
        Args:
            network_element (dict): A dictionary containing the API family and function for retrieving fabric VLANs.
            component_specific_filters (list, optional): A list of dictionaries containing filters for fabric VLANs.

        Returns:
            dict: A dictionary containing the modified details of fabric VLANs.
        """

        self.log(
            "Starting to retrieve fabric VLANs with network element: {0} and component-specific filters: {1}".format(
                network_element, component_specific_filters
            ),
            "DEBUG",
        )
        # Extract API family and function from network_element
        final_fabric_vlans = []
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting layer 2 fabric vlans using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        params = {}
        if component_specific_filters:
            for filter_param in component_specific_filters:
                for key, value in filter_param.items():
                    if key == "vlan_name":
                        params["vlanName"] = value
                    elif key == "vlan_id":
                        params["vlanId"] = value
                    else:
                        self.log(
                            "Ignoring unsupported filter parameter: {0}".format(key),
                            "DEBUG",
                        )
                    fabric_vlan_details = self.execute_get_with_pagination(
                        api_family, api_function, params
                    )
                    self.log("Retrieved fabric vlan details: {0}".format(fabric_vlan_details), "INFO")
                    final_fabric_vlans.extend(fabric_vlan_details)
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            # Execute API call to retrieve Interfaces details
            fabric_vlan_details = self.execute_get_with_pagination(
                api_family, api_function, params
            )
            self.log("Retrieved fabric vlan details: {0}".format(fabric_vlan_details), "INFO")
            final_fabric_vlans.extend(fabric_vlan_details)

        # Modify Fabric VLAN's details using temp_spec
        fabric_vlan_temp_spec = self.fabric_vlan_temp_spec()
        vlans_details = self.modify_parameters(
            fabric_vlan_temp_spec, final_fabric_vlans
        )
        modified_fabric_vlans_details = {}
        modified_fabric_vlans_details['fabric_vlan'] = vlans_details

        self.log(
            "Modified Fabric VLAN's details: {0}".format(
                modified_fabric_vlans_details
            ),
            "INFO",
        )

        return modified_fabric_vlans_details

    def get_virtual_networks(self, network_element, component_specific_filters=None):
        """
        Retrieves virtual networks based on the provided network element and component-specific filters.

        Args:
            network_element (dict): A dictionary containing the API family and function for retrieving virtual networks.
            component_specific_filters (list, optional): A list of dictionaries containing filters for virtual networks.

        Returns:
            dict: A dictionary containing the modified details of virtual networks.
        """

        self.log(
            "Starting to retrieve virtual networks with network element: {0} and component-specific filters: {1}".format(
                network_element, component_specific_filters
            ),
            "DEBUG",
        )
        final_virtual_networks = []
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting layer 2 virtual networks using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        params = {}
        if component_specific_filters:
            for filter_param in component_specific_filters:
                for key, value in filter_param.items():
                    if key == "vn_name":
                        params["virtualNetworkName"] = value
                    else:
                        self.log(
                            "Ignoring unsupported filter parameter: {0}".format(key),
                            "DEBUG",
                        )
                virtual_network_details = self.execute_get_with_pagination(
                    api_family, api_function, params
                )
                self.log("Retrieved virtual network details: {0}".format(virtual_network_details), "INFO")
                final_virtual_networks.extend(virtual_network_details)
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            # Execute API call to retrieve Virtual Networks details
            virtual_network_details = self.execute_get_with_pagination(
                api_family, api_function, params
            )
            self.log("Retrieved virtual network details: {0}".format(virtual_network_details), "INFO")
            final_virtual_networks.extend(virtual_network_details)

        # Modify Virtual Network's details using temp_spec
        virtual_network_temp_spec = self.virtual_network_temp_spec()
        vn_details = self.modify_parameters(
            virtual_network_temp_spec, final_virtual_networks
        )
        modified_virtual_networks_details = {}
        modified_virtual_networks_details['virtual_networks'] = vn_details

        self.log(
            "Modified Virtual Network's details: {0}".format(
                modified_virtual_networks_details
            ),
            "INFO",
        )

        return modified_virtual_networks_details

    def fetch_anycast_gateways_from_ccc(self, network_element, component_specific_filters=None):
        """
        Fetches anycast gateways from the Cisco DNA Center using the provided network element and component-specific filters.

        Args:
            network_element (dict): A dictionary containing the API family and function for retrieving anycast gateways.
            component_specific_filters (list, optional): A list of dictionaries containing filters for anycast gateways.

        Returns:
            dict: A dictionary containing the modified details of anycast gateways.
        """

        self.log(
            "Starting to retrieve anycast gateways with network element: {0} and component-specific filters: {1}".format(
                network_element, component_specific_filters
            ),
            "DEBUG",
        )
        final_anycast_gateways = []
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting anycast gateways using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        params = {}
        if component_specific_filters:
            for filter_param in component_specific_filters:
                params = {}
                for key, value in filter_param.items():
                    if key == "vn_name":
                        params["virtualNetworkName"] = value
                    elif key == "vlan_name":
                        params["vlanName"] = value
                    elif key == "ip_pool_name":
                        params["ipPoolName"] = value
                    else:
                        self.log(
                            "Ignoring unsupported filter parameter: {0}".format(key),
                            "DEBUG",
                        )
                anycast_gateway_details = self.execute_get_with_pagination(
                    api_family, api_function, params
                )
                self.log("Retrieved anycast gateway details: {0}".format(anycast_gateway_details), "INFO")
                final_anycast_gateways.extend(anycast_gateway_details)
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            # Execute API call to retrieve Anycast Gateways details
            anycast_gateway_details = self.execute_get_with_pagination(
                api_family, api_function, params
            )
            self.log("Retrieved anycast gateway details: {0}".format(anycast_gateway_details), "INFO")
            final_anycast_gateways.extend(anycast_gateway_details)

        # Modify Anycast Gateway's details using temp_spec
        anycast_gateway_temp_spec = self.anycast_gateway_temp_spec()
        anycast_gateways_details = self.modify_parameters(
            anycast_gateway_temp_spec, final_anycast_gateways
        )
        modified_anycast_gateways_details = {}
        modified_anycast_gateways_details["anycast_gateways"] = anycast_gateways_details

        self.log(
            "Modified Anycast Gateway's details: {0}".format(
                modified_anycast_gateways_details
            ),
            "INFO",
        )
        return modified_anycast_gateways_details

    def yaml_config_generator(self, yaml_config_generator):
        """
        Generates a YAML configuration file based on the provided parameters.
        This function retrieves network element details using global and component-specific filters, processes the data,
        and writes the YAML content to a specified file. It dynamically handles multiple network elements and their respective filters.

        Args:
            yaml_config_generator (dict): Contains file_path, global_filters, and component_specific_filters.

        Returns:
            self: The current instance with the operation result and message updated.
        """

        self.log(
            "Starting YAML config generation with parameters: {0}".format(
                yaml_config_generator
            ),
            "DEBUG",
        )
        file_path = yaml_config_generator.get("file_path", self.generate_filename())
        self.log("File path determined: {0}".format(file_path), "DEBUG")

        # Initialize global_filters and component_specific_filters as empty dictionaries if they are None
        global_filters = yaml_config_generator.get("global_filters") or {}

        component_specific_filters = (
            yaml_config_generator.get("component_specific_filters") or {}
        )
        self.log(
            "Global filters: {0}, Component-specific filters: {1}".format(
                global_filters, component_specific_filters
            ),
            "DEBUG",
        )

        # Retrieve the supported network elements for the module
        module_supported_network_elements = self.module_mapping.get(
            "network_elements", {}
        )
        components_list = component_specific_filters.get(
            "components_list", module_supported_network_elements.keys()
        )
        self.log("Components to process: {0}".format(components_list), "DEBUG")

        final_list = []
        for component in components_list:
            network_element = module_supported_network_elements.get(component)
            if not network_element:
                self.log(
                    "Skipping unsupported network element: {0}".format(component),
                    "WARNING",
                )
                continue

            filters = component_specific_filters.get(component, [])
            operation_func = network_element.get("get_function_name")
            if callable(operation_func):
                details = operation_func(network_element, filters)
                self.log(
                    "Details retrieved for {0}: {1}".format(component, details), "DEBUG"
                )
                final_list.append(details)

        if not final_list:
            self.msg = "No configurations or components to process for module '{0}'. Verify input filters or configuration.".format(
                self.module_name
            )
            self.set_operation_result("ok", False, self.msg, "INFO")
            return self

        final_dict = {"config": final_list}
        self.log("Final dictionary created: {0}".format(final_dict), "DEBUG")

        if self.write_dict_to_yaml(final_dict, file_path):
            self.msg = {
                "YAML config generation Task succeeded for module '{0}'.".format(
                    self.module_name
                ): {"file_path": file_path}
            }
            self.set_operation_result("success", True, self.msg, "INFO")
        else:
            self.msg = {
                "YAML config generation Task failed for module '{0}'.".format(
                    self.module_name
                ): {"file_path": file_path}
            }
            self.set_operation_result("failed", True, self.msg, "ERROR")

        return self

    def get_want(self, config, state):
        """
        Creates parameters for API calls based on the specified state.
        This method prepares the parameters required for adding, updating, or deleting
        network configurations such as SSIDs and interfaces in the Cisco Catalyst Center
        based on the desired state. It logs detailed information for each operation.

        Args:
            config (dict): The configuration data for the network elements.
            state (str): The desired state of the network elements ('merged' or 'deleted').
        """

        self.log(
            "Creating Parameters for API Calls with state: {0}".format(state), "INFO"
        )

        self.validate_params(config)

        want = {}

        # Add yaml_config_generator to want
        want["yaml_config_generator"] = config
        self.log(
            "yaml_config_generator added to want: {0}".format(
                want["yaml_config_generator"]
            ),
            "INFO",
        )

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
        self.msg = "Successfully collected all parameters from the playbook for Wireless Design operations."
        self.status = "success"
        return self

    def get_diff_merged(self):
        """
        Executes the merge operations for various network configurations in the Cisco Catalyst Center.
        This method processes additions and updates for SSIDs, interfaces, power profiles, access point profiles,
        radio frequency profiles, and anchor groups. It logs detailed information about each operation,
        updates the result status, and returns a consolidated result.
        """

        start_time = time.time()
        self.log("Starting 'get_diff_merged' operation.", "DEBUG")
        operations = [
            (
                "yaml_config_generator",
                "YAML Config Generator",
                self.yaml_config_generator,
            )
        ]

        # Iterate over operations and process them
        self.log("Beginning iteration over defined operations for processing.", "DEBUG")
        for index, (param_key, operation_name, operation_func) in enumerate(
            operations, start=1
        ):
            self.log(
                "Iteration {0}: Checking parameters for {1} operation with param_key '{2}'.".format(
                    index, operation_name, param_key
                ),
                "DEBUG",
            )
            params = self.want.get(param_key)
            if params:
                self.log(
                    "Iteration {0}: Parameters found for {1}. Starting processing.".format(
                        index, operation_name
                    ),
                    "INFO",
                )
                operation_func(params).check_return_status()
            else:
                self.log(
                    "Iteration {0}: No parameters found for {1}. Skipping operation.".format(
                        index, operation_name
                    ),
                    "WARNING",
                )

        end_time = time.time()
        self.log(
            "Completed 'get_diff_merged' operation in {0:.2f} seconds.".format(
                end_time - start_time
            ),
            "DEBUG",
        )

        return self


def main():
    """main entry point for module execution"""
    # Define the specification for the module"s arguments
    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": True},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged"]},
    }

    # Initialize the Ansible module with the provided argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=True)
    # Initialize the NetworkCompliance object with the module
    ccc_virtual_networks_playbook_generator = VirtualNetworksPlaybookGenerator(module)
    if (
        ccc_virtual_networks_playbook_generator.compare_dnac_versions(
            ccc_virtual_networks_playbook_generator.get_ccc_version(), "2.3.7.9"
        )
        < 0
    ):
        ccc_virtual_networks_playbook_generator.msg = (
            "The specified version '{0}' does not support the YAML Playbook generation "
            "for Wireless Design Module. Supported versions start from '2.3.7.9' onwards. "
            "Version '2.3.7.9' introduces APIs for retrieving the wireless settings for "
            "the following components: SSID(s), Interface(s), Power Profile(s), Access "
            "Point Profile(s), Radio Frequency Profile(s), Anchor Group(s) from the "
            "Catalyst Center".format(
                ccc_virtual_networks_playbook_generator.get_ccc_version()
            )
        )
        ccc_virtual_networks_playbook_generator.set_operation_result(
            "failed", False, ccc_virtual_networks_playbook_generator.msg, "ERROR"
        ).check_return_status()

    # Get the state parameter from the provided parameters
    state = ccc_virtual_networks_playbook_generator.params.get("state")

    # Check if the state is valid
    if state not in ccc_virtual_networks_playbook_generator.supported_states:
        ccc_virtual_networks_playbook_generator.status = "invalid"
        ccc_virtual_networks_playbook_generator.msg = "State {0} is invalid".format(
            state
        )
        ccc_virtual_networks_playbook_generator.check_return_status()

    # Validate the input parameters and check the return statusk
    ccc_virtual_networks_playbook_generator.validate_input().check_return_status()
    config = ccc_virtual_networks_playbook_generator.validated_config
    if len(config) == 1 and config[0].get("component_specific_filters") is None:
        ccc_virtual_networks_playbook_generator.msg = (
            "No valid configurations found in the provided parameters."
        )
        ccc_virtual_networks_playbook_generator.validated_config = [
            {
                'component_specific_filters':
                {
                    'components_list': ["fabric_vlan", "virtual_networks", "anycast_gateways"]
                }
            }
        ]

    # Iterate over the validated configuration parameters
    for config in ccc_virtual_networks_playbook_generator.validated_config:
        ccc_virtual_networks_playbook_generator.reset_values()
        ccc_virtual_networks_playbook_generator.get_want(
            config, state
        ).check_return_status()
        ccc_virtual_networks_playbook_generator.get_diff_state_apply[
            state
        ]().check_return_status()

    module.exit_json(**ccc_virtual_networks_playbook_generator.result)


if __name__ == "__main__":
    main()
