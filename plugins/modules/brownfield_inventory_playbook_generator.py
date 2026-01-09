#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to generate YAML configurations for Wired Campus Automation Module."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Mridul Saurabh, Madhan Sankaranarayanan"

DOCUMENTATION = r"""
---
module: <brownfield_inventory_playbook_generator>
short_description: Generate YAML configurations playbook for 'inventory_workflow_manager' module.
description:
- Generates YAML configurations compatible with the '<inventory_workflow_manager>'
  module, reducing the effort required to manually create Ansible playbooks and
  enabling programmatic modifications.
version_added: 6.17.0
extends_documentation_fragment:
- cisco.dnac.workflow_manager_params
author:
- Mridul Saurabh (@msaurabh)
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
    - A list of filters for generating YAML playbook compatible with the `<module_name>`
      module.
    - Filters specify which components to include in the YAML configuration file.
    - If "components_list" is specified, only those components are included, regardless of the filters.
    type: list
    elements: dict
    required: true
    suboptions:
      generate_all_configurations:
        description:
          - When set to True, automatically generates YAML configurations for all devices and all supported features.
          - This mode discovers all managed devices in Cisco Catalyst Center and extracts all supported configurations.
          - When enabled, the config parameter becomes optional and will use default values if not provided.
          - A default filename will be generated automatically if file_path is not specified.
          - This is useful for complete brownfield infrastructure discovery and documentation.
        type: bool
        required: false
        default: false
      file_path:
        description:
        - Path where the YAML configuration file will be saved.
        - If not provided, the file will be saved in the current working directory with
          a default file name  "<module_name>_playbook_<DD_Mon_YYYY_HH_MM_SS_MS>.yml".
        - For example, "<module_name>_playbook_22_Apr_2025_21_43_26_379.yml".
        type: str
      global_filters:
        description:
        - Global filters to apply when generating the YAML configuration file.
        - These filters apply to all components unless overridden by component-specific filters.
        type: dict
        suboptions:
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
"""

EXAMPLES = r"""

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


class InventoryPlaybookGenerator(DnacBase, BrownFieldHelper):
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
        self.supported_states = ["gathered"]
        super().__init__(module)
        self.module_schema = self.get_workflow_filters_schema()
        # self.site_id_name_dict = self.get_site_id_name_mapping()
        self.module_name = "inventory_workflow_manager"

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
            "generate_all_configurations": {"type": "bool", "required": False, "default": False},
            "file_path": {"type": "str", "required": False},
            "component_specific_filters": {"type": "dict", "required": False},
            "global_filters": {"type": "dict", "required": False},
        }

        # Import validate_list_of_dicts function here to avoid circular imports
        from ansible_collections.cisco.dnac.plugins.module_utils.dnac import validate_list_of_dicts

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

    def get_workflow_filters_schema(self):
        """
        Description: Returns the schema for workflow filters supported by the module.
        Returns:
            dict: A dictionary representing the schema for workflow filters.
        """
        self.log("Inside get_workflow_filters_schema function.", "DEBUG")
        return {
            "network_elements": {
                "inventory_workflow_manager": {
                    "filters" : ["ip_address"],
                    "api_function":"get_device_list",
                    "api_family": "devices",
                    "reverse_mapping_function": self.inventory_get_device_reverse_mapping,
                    "get_function_name": self.get_inventory_workflow_manager_details,  
                }
            },
            "global_filters": {
                "ip_address_list": {
                    "type": "list",
                    "required": False,
                    "elements": "str",
                    "validate_ip": True,
                },
                "hostname_list": {"type": "list", "required": False, "elements": "str"},
                "serial_number_list": {
                    "type": "list",
                    "required": False,
                    "elements": "str",
                },
            },
        }

    def process_global_filters(self, global_filters):
        pass

    def inventory_get_device_reverse_mapping(self):
        """
        Returns reverse mapping specification for inventory devices.
        Transforms API response from credential API back to inventory_workflow_manager format.
        """
        return OrderedDict({
            "ip_address_list": {
                "type": "list",
                "elements": "str",
                "source_key": "ipAddress",
                "transform": self.transform_ip_address_list
            },
            "cli_transport": {
                "type": "str",
                "source_key": "cliTransport",
                "transform": lambda x: x.lower() if x else None
            },
            "compute_device": {
                "type": "bool",
                "source_key": "computeDevice",
                "transform": lambda x: x if isinstance(x, bool) else x.lower() == "true"
            },
            "password": {
                "type": "str",
                "source_key": "password",
                "transform": lambda x: x if x else None
            },
            "enable_password": {
                "type": "str",
                "source_key": "enablePassword",
                "transform": lambda x: x if x else None
            },
            "extended_discovery_info": {
                "type": "str",
                "source_key": "extendedDiscoveryInfo",
                "transform": lambda x: x if x else None
            },
            "http_username": {
                "type": "str",
                "source_key": "httpUserName",
                "transform": lambda x: x if x else None
            },
            "http_password": {
                "type": "str",
                "source_key": "httpPassword",
                "transform": lambda x: x if x else None
            },
            "http_port": {
                "type": "str",
                "source_key": "httpPort",
                "transform": lambda x: str(x) if x else None
            },
            "http_secure": {
                "type": "bool",
                "source_key": "httpSecure",
                "transform": lambda x: x if isinstance(x, bool) else x.lower() == "true"
            },
            "netconf_port": {
                "type": "int",
                "source_key": "netconfPort",
                "transform": lambda x: int(x) if x else None
            },
            "snmp_auth_passphrase": {
                "type": "str",
                "source_key": "snmpAuthPassphrase",
                "transform": lambda x: x if x else None
            },
            "snmp_auth_protocol": {
                "type": "str",
                "source_key": "snmpAuthProtocol",
                "transform": lambda x: x.upper() if x else None
            },
            "snmp_mode": {
                "type": "str",
                "source_key": "snmpMode",
                "transform": lambda x: x.upper() if x else None
            },
            "snmp_priv_passphrase": {
                "type": "str",
                "source_key": "snmpPrivPassphrase",
                "transform": lambda x: x if x else None
            },
            "snmp_priv_protocol": {
                "type": "str",
                "source_key": "snmpPrivProtocol",
                "transform": lambda x: x.upper() if x else None
            },
            "snmp_ro_community": {
                "type": "str",
                "source_key": "snmpROCommunity",
                "transform": lambda x: x if x else None
            },
            "snmp_rw_community": {
                "type": "str",
                "source_key": "snmpRWCommunity",
                "transform": lambda x: x if x else None
            },
            "snmp_retry": {
                "type": "int",
                "source_key": "snmpRetry",
                "transform": lambda x: int(x) if x else None
            },
            "snmp_timeout": {
                "type": "int",
                "source_key": "snmpTimeout",
                "transform": lambda x: int(x) if x else None
            },
            "snmp_username": {
                "type": "str",
                "source_key": "snmpUserName",
                "transform": lambda x: x if x else None
            },
            "snmp_version": {
                "type": "str",
                "source_key": "snmpVersion",
                "transform": lambda x: x.lower() if x else None
            },
            "type": {
                "type": "str",
                "source_key": "type",
                "transform": lambda x: x if x else "NETWORK_DEVICE"
            },
            "username": {
                "type": "str",
                "source_key": "userName",
                "transform": lambda x: x if x else None
            }
        })

    def transform_ip_address_list(self, api_value):
        """
        Transform API ipAddress to ip_address_list format.
        Ensures it's always returned as a list.
        """
        if not api_value:
            return []
        if isinstance(api_value, list):
            return api_value
        return [api_value]

    def get_inventory_workflow_manager_details(self, network_element, filters):
        """
        Retrieves inventory device credentials from Cisco Catalyst Center API.
        Processes the response and transforms it using the reverse mapping specification.
        
        Args:
            network_element (dict): Network element configuration containing API details
            filters (dict): Filters containing global_filters and component_specific_filters
            
        Returns:
            list: List of processed device credential configurations
        """
        self.log("Starting get_inventory_workflow_manager_details", "INFO")
        self.log("Network element configuration: {0}".format(network_element), "DEBUG")
        self.log("Applied filters: {0}".format(filters), "DEBUG")
        
        try:
            # Get reverse mapping specification
            reverse_mapping_spec = self.inventory_get_device_reverse_mapping()
            self.log("Reverse mapping spec retrieved", "DEBUG")
            
            # Process global filters to obtain device IP to ID mapping
            self.log("Processing global filters to obtain device details", "DEBUG")
            global_filters = filters.get("global_filters", {})
            
            # Check if this is generate_all_configurations mode
            if self.generate_all_configurations:
                self.log(
                    "Generate all configurations mode detected - retrieving all managed devices",
                    "INFO",
                )
                # Get all devices without any parameters to retrieve everything
                device_ip_to_id_mapping = self.get_network_device_details()
            else:
                processed_global_filters = self.process_global_filters(global_filters)
                device_ip_to_id_mapping = processed_global_filters.get(
                    "device_ip_to_id_mapping", {}
                )
                
                # If no device filters provided, get all devices
                if not device_ip_to_id_mapping and not any(
                    [
                        global_filters.get("ip_address_list"),
                        global_filters.get("hostname_list"),
                        global_filters.get("serial_number_list"),
                    ]
                ):
                    self.log(
                        "No device filters provided - retrieving all managed devices",
                        "INFO",
                    )
                    device_ip_to_id_mapping = self.get_network_device_details()
            
            if not device_ip_to_id_mapping:
                self.log("No devices found from global filters. Terminating retrieval.", "WARNING")
                return []
            
            self.log(
                "Found {0} devices to process from global filters".format(
                    len(device_ip_to_id_mapping)
                ),
                "INFO",
            )
            
            # Extract device details from the mapping
            device_response = []
            for device_ip, device_info in device_ip_to_id_mapping.items():
                device_response.append(device_info)
            
            self.log("Device details retrieved: {0} devices".format(len(device_response)), "INFO")
            
            if not device_response:
                self.log("No device details found", "WARNING")
                return []
            
            # Transform the response using modify_parameters
            transformed_devices = self.modify_parameters(reverse_mapping_spec, device_response)
            self.log("Devices transformed successfully: {0} devices".format(len(transformed_devices)), "INFO")
            
            return transformed_devices
            
        except Exception as e:
            self.log("Error in get_inventory_workflow_manager_details: {0}".format(str(e)), "ERROR")
            return []

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

        # Check if generate_all_configurations mode is enabled
        generate_all = yaml_config_generator.get("generate_all_configurations", False)
        if generate_all:
            self.log("Auto-discovery mode enabled - will process all devices and all features", "INFO")

        self.log("Determining output file path for YAML configuration", "DEBUG")
        file_path = yaml_config_generator.get("file_path")
        if not file_path:
            self.log("No file_path provided by user, generating default filename", "DEBUG")
            file_path = self.generate_filename()
        else:
            self.log("Using user-provided file_path: {0}".format(file_path), "DEBUG")

        self.log("YAML configuration file path determined: {0}".format(file_path), "DEBUG")

        self.log("Initializing filter dictionaries", "DEBUG")
        if generate_all:
            # In generate_all_configurations mode, override any provided filters to ensure we get ALL configurations
            self.log("Auto-discovery mode: Overriding any provided filters to retrieve all devices and all features", "INFO")
            if yaml_config_generator.get("global_filters"):
                self.log("Warning: global_filters provided but will be ignored due to generate_all_configurations=True", "WARNING")
            if yaml_config_generator.get("component_specific_filters"):
                self.log("Warning: component_specific_filters provided but will be ignored due to generate_all_configurations=True", "WARNING")
            
            # Set empty filters to retrieve everything
            global_filters = {}
            component_specific_filters = {}
        else:
            # Use provided filters or default to empty
            global_filters = yaml_config_generator.get("global_filters") or {}
            component_specific_filters = yaml_config_generator.get("component_specific_filters") or {}

        # Retrieve the supported network elements for the module
        module_supported_network_elements = self.module_schema.get(
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
    ccc_inventory_playbook_generator = InventoryPlaybookGenerator(module)
    if (
        ccc_inventory_playbook_generator.compare_dnac_versions(
            ccc_inventory_playbook_generator.get_ccc_version(), "2.3.7.9"
        )
        < 0
    ):
        ccc_inventory_playbook_generator.msg = (
            "The specified version '{0}' does not support the YAML Playbook generation "
            "for INVENTORY Module. Supported versions start from '2.3.7.9' onwards. ".format(
                ccc_inventory_playbook_generator.get_ccc_version()
            )
        )
        ccc_inventory_playbook_generator.set_operation_result(
            "failed", False, ccc_inventory_playbook_generator.msg, "ERROR"
        ).check_return_status()

    # Get the state parameter from the provided parameters
    state = ccc_inventory_playbook_generator.params.get("state")

    # Check if the state is valid
    if state not in ccc_inventory_playbook_generator.supported_states:
        ccc_inventory_playbook_generator.status = "invalid"
        ccc_inventory_playbook_generator.msg = "State {0} is invalid".format(
            state
        )
        ccc_inventory_playbook_generator.check_recturn_status()

    # Validate the input parameters and check the return statusk
    ccc_inventory_playbook_generator.validate_input().check_return_status()
    config = ccc_inventory_playbook_generator.validated_config
    if len(config) == 1 and config[0].get("component_specific_filters") is None:
        ccc_inventory_playbook_generator.msg = (
            "No valid configurations found in the provided parameters."
        )
        ccc_inventory_playbook_generator.validated_config = [
            {
                'component_specific_filters':
                {
                    'components_list': []
                }
            }
        ]

    # Iterate over the validated configuration parameters
    for config in ccc_inventory_playbook_generator.validated_config:
        ccc_inventory_playbook_generator.reset_values()
        ccc_inventory_playbook_generator.get_want(
            config, state
        ).check_return_status()
        ccc_inventory_playbook_generator.get_diff_state_apply[
            state
        ]().check_return_status()

    module.exit_json(**ccc_inventory_playbook_generator.result)


if __name__ == "__main__":
    main()