#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to manage Extranet Policy Operations in SD-Access Fabric in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Rugvedi Kapse, Madhan Sankaranarayanan"

DOCUMENTATION = r"""
---
module: wireless_design_workflow_playbook_generator
short_description: Generate YAML playbook for 'wireless_design_workflow_manager' module.
description:
- Generates YAML configurations compatible with the `wireless_design_workflow_manager`
  module, reducing the effort required to manually create Ansible playbooks and 
  enabling programmatic modifications.
- The YAML configurations generated represent the wireless settings configured on
  the Cisco Catalyst Center.
version_added: 6.17.0
extends_documentation_fragment:
- cisco.dnac.workflow_manager_params
author:
- Rugvedi Kapse (@rukapse)
- Madhan Sankaranarayanan (@madhansansel)
options:
  state:
    description: The desired state of Cisco Catalyst Center after module execution.
    type: str
    choices: [merged]
    default: merged
  config:
    description:
    - A list of filters for generating YAML playbook compatible with the `wireless_design_workflow_manager`
      module.
    - Filters specify which components to include in the YAML configuration file.
    - If "components_list" is specified, only those components are included, regardless of the filters.
    type: list
    elements: dict
    required: true
    suboptions:
      file_path:
        description:
        - Path where the YAML configuration file will be saved.
        - If not provided, the file will be saved in the current working directory with
          a default file name  "<module_name>_playbook_<DD_Mon_YYYY_HH_MM_SS_MS>.yml".
        - For example, "wireless_design_workflow_manager_playbook_22_Apr_2025_21_43_26_379.yml".
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
              - Wireless SSIDs "ssids"
              - Anchor Groups "anchor_groups"
              - Power Profiles "power_profiles" 
              - Access Point Profiles "ap_profiles"
              - Radio Frequency Profiles "rf_profiles" 
              - Interfaces "interfaces"
            - If not specified, all components are included.
            - For example, ["ssids", "anchor_groups", "power_profiles", "ap_profiles",
                "rf_profiles", "interfaces"].
            type: list
            elements: str
          site_name_hierarchy:
            description:
            - Site name hierarchy to filter ssids by site name hierarchy.
            type: str
          ssids_names_list:
            description:
            - List of SSID names to filter ssids.
            type: list
            elements: str
          interface_names_list:
            description:
            - List of interface names to filter interfaces.
            type: list
            elements: str
          power_profile_names_list:
            description:
            - List of power profile names to filter power profiles.
            type: list
            elements: str
          access_point_profile_names_list:
            description:
            - List of access point profile names to filter access point profiles.
            type: list
            elements: str
          radio_frequency_profile_names_list:
            description:
            - List of radio frequency profile names to filter radio frequency profiles.
            type: list
            elements: str
requirements:
- dnacentersdk >= 2.10.3
- python >= 3.9
notes:
- SDK Methods used are - sites.Sites.get_site - site_design.SiteDesigns.get_sites
  - wirelesss.Wireless.get_ssid_by_site - wirelesss.Wireless.get_interfaces - wirelesss.Wireless.get_power_profiles
  - wirelesss.Wireless.get_ap_profiles - wirelesss.Wireless.get_rf_profiles - wirelesss.Wireless.get_anchor_groups
- Paths used are - GET /dna/intent/api/v1/sites - GET /dna/intent/api/v1/sites/${siteId}/wirelessSettings/ssids
  - GET /dna/intent/api/v1/wirelessSettings/interfaces - GET /dna/intent/api/v1/wirelessSettings/powerProfiles
  - GET /dna/intent/api/v1/wirelessSettings/apProfiles - GET /dna/intent/api/v1/wirelessSettings/rfProfiles
  - GET /dna/intent/api/v1/wirelessSettings/anchorGroups
"""

EXAMPLES = r"""
- name: Generate YAML Configuration with File Path specified
  cisco.dnac.wireless_design_workflow_manager:
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
      file_path: "/tmp/catc_wireless_components_config.yaml"
- name: Generate YAML Configuration with specific wireless network components only
  cisco.dnac.wireless_design_workflow_manager:
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
      file_path: "/tmp/catc_wireless_components_config.yaml"
      component_specific_filters:
        components_list: ["interfaces", "anchor_groups"]
- name: Generate YAML Configuration for wireless SSIDs with site filter
  cisco.dnac.wireless_design_workflow_manager:
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
      file_path: "/tmp/catc_wireless_components_config.yaml"
      component_specific_filters:
        components_list: ["ssids"]
        site_name_hierarchy: "Global/USA/San Jose"
- name: Generate YAML Configuration with multiple filters
  cisco.dnac.wireless_design_workflow_manager:
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
      file_path: "/tmp/catc_wireless_components_config.yaml"
      component_specific_filters:
        ssid_names_list: ["lab_wifi", "enterprise_secure", "guest_wifi"]
        interface_names_list: ["data", "voice"]
        power_profile_names_list: ["EthernetSpeeds", "EthernetState"]
        access_point_profile_names_list: ["Warehouse-AP", "Default_AP_Profile_AireOS"]
        radio_frequency_profile_names_list: ["rf_profile_2_4_5_6ghz_high_low", "rf_profile_5ghz_basic"]
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
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
import datetime
import yaml
from collections import OrderedDict
import os


class OrderedDumper(yaml.Dumper):
    def represent_dict(self, data):
        return self.represent_mapping("tag:yaml.org,2002:map", data.items())


OrderedDumper.add_representer(OrderedDict, OrderedDumper.represent_dict)


class WirelessDesignPlaybookGenerator(DnacBase):
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
        self.module_mapping = self.wireless_design_workflow_manager_mapping()
        self.module_name = "wireless_design_workflow_manager"

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

    def wireless_design_workflow_manager_mapping(self):
        """
        Returns the mapping for the 'wireless_design_workflow_manager' module.
        """
        return {
            "network_elements": {
                "ssids": {
                    "filters": ["site_name_hierarchy", "ssid_names_list"],
                    "temp_spec_function": self.wireless_ssid_temp_spec,
                    "api_function": "get_ssid_by_site",
                    "api_family": "wireless",
                    "get_function_name": self.get_wireless_ssids,
                },
                "interfaces": {
                    "filters": ["interface_names_list"],
                    "temp_spec_function": self.wireless_interfaces_temp_spec,
                    "api_function": "get_interfaces",
                    "api_family": "wireless",
                    "get_function_name": self.get_wireless_interfaces,
                },
                "power_profiles": {
                    "filters": ["power_profile_names_list"],
                    "temp_spec_function": self.wireless_power_profiles_temp_spec,
                    "api_function": "get_power_profiles",
                    "api_family": "wireless",
                    "get_function_name": self.get_wireless_power_profiles,
                },
                "access_point_profiles": {
                    "filters": ["access_point_profile_names_list"],
                    "temp_spec_function": self.wireless_access_point_profiles_temp_spec,
                    "api_function": "get_ap_profiles",
                    "api_family": "wireless",
                    "get_function_name": self.get_wireless_access_point_profiles,
                },
                "radio_frequency_profiles": {
                    "filters": ["radio_frequency_profile_names_list"],
                    "temp_spec_function": self.wireless_radio_frequency_profiles_temp_spec,
                    "api_function": "get_rf_profiles",
                    "api_family": "wireless",
                    "get_function_name": self.get_wireless_radio_frequency_profiles,
                },
                "anchor_groups": {
                    "filters": [],
                    "temp_spec_function": self.wireless_anchor_groups_temp_spec,
                    "api_function": "get_anchor_groups",
                    "api_family": "wireless",
                    "get_function_name": self.get_wireless_anchor_groups,
                },
            },
            "global_filters": [],
        }

    def execute_get_with_pagination(self, api_family, api_function, params):
        """
        Executes a paginated GET request using the specified API family, function, and parameters.
        Args:
            api_family (str): The API family to use for the call (For example, 'wireless', 'network', etc.).
            api_function (str): The specific API function to call for retrieving data (For example, 'get_ssid_by_site', 'get_interfaces').
            params (dict): Parameters for filtering the data.
        Returns:
            list: A list of dictionaries containing the retrieved data based on the filtering parameters.
        """

        def update_params(offset, limit, use_strings=False):
            """Update the params dictionary with pagination info."""
            params.update(
                {
                    "offset": str(offset) if use_strings else offset,
                    "limit": str(limit) if use_strings else limit,
                }
            )

        try:
            # Initialize pagination variables
            offset = 1
            limit = 500
            results = []
            use_strings = api_function in {"get_ap_profiles", "get_anchor_groups"}

            # Start the loop for paginated API calls
            while True:
                # Update parameters for pagination
                update_params(offset, limit, use_strings)

                try:
                    # Execute the API call
                    self.log(
                        "Attempting API call with {0} offset and limit for family '{1}', function '{2}': {3}".format(
                            "string" if use_strings else "integer",
                            api_family,
                            api_function,
                            params,
                        ),
                        "INFO",
                    )

                    # Execute the API call
                    response = self.dnac._exec(
                        family=api_family,
                        function=api_function,
                        op_modifies=False,
                        params=params,
                    )

                except Exception as e:
                    # Retry with integer offset/limit for specific cases
                    if api_function == "get_ap_profiles" and use_strings:
                        self.log(
                            "API call failed with string offset and limit. Retrying with integer values. Error: {0}".format(
                                str(e)
                            ),
                            "WARNING",
                        )
                        use_strings = False
                        continue

                    else:
                        self.msg = (
                            "An error occurred while retrieving data using family '{0}', function '{1}'. "
                            "Details using API call. Error: {2}".format(
                                api_family, api_function, str(e)
                            )
                        )
                        self.fail_and_exit(self.msg)

                self.log(
                    "Response received from API call for family '{0}', function '{1}': {2}".format(
                        api_family, api_function, response
                    ),
                    "INFO",
                )

                # Process the response if available
                response = response.get("response")
                if not response:
                    self.log(
                        "Exiting the loop because no data was returned after increasing the offset. "
                        "Current offset: {0}".format(offset),
                        "INFO",
                    )
                    break

                # Extend the results list with the response data
                results.extend(response)

                # Check if the response size is less than the limit
                if len(response) < limit:
                    self.log(
                        "Received less than limit ({0}) results, assuming last page. Exiting pagination.".format(
                            limit
                        ),
                        "DEBUG",
                    )
                    break

                # Increment the offset for the next iteration
                offset += limit

            if results:
                self.log(
                    "Data retrieved for family '{0}', function '{1}': {2}".format(
                        api_family, api_function, results
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "No data found for family '{0}', function '{1}'.".format(
                        api_family, api_function
                    ),
                    "DEBUG",
                )

            # Return the list of retrieved data
            return results

        except Exception as e:
            self.msg = (
                "An error occurred while retrieving data using family '{0}', function '{1}'. "
                "Details using API call. Error: {2}".format(
                    api_family, api_function, str(e)
                )
            )
            self.fail_and_exit(self.msg)

    def get_global_site_details(self):
        """
        Retrieves details for the global site.
        Assumes the global site always exists.
        Returns:
            str: Global site ID.
        """
        global_site_name = "Global"
        self.log(
            "Fetching details for global site: {0}".format(global_site_name), "INFO"
        )

        # Directly retrieve the global site ID
        global_site_id = self.get_site_id(global_site_name)[1]

        self.log("Global site found with ID: {0}".format(global_site_id), "DEBUG")

        return global_site_id

    def validate_global_filters(self, global_filters):
        """
        Validates the provided global filters against the valid global filters for the current module.
        Args:
            module_name (str): The name of the module for which filters are being validated.
            global_filters (dict): The global filters to be validated.
        Returns:
            bool: True if all filters are valid, False otherwise.
        """
        # Log the start of the validation process, indicating the module being validated
        self.log(
            "Starting validation of global filters for module: {0}".format(
                self.module_name
            ),
            "INFO",
        )

        # Retrieve the valid global filters from the module mapping, defaulting to an empty list if not found
        valid_global_filters = self.module_mapping.get("global_filters", [])
        # Check if the module does not support global filters but global filters are provided
        if not valid_global_filters and global_filters:
            self.msg = "Module '{0}' does not support global filters, but 'global_filters' were provided: {1}. Please remove them.".format(
                self.module_name, list(global_filters.keys())
            )
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        self.log(
            "Valid global filters for module '{0}': {1}".format(
                self.module_name, valid_global_filters
            ),
            "DEBUG",
        )

        # Check each filter in the provided global filters against the list of valid filters
        invalid_filters = [
            key for key in global_filters.keys() if key not in valid_global_filters
        ]

        # If any invalid filters are found, log the error and exit the operation
        if invalid_filters:
            self.msg = "Invalid 'global_filters' found for module '{0}': {1}. Valid 'global_filters' are: {2}".format(
                self.module_name, invalid_filters, valid_global_filters
            )
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        # Log the successful validation of all filters
        self.log(
            "All global filters for module '{0}' are valid.".format(self.module_name),
            "INFO",
        )
        return True

    def validate_component_specific_filters(self, component_specific_filters):
        """
        Validates component-specific filters for the given module.
        Args:
            component_specific_filters (dict): User-provided component-specific filters.
        Returns:
            bool: True if all filters are valid, False otherwise.
        """
        # Log the start of component-specific filter validation
        self.log(
            "Validating 'component_specific_filters' for module: {0}".format(
                self.module_name
            ),
            "INFO",
        )

        # Retrieve network elements for the module
        module_info = self.module_mapping
        self.log("Module info: {0}".format(module_info), "DEBUG")
        network_elements = module_info.get("network_elements", {})
        self.log("Network elements: {0}".format(network_elements), "DEBUG")

        if not network_elements:
            # Exit if no network elements are defined for the module
            self.msg = "'component_specific_filters' are not supported for module '{0}'.".format(
                self.module_name
            )
            self.fail_and_exit(self.msg)

        # Retrieve components_list from the filters
        components_list = component_specific_filters.get("components_list", [])

        # Validate components_list
        invalid_components = [
            component
            for component in components_list
            if component not in network_elements
        ]
        if invalid_components:
            self.msg = "Invalid network components provided for module '{0}': {1}. Valid components are: {2}".format(
                self.module_name, invalid_components, list(network_elements.keys())
            )
            self.fail_and_exit(self.msg)

        # Gather all valid filters from network elements
        valid_filters = []
        for element, details in network_elements.items():
            valid_filters.extend(details.get("filters", []))

        self.log(
            "Valid filters for module '{0}': {1}".format(
                self.module_name, valid_filters
            ),
            "DEBUG",
        )

        # Validate provided filters against valid filters list
        invalid_filters = [
            filter_name
            for filter_name in component_specific_filters.keys()
            if filter_name != "components_list" and filter_name not in valid_filters
        ]

        if invalid_filters:
            self.msg = "Invalid filters provided for module '{0}': {1}. Valid filters are: {2}".format(
                self.module_name, invalid_filters, valid_filters
            )
            self.fail_and_exit(self.msg)

        # Log the successful validation of component-specific filters
        self.log(
            "All component-specific filters for module '{0}' are valid.".format(
                self.module_name
            ),
            "INFO",
        )
        return True

    def validate_params(self, config):
        """
        Validates the parameters provided for the YAML configuration generator.
        Args:
            config (dict): A dictionary containing the configuration parameters
                for the YAML configuration generator. It may include:
                - "global_filters": A dictionary of global filters to validate.
                - "component_specific_filters": A dictionary of component-specific filters to validate.
            state (str): The state of the operation, e.g., "merged" or "deleted".
        """
        self.log("Starting validation of the input parameters.", "INFO")
        self.log(self.module_mapping)

        # Validate global_filters if provided
        global_filters = config.get("global_filters")
        if global_filters:
            self.log(
                "Validating 'global_filters' for module '{0}': {1}.".format(
                    self.module_name, global_filters
                ),
                "INFO",
            )
            self.validate_global_filters(global_filters)
        else:
            self.log(
                "No 'global_filters' provided for module '{0}'; skipping validation.".format(
                    self.module_name
                ),
                "INFO",
            )

        # Validate component_specific_filters if provided
        component_specific_filters = config.get("component_specific_filters")
        if component_specific_filters:
            self.log(
                "Validating 'component_specific_filters' for module '{0}': {1}.".format(
                    self.module_name, component_specific_filters
                ),
                "INFO",
            )
            self.validate_component_specific_filters(component_specific_filters)
        else:
            self.log(
                "No 'component_specific_filters' provided for module '{0}'; skipping validation.".format(
                    self.module_name
                ),
                "INFO",
            )

        self.log("Completed validation of all input parameters.", "INFO")

    def generate_filename(self):
        """
        Generates a filename for the module with a timestamp and '.yml' extension in the format 'DD_Mon_YYYY_HH_MM_SS_MS'.
        Args:
            module_name (str): The name of the module for which the filename is generated.
        Returns:
            str: The generated filename with the format 'module_name_playbook_timestamp.yml'.
        """
        self.log("Starting the filename generation process.", "INFO")

        # Get the current timestamp in the desired format
        timestamp = datetime.datetime.now().strftime("%d_%b_%Y_%H_%M_%S_%f")[:-3]
        self.log("Timestamp successfully generated: {0}".format(timestamp), "DEBUG")

        # Construct the filename
        filename = "{0}_playbook_{1}.yml".format(self.module_name, timestamp)
        self.log("Filename successfully constructed: {0}".format(filename), "DEBUG")

        self.log(
            "Filename generation process completed successfully: {0}".format(filename),
            "INFO",
        )
        return filename

    def ensure_directory_exists(self, file_path):
        """Ensure the directory for the file path exists."""
        self.log(
            "Starting 'ensure_directory_exists' for file path: {0}".format(file_path),
            "INFO",
        )

        # Extract the directory from the file path
        directory = os.path.dirname(file_path)
        self.log("Extracted directory: {0}".format(directory), "DEBUG")

        # Check if the directory exists
        if directory and not os.path.exists(directory):
            self.log(
                "Directory '{0}' does not exist. Creating it.".format(directory), "INFO"
            )
            os.makedirs(directory)
            self.log("Directory '{0}' created successfully.".format(directory), "INFO")
        else:
            self.log(
                "Directory '{0}' already exists. No action needed.".format(directory),
                "INFO",
            )

    def process_boolean_to_list(self, ssid_details, mapping):
        """
        Processes a mapping of boolean keys to list values and returns a list of keys where the corresponding boolean is True.
        """
        self.log(
            "Starting process_boolean_to_list with ssid_details: {0}".format(
                ssid_details
            ),
            "DEBUG",
        )
        result = []
        for list_value, boolean_key in mapping.items():
            boolean_value = ssid_details.get(boolean_key, False)
            self.log(
                "Checking key '{0}': {1}".format(boolean_key, boolean_value), "DEBUG"
            )
            if boolean_value:  # Check if the boolean key is True
                result.append(list_value)
        self.log("Resulting list: {0}".format(result), "DEBUG")
        return result

    def generate_custom_variable_name(
        self,
        network_component_details,
        network_component,
        network_component_name_parameter,
        parameter,
    ):
        """
        Generates a custom variable name for a given network component, component name, and parameter.
        Args:
            network_component (str): The type of network component (e.g., "ssid", "mpsk").
            network_component_name (str): The name of the network component (e.g., SSID name).
            parameter (str): The parameter for which the variable is being generated (e.g., "passphrase").
        Returns:
            str: The generated custom variable name.
        """
        # Generate the custom variable name
        self.log(
            "Generating custom variable name for network component: {0}".format(
                network_component
            ),
            "DEBUG",
        )
        self.log(
            "Network component details: {0}".format(network_component_details), "DEBUG"
        )
        self.log(
            "Network component name parameter: {0}".format(
                network_component_name_parameter
            ),
            "DEBUG",
        )
        self.log("Parameter: {0}".format(parameter), "DEBUG")
        variable_name = "{{ {0}_{1}_{2} }}".format(
            network_component,
            network_component_details[network_component_name_parameter],
            parameter,
        )
        custom_variable_name = "{" + variable_name + "}"
        self.log(
            "Generated custom variable name: {0}".format(custom_variable_name), "DEBUG"
        )
        return custom_variable_name

    def get_ssids_params(
        self,
        site_id,
        ssid_name=None,
        ssid_type=None,
        l2_auth_type=None,
        l3_auth_type=None,
    ):
        """
        Generates the parameters for retrieving SSIDs, mapping optional user parameters
        to the API's expected parameter names.
        """
        # Initialize the parameters dictionary with the required site_id
        get_ssids_params = {"site_id": site_id}
        self.log("Initialized parameters dictionary for API call.", "DEBUG")

        # Map optional parameters dynamically
        param_mapping = {
            "ssid_name": "ssid",
            "ssid_type": "wlanType",
            "l2_auth_type": "authType",
            "l3_auth_type": "l3AuthType",
        }

        for param, api_key in param_mapping.items():
            value = locals().get(param)  # Dynamically get the value of the parameter
            if value:
                get_ssids_params[api_key] = value
                self.log(f"Mapped '{param}' to '{value}'.", "DEBUG")

        self.log(f"Constructed get_ssids_params: {get_ssids_params}", "DEBUG")
        return get_ssids_params

    def wireless_ssid_temp_spec(self):
        wireless_ssid_temp_spec = OrderedDict(
            {
                "ssid_name": {"type": "str", "source_key": "ssid"},
                "wlan_profile_name": {"type": "str", "source_key": "profileName"},
                "ssid_type": {"type": "str", "source_key": "wlanType"},
                "radio_policy": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "radio_bands": {
                                "type": "list",
                                "source_key": "ssidRadioType",
                                "transform": lambda x: {
                                    "Triple band operation(2.4GHz, 5GHz and 6GHz)": [
                                        2.4,
                                        5,
                                        6,
                                    ],
                                    "5GHz only": [5],
                                    "2.4GHz only": [2.4],
                                    "6GHz only": [6],
                                    "2.4 and 5 GHz": [2.4, 5],
                                    "2.4 and 6 GHz": [2.4, 6],
                                    "5 and 6 GHz": [5, 6],
                                }.get(x, []),
                            },
                            "2_dot_4_ghz_band_policy": {
                                "type": "str",
                                "source_key": "ghz24Policy",
                                "transform": lambda x: {
                                    "dot11-bg-only": "802.11-bg",
                                    "dot11-g-only": "802.11-g",
                                }.get(x, x),
                            },
                            "band_select": {
                                "type": "bool",
                                "source_key": "wlanBandSelectEnable",
                            },
                            "6_ghz_client_steering": {
                                "type": "bool",
                                "source_key": "ghz6PolicyClientSteering",
                            },
                        }
                    ),
                },
                "fast_lane": {"type": "bool", "source_key": "isFastLaneEnabled"},
                "quality_of_service": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "egress": {"type": "str", "source_key": "egressQos"},
                            "ingress": {"type": "str", "source_key": "ingressQos"},
                        }
                    ),
                },
                "ssid_state": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "admin_status": {"type": "bool", "source_key": "isEnabled"},
                            "broadcast_ssid": {
                                "type": "bool",
                                "source_key": "isBroadcastSSID",
                            },
                        }
                    ),
                },
                "l2_security": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "l2_auth_type": {"type": "str", "source_key": "authType"},
                            "ap_beacon_protection": {
                                "type": "bool",
                                "source_key": "isApBeaconProtectionEnabled",
                            },
                            "passphrase_type": {
                                "type": "str",
                                "source_key": "isHex",
                                "transform": lambda x: "HEX" if x else "ASCII",
                            },
                            "passphrase": {
                                "type": "str",
                                "special_handling": True,
                                "transform": lambda ssid_details: self.generate_custom_variable_name(
                                    ssid_details, "ssid", "ssid", "passphrase"
                                ),
                            },
                            "open_ssid": {"type": "str", "source_key": "openSsid"},
                            "mpsk_settings": {
                                "type": "list",
                                "elements": "dict",
                                "source_key": "multiPSKSettings",
                                "options": OrderedDict(
                                    {
                                        "mpsk_priority": {
                                            "type": "int",
                                            "source_key": "priority",
                                        },
                                        "mpsk_passphrase_type": {
                                            "type": "str",
                                            "source_key": "passphraseType",
                                        },
                                        "mpsk_passphrase": {
                                            "type": "str",
                                            "special_handling": True,
                                            "transform": lambda ssid_details: self.generate_custom_variable_name(
                                                ssid_details,
                                                "ssid",
                                                "ssid",
                                                "mpsk_passphrase",
                                            ),
                                        },
                                    }
                                ),
                            },
                        }
                    ),
                },
                "fast_transition": {"type": "str", "source_key": "fastTransition"},
                "fast_transition_over_the_ds": {
                    "type": "bool",
                    "source_key": "fastTransitionOverTheDistributedSystemEnable",
                },
                "wpa_encryption": {
                    "type": "list",
                    "special_handling": True,  # Indicates this field requires special handling
                    "transform": lambda ssid_details: self.process_boolean_to_list(
                        ssid_details,
                        {
                            "GCMP256": "rsnCipherSuiteGcmp256",
                            "CCMP256": "rsnCipherSuiteCcmp256",
                            "GCMP128": "rsnCipherSuiteGcmp128",
                            "CCMP128": "rsnCipherSuiteCcmp128",
                        },
                    ),
                },
                "auth_key_management": {
                    "type": "list",
                    "special_handling": True,
                    "transform": lambda ssid_details: self.process_boolean_to_list(
                        ssid_details,
                        {
                            "SAE": "isAuthKeySae",
                            "SAE-EXT-KEY": "isAuthKeySaeExt",
                            "FT+SAE": "isAuthKeySaePlusFT",
                            "FT+SAE-EXT-KEY": "isAuthKeySaeExtPlusFT",
                            "OWE": "isAuthKeyOWE",
                            "PSK": "isAuthKeyPSK",
                            "FT+PSK": "isAuthKeyPSKPlusFT",
                            "Easy-PSK": "isAuthKeyEasyPSK",
                            "PSK-SHA2": "isAuthKeyPSKSHA256",
                            "802.1X-SHA1": "isAuthKey8021x",
                            "802.1X-SHA2": "isAuthKey8021x_SHA256",
                            "FT+802.1x": "isAuthKey8021xPlusFT",
                            "SUITE-B-1X": "isAuthKeySuiteB1x",
                            "SUITE-B-192X": "isAuthKeySuiteB1921x",
                            "CCKM": "isCckmEnabled",
                        },
                    ),
                },
                "cckm_timestamp_tolerance": {
                    "type": "int",
                    "source_key": "cckmTsfTolerance",
                },
                "l3_security": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "l3_auth_type": {
                                "type": "str",
                                "source_key": "l3AuthType",
                                "transform": lambda x: {
                                    "WEB_AUTH": "web_auth",
                                    "OPEN": "open",
                                }.get(x, x),
                            },
                            "auth_server": {
                                "type": "str",
                                "source_key": "authServer",
                                "transform": lambda x: {
                                    "Central Web Authentication": "auth_ise",
                                    "Web Authentication Internal": "auth_internal",
                                    "Web Authentication External": "auth_external",
                                    "Web Passthrough Internal": "auth_internal",
                                    "Web Passthrough External": "auth_external",
                                }.get(x, x),
                            },
                            "web_auth_url": {
                                "type": "str",
                                "source_key": "externalAuthIpAddress",
                            },
                            "enable_sleeping_client": {
                                "type": "bool",
                                "source_key": "sleepingClientEnable",
                            },
                            "sleeping_client_timeout": {
                                "type": "int",
                                "source_key": "sleepingClientTimeout",
                            },
                        }
                    ),
                },
                "aaa": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "auth_servers_ip_address_list": {
                                "type": "list",
                                "source_key": "authServers",
                            },
                            "accounting_servers_ip_address_list": {
                                "type": "list",
                                "source_key": "acctServers",
                            },
                            "aaa_override": {
                                "type": "bool",
                                "source_key": "aaaOverride",
                            },
                            "mac_filtering": {
                                "type": "bool",
                                "source_key": "isMacFilteringEnabled",
                            },
                            "deny_rcm_clients": {
                                "type": "bool",
                                "source_key": "isRandomMacFilterEnabled",
                            },
                            "enable_posture": {
                                "type": "bool",
                                "source_key": "isPosturingEnabled",
                            },
                            "pre_auth_acl_name": {
                                "type": "str",
                                "source_key": "aclName",
                            },
                        }
                    ),
                },
                "mfp_client_protection": {
                    "type": "str",
                    "source_key": "managementFrameProtectionClientprotection",
                },
                "protected_management_frame": {
                    "type": "str",
                    "source_key": "protectedManagementFrame",
                },
                "11k_neighbor_list": {
                    "type": "bool",
                    "source_key": "neighborListEnable",
                },
                "coverage_hole_detection": {
                    "type": "bool",
                    "source_key": "coverageHoleDetectionEnable",
                },
                "wlan_timeouts": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "enable_session_timeout": {
                                "type": "bool",
                                "source_key": "sessionTimeOutEnable",
                            },
                            "session_timeout": {
                                "type": "int",
                                "source_key": "sessionTimeOut",
                            },
                            "enable_client_execlusion_timeout": {
                                "type": "bool",
                                "source_key": "clientExclusionEnable",
                            },
                            "client_execlusion_timeout": {
                                "type": "int",
                                "source_key": "clientExclusionTimeout",
                            },
                        }
                    ),
                },
                "bss_transition_support": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "bss_max_idle_service": {
                                "type": "bool",
                                "source_key": "basicServiceSetMaxIdleEnable",
                            },
                            "bss_idle_client_timeout": {
                                "type": "int",
                                "source_key": "basicServiceSetClientIdleTimeout",
                            },
                            "directed_multicast_service": {
                                "type": "bool",
                                "source_key": "directedMulticastServiceEnable",
                            },
                        }
                    ),
                },
                "nas_id": {"type": "list", "source_key": "nasOptions"},
                "client_rate_limit": {"type": "int", "source_key": "clientRateLimit"},
                "sites_specific_override_settings": {
                    "type": "list",
                    "elements": "dict",
                    "special_handling": True,
                    "transform": lambda ssid_details: (
                        self.modify_parameters(
                            OrderedDict(
                                {
                                    "site_name_hierarchy": {
                                        "type": "str",
                                        "source_key": "site_name_hierarchy",
                                    },
                                    "wlan_profile_name": {
                                        "type": "str",
                                        "source_key": "profileName",
                                    },
                                    "l2_security": {
                                        "type": "dict",
                                        "options": OrderedDict(
                                            {
                                                "l2_auth_type": {
                                                    "type": "str",
                                                    "source_key": "authType",
                                                },
                                                "open_ssid": {
                                                    "type": "str",
                                                    "source_key": "openSsid",
                                                },
                                                "passphrase": {
                                                    "type": "str",
                                                    "special_handling": True,
                                                    "transform": lambda site_override: self.generate_custom_variable_name(
                                                        site_override,
                                                        "ssid",
                                                        "ssid",
                                                        "passphrase",
                                                    ),
                                                },
                                                "mpsk_settings": {
                                                    "type": "list",
                                                    "elements": "dict",
                                                    "source_key": "multiPSKSettings",
                                                    "options": OrderedDict(
                                                        {
                                                            "mpsk_priority": {
                                                                "type": "int",
                                                                "source_key": "priority",
                                                            },
                                                            "mpsk_passphrase_type": {
                                                                "type": "str",
                                                                "source_key": "passphraseType",
                                                            },
                                                            "mpsk_passphrase": {
                                                                "type": "str",
                                                                "special_handling": True,
                                                                "transform": lambda site_override: self.generate_custom_variable_name(
                                                                    site_override,
                                                                    "ssid",
                                                                    "ssid",
                                                                    "mpsk_passphrase",
                                                                ),
                                                            },
                                                        }
                                                    ),
                                                },
                                            }
                                        ),
                                    },
                                    "fast_transition": {
                                        "type": "str",
                                        "source_key": "fastTransition",
                                    },
                                    "fast_transition_over_the_ds": {
                                        "type": "bool",
                                        "source_key": "fastTransitionOverTheDistributedSystemEnable",
                                    },
                                    "wpa_encryption": {
                                        "type": "list",
                                        "special_handling": True,
                                        "transform": lambda site_override: self.process_boolean_to_list(
                                            (
                                                site_override
                                                if isinstance(site_override, dict)
                                                else {}
                                            ),
                                            {
                                                "GCMP256": "rsnCipherSuiteGcmp256",
                                                "CCMP256": "rsnCipherSuiteCcmp256",
                                                "GCMP128": "rsnCipherSuiteGcmp128",
                                                "CCMP128": "rsnCipherSuiteCcmp128",
                                            },
                                        ),
                                    },
                                    "auth_key_management": {
                                        "type": "list",
                                        "special_handling": True,
                                        "transform": lambda site_override: self.process_boolean_to_list(
                                            (
                                                site_override
                                                if isinstance(site_override, dict)
                                                else {}
                                            ),
                                            {
                                                "SAE": "isAuthKeySae",
                                                "SAE-EXT-KEY": "isAuthKeySaeExt",
                                                "FT+SAE": "isAuthKeySaePlusFT",
                                                "FT+SAE-EXT-KEY": "isAuthKeySaeExtPlusFT",
                                                "OWE": "isAuthKeyOWE",
                                                "PSK": "isAuthKeyPSK",
                                                "FT+PSK": "isAuthKeyPSKPlusFT",
                                                "Easy-PSK": "isAuthKeyEasyPSK",
                                                "PSK-SHA2": "isAuthKeyPSKSHA256",
                                                "802.1X-SHA1": "isAuthKey8021x",
                                                "802.1X-SHA2": "isAuthKey8021x_SHA256",
                                                "FT+802.1x": "isAuthKey8021xPlusFT",
                                                "SUITE-B-1X": "isAuthKeySuiteB1x",
                                                "SUITE-B-192X": "isAuthKeySuiteB1921x",
                                                "CCKM": "isCckmEnabled",
                                            },
                                        ),
                                    },
                                    "protected_management_frame": {
                                        "type": "str",
                                        "source_key": "protectedManagementFrame",
                                    },
                                    "nas_id": {
                                        "type": "list",
                                        "source_key": "nasOptions",
                                    },
                                    "client_rate_limit": {
                                        "type": "int",
                                        "source_key": "clientRateLimit",
                                    },
                                }
                            ),
                            ssid_details.get("sites_specific_override_settings", []),
                        )
                        if "sites_specific_override_settings" in ssid_details
                        else []
                    ),
                },
            }
        )
        return wireless_ssid_temp_spec

    def combine_global_and_site_ssids(
        self, global_ssids, site_ssids, site_name_hierarchy
    ):
        """
        Combines global and site-specific SSIDs, giving precedence to site-specific overrides.

        Args:
            global_ssids (list): List of SSIDs retrieved from the global site.
            site_ssids (list): List of SSIDs retrieved from the specified site.
            site_name_hierarchy (str): The site name hierarchy for the site-specific SSIDs.

        Returns:
            list: A combined list of SSIDs with site-specific overrides applied.
        """
        # Create a dictionary of global SSIDs for quick lookup by ssid_name
        combined_ssids = {ssid["ssid"]: ssid for ssid in global_ssids}

        for site_ssid in site_ssids:
            ssid_name = site_ssid["ssid"]
            # Add the site_name_hierarchy to the site-specific SSID
            site_ssid["site_name_hierarchy"] = site_name_hierarchy

            if ssid_name in combined_ssids:
                # Apply site-specific overrides
                if "sites_specific_override_settings" not in combined_ssids[ssid_name]:
                    combined_ssids[ssid_name]["sites_specific_override_settings"] = []
                combined_ssids[ssid_name]["sites_specific_override_settings"].append(
                    site_ssid
                )
            else:
                # Add the site-specific SSID as a new entry
                combined_ssids[ssid_name] = site_ssid

        return list(combined_ssids.values())

    def get_wireless_ssids(self, network_element, component_specific_filters=None):
        """
        Retrieves wireless SSID details and modifies them according to the specified parameters mapping.
        Args:
            network_element (dict): Contains api_family and api_function for retrieving SSID details.
            component_specific_filters (dict, optional): Filters to apply when retrieving SSID details.
        Returns:
            dict: A dictionary containing modified SSID details.
        """
        # Extract API family and function from network_element
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting wireless SSIDs using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        # Initialize the list to accumulate results
        accumulated_results = []
        global_site_id = self.get_global_site_details()
        # Determine parameters based on component_specific_filters
        if component_specific_filters:
            self.log("Using component-specific filters for API call.", "INFO")
            site_name_hierarchy = component_specific_filters.get("site_name_hierarchy")
            ssid_names_list = component_specific_filters.get("ssid_names_list", [])

            # If a site is specified, retrieve its site ID
            if site_name_hierarchy:
                site_exists, site_id = self.get_site_id(site_name_hierarchy)
                if not site_exists:
                    self.msg = "Site '{0}' does not exist.".format(site_name_hierarchy)
                    self.fail_and_exit(self.msg)
                self.log(
                    "Site '{0}' found with ID: {1}".format(
                        site_name_hierarchy, site_id
                    ),
                    "DEBUG",
                )

                # If only site_name_hierarchy is provided
                if not ssid_names_list:
                    # Create params for global site
                    global_params = self.get_ssids_params(site_id=global_site_id)
                    self.log(
                        "Created params for global site: {0}".format(global_params),
                        "DEBUG",
                    )
                    global_ssids = self.execute_get_with_pagination(
                        api_family, api_function, global_params
                    )

                    # Create params for the specified site
                    site_params = self.get_ssids_params(site_id=site_id)
                    self.log(
                        "Created params for specified site: {0}".format(site_params),
                        "DEBUG",
                    )
                    site_ssids = self.execute_get_with_pagination(
                        api_family, api_function, site_params
                    )

                    # Combine global and site-specific SSIDs
                    combined_ssids = self.combine_global_and_site_ssids(
                        global_ssids, site_ssids, site_name_hierarchy
                    )
                    accumulated_results.extend(combined_ssids)

                # If both site_name_hierarchy and ssid_names_list are provided
                else:
                    for ssid_name in ssid_names_list:
                        # Create params for global site with SSID name
                        global_params = self.get_ssids_params(
                            site_id=global_site_id, ssid_name=ssid_name
                        )
                        self.log(
                            "Created params for global site with SSID '{0}': {1}".format(
                                ssid_name, global_params
                            ),
                            "DEBUG",
                        )
                        global_ssid = self.execute_get_with_pagination(
                            api_family, api_function, global_params
                        )

                        # Create params for the specified site with SSID name
                        site_params = self.get_ssids_params(
                            site_id=site_id, ssid_name=ssid_name
                        )
                        self.log(
                            "Created params for specified site with SSID '{0}': {1}".format(
                                ssid_name, site_params
                            ),
                            "DEBUG",
                        )
                        site_ssid = self.execute_get_with_pagination(
                            api_family, api_function, site_params
                        )

                        # Combine global and site-specific SSIDs for this SSID name
                        combined_ssids = self.combine_global_and_site_ssids(
                            global_ssid, site_ssid, site_name_hierarchy
                        )
                        accumulated_results.extend(combined_ssids)
            else:
                # If no site is specified, use the global site ID
                for ssid_name in ssid_names_list:
                    params = self.get_ssids_params(
                        site_id=global_site_id, ssid_name=ssid_name
                    )
                    self.log(
                        "Created params for global site: {0}".format(params), "DEBUG"
                    )
                    accumulated_results.extend(
                        self.execute_get_with_pagination(
                            api_family, api_function, params
                        )
                    )
        else:
            # If no filters are provided, use the global site ID
            self.log(
                "No filters provided. Using global site details for API call.", "INFO"
            )
            global_params = self.get_ssids_params(site_id=global_site_id)
            self.log(
                "Created params for global site: {0}".format(global_params), "DEBUG"
            )
            accumulated_results.extend(
                self.execute_get_with_pagination(
                    api_family, api_function, global_params
                )
            )

        # Modify SSID details using temp_spec
        wireless_ssid_temp_spec = self.wireless_ssid_temp_spec()
        modified_ssid_details = self.modify_parameters(
            wireless_ssid_temp_spec, accumulated_results
        )
        self.log("Modified SSID details: {0}".format(modified_ssid_details), "INFO")

        ssids = {"ssids": modified_ssid_details}
        self.log("Modified SSIDs: {0}".format(ssids), "INFO")
        return ssids

    def wireless_interfaces_temp_spec(self):
        wireless_interfaces_temp_spec = OrderedDict(
            {
                "interface_name": {"type": "str", "source_key": "interfaceName"},
                "vlan_id": {"type": "int", "source_key": "vlanId"},
            }
        )

        return wireless_interfaces_temp_spec

    def get_wireless_interfaces(self, network_element, component_specific_filters=None):
        # Extract API family and function from network_element
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting wireless Interfaces using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        # Determine parameters based on component_specific_filters
        if component_specific_filters:
            params = {}
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            params = {}
            self.log("Using global site details for API call.", "INFO")

        # Execute API call to retrieve Interfaces details
        interfaces_details = self.execute_get_with_pagination(
            api_family, api_function, params
        )
        self.log("Retrieved Interfaces details: {0}".format(interfaces_details), "INFO")

        # Modify Interfaces details using temp_spec
        wireless_interfaces_temp_spec = self.wireless_interfaces_temp_spec()
        modified_wireless_interfaces_details = self.modify_parameters(
            wireless_interfaces_temp_spec, interfaces_details
        )
        self.log(
            "Modified Interfaces details: {0}".format(
                modified_wireless_interfaces_details
            ),
            "INFO",
        )

        # Remove the specific interface with interface_name 'management' and vlan_id 0
        modified_wireless_interfaces_details = [
            interface
            for interface in modified_wireless_interfaces_details
            if not (
                interface.get("interface_name") == "management"
                and interface.get("vlan_id") == 0
            )
        ]
        self.log(
            "Filtered Interfaces details: {0}".format(
                modified_wireless_interfaces_details
            ),
            "INFO",
        )

        interfaces = {"interfaces": modified_wireless_interfaces_details}
        self.log("Modified Interfaces: {0}".format(interfaces), "INFO")
        return interfaces

    def wireless_power_profiles_temp_spec(self):
        wireless_power_profiles_temp_spec = OrderedDict(
            {
                "power_profile_name": {"type": "str", "source_key": "profileName"},
                "power_profile_description": {
                    "type": "str",
                    "source_key": "description",
                },
                "rules": {
                    "type": "list",
                    "elements": "dict",
                    "options": OrderedDict(
                        {
                            "interface_type": {
                                "type": "str",
                                "source_key": "interfaceType",
                            },
                            "interface_id": {
                                "type": "str",
                                "source_key": "interfaceId",
                            },
                            "parameter_type": {
                                "type": "str",
                                "source_key": "parameterType",
                            },
                            "parameter_value": {
                                "type": "str",
                                "source_key": "parameterValue",
                            },
                        }
                    ),
                },
            }
        )
        return wireless_power_profiles_temp_spec

    def get_wireless_power_profiles(
        self, network_element, component_specific_filters=None
    ):
        # Extract API family and function from network_element
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting wireless Power Profiles using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        # Determine parameters based on component_specific_filters
        if component_specific_filters:
            params = {}
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            params = {}
            self.log("Using global site details for API call.", "INFO")

        # Execute API call to retrieve Power Profiles details
        power_profiles_details = self.execute_get_with_pagination(
            api_family, api_function, params
        )
        self.log(
            "Retrieved Power Profiles details: {0}".format(power_profiles_details),
            "INFO",
        )

        # Modify Power Profiles details using temp_spec
        wireless_power_profiles_temp_spec = self.wireless_power_profiles_temp_spec()
        modified_wireless_power_profiles_details = self.modify_parameters(
            wireless_power_profiles_temp_spec, power_profiles_details
        )
        self.log(
            "Modified Power Profiles details: {0}".format(
                modified_wireless_power_profiles_details
            ),
            "INFO",
        )

        power_profiles = {"power_profiles": modified_wireless_power_profiles_details}
        self.log("Modified Power Profiles: {0}".format(power_profiles), "INFO")
        return power_profiles

    def wireless_access_point_profiles_temp_spec(self):
        country_code_map = {
            "AF": "Afghanistan",
            "AL": "Albania",
            "DZ": "Algeria",
            "AO": "Angola",
            "AR": "Argentina",
            "AU": "Australia",
            "AT": "Austria",
            "BS": "Bahamas",
            "BH": "Bahrain",
            "BD": "Bangladesh",
            "BB": "Barbados",
            "BY": "Belarus",
            "BE": "Belgium",
            "BT": "Bhutan",
            "BO": "Bolivia",
            "BA": "Bosnia",
            "BW": "Botswana",
            "BR": "Brazil",
            "BN": "Brunei",
            "BG": "Bulgaria",
            "BI": "Burundi",
            "KH": "Cambodia",
            "CM": "Cameroon",
            "CA": "Canada",
            "CL": "Chile",
            "CN": "China",
            "CO": "Colombia",
            "CR": "Costa Rica",
            "HR": "Croatia",
            "CU": "Cuba",
            "CY": "Cyprus",
            "CZ": "Czech Republic",
            "CD": "Democratic Republic of the Congo",
            "DK": "Denmark",
            "DO": "Dominican Republic",
            "EC": "Ecuador",
            "EG": "Egypt",
            "SV": "El Salvador",
            "EE": "Estonia",
            "ET": "Ethiopia",
            "FJ": "Fiji",
            "FI": "Finland",
            "FR": "France",
            "GA": "Gabon",
            "GE": "Georgia",
            "DE": "Germany",
            "GH": "Ghana",
            "GI": "Gibraltar",
            "GR": "Greece",
            "GT": "Guatemala",
            "HN": "Honduras",
            "HK": "Hong Kong",
            "HU": "Hungary",
            "IS": "Iceland",
            "IN": "India",
            "ID": "Indonesia",
            "IQ": "Iraq",
            "IE": "Ireland",
            "IM": "Isle of Man",
            "IL": "Israel",
            "IT": "Italy",
            "CI": "Ivory Coast (Cote dIvoire)",
            "JM": "Jamaica",
            "J2": "Japan 2(P)",
            "J4": "Japan 4(Q)",
            "JE": "Jersey",
            "JO": "Jordan",
            "KZ": "Kazakhstan",
            "KE": "Kenya",
            "KR": "Korea Extended (CK)",
            "XK": "Kosovo",
            "KW": "Kuwait",
            "LA": "Laos",
            "LV": "Latvia",
            "LB": "Lebanon",
            "LY": "Libya",
            "LI": "Liechtenstein",
            "LT": "Lithuania",
            "LU": "Luxembourg",
            "MO": "Macao",
            "MK": "Macedonia",
            "MY": "Malaysia",
            "MT": "Malta",
            "MU": "Mauritius",
            "MX": "Mexico",
            "MD": "Moldova",
            "MC": "Monaco",
            "MN": "Mongolia",
            "ME": "Montenegro",
            "MA": "Morocco",
            "MM": "Myanmar",
            "NA": "Namibia",
            "NP": "Nepal",
            "NL": "Netherlands",
            "NZ": "New Zealand",
            "NI": "Nicaragua",
            "NG": "Nigeria",
            "NO": "Norway",
            "OM": "Oman",
            "PK": "Pakistan",
            "PA": "Panama",
            "PY": "Paraguay",
            "PE": "Peru",
            "PH": "Philippines",
            "PL": "Poland",
            "PT": "Portugal",
            "PR": "Puerto Rico",
            "QA": "Qatar",
            "RO": "Romania",
            "RU": "Russian Federation",
            "SM": "San Marino",
            "SA": "Saudi Arabia",
            "RS": "Serbia",
            "SG": "Singapore",
            "SK": "Slovak Republic",
            "SI": "Slovenia",
            "ZA": "South Africa",
            "ES": "Spain",
            "LK": "Sri Lanka",
            "SD": "Sudan",
            "SE": "Sweden",
            "CH": "Switzerland",
            "TW": "Taiwan",
            "TH": "Thailand",
            "TT": "Trinidad",
            "TN": "Tunisia",
            "TR": "Turkey",
            "UG": "Uganda",
            "UA": "Ukraine",
            "AE": "United Arab Emirates",
            "GB": "United Kingdom",
            "TZ": "United Republic of Tanzania",
            "US": "United States",
            "UY": "Uruguay",
            "UZ": "Uzbekistan",
            "VA": "Vatican City State",
            "VE": "Venezuela",
            "VN": "Vietnam",
            "YE": "Yemen",
            "ZM": "Zambia",
            "ZW": "Zimbabwe",
        }

        ap_profile_temp_spec = OrderedDict(
            {
                "access_point_profile_name": {
                    "type": "str",
                    "source_key": "apProfileName",
                },
                "access_point_profile_description": {
                    "type": "str",
                    "source_key": "description",
                },
                "remote_teleworker": {
                    "type": "bool",
                    "source_key": "remoteWorkerEnabled",
                },
                "management_settings": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "access_point_authentication": {
                                "type": "str",
                                "source_key": "managementSetting.authType",
                            },
                            "dot1x_username": {
                                "type": "str",
                                "source_key": "managementSetting.dot1xUsername",
                            },
                            "dot1x_password": {
                                "type": "str",
                                "special_handling": True,
                                "transform": lambda ssid_details: self.generate_custom_variable_name(
                                    ssid_details,
                                    "ap_profile",
                                    "apProfileName",
                                    "dot1x_password",
                                ),
                            },
                            "ssh_enabled": {
                                "type": "bool",
                                "source_key": "managementSetting.sshEnabled",
                            },
                            "telnet_enabled": {
                                "type": "bool",
                                "source_key": "managementSetting.telnetEnabled",
                            },
                            "management_username": {
                                "type": "str",
                                "source_key": "managementSetting.managementUserName",
                            },
                            "management_password": {
                                "type": "str",
                                "special_handling": True,
                                "transform": lambda ssid_details: self.generate_custom_variable_name(
                                    ssid_details,
                                    "ap_profile",
                                    "apProfileName",
                                    "management_password",
                                ),
                            },
                            "management_enable_password": {
                                "type": "str",
                                "special_handling": True,
                                "transform": lambda ssid_details: self.generate_custom_variable_name(
                                    ssid_details,
                                    "ap_profile",
                                    "apProfileName",
                                    "management_enable_password",
                                ),
                            },
                            "cdp_state": {
                                "type": "bool",
                                "source_key": "managementSetting.cdpState",
                            },
                        }
                    ),
                },
                "security_settings": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "awips": {"type": "bool", "source_key": "awipsEnabled"},
                            "awips_forensic": {
                                "type": "bool",
                                "source_key": "awipsForensicEnabled",
                            },
                            "rogue_detection_enabled": {
                                "type": "bool",
                                "source_key": "rogueDetectionSetting.rogueDetection",
                            },
                            "minimum_rssi": {
                                "type": "int",
                                "source_key": "rogueDetectionSetting.rogueDetectionMinRssi",
                            },
                            "transient_interval": {
                                "type": "int",
                                "source_key": "rogueDetectionSetting.rogueDetectionTransientInterval",
                            },
                            "report_interval": {
                                "type": "int",
                                "source_key": "rogueDetectionSetting.rogueDetectionReportInterval",
                            },
                            "pmf_denial": {
                                "type": "bool",
                                "source_key": "pmfDenialEnabled",
                            },
                        }
                    ),
                },
                "mesh_enabled": {"type": "bool", "source_key": "meshEnabled"},
                "mesh_settings": {
                    "type": "dict",
                    "source_key": "meshSetting",
                    "options": OrderedDict(
                        {
                            "range": {"type": "int", "source_key": "meshSetting.range"},
                            "backhaul_client_access": {
                                "type": "bool",
                                "source_key": "meshSetting.backhaulClientAccess",
                            },
                            "rap_downlink_backhaul": {
                                "type": "str",
                                "source_key": "meshSetting.rapDownlinkBackhaul",
                            },
                            "ghz_5_backhaul_data_rates": {
                                "type": "str",
                                "source_key": "meshSetting.ghz5BackhaulDataRates",
                            },
                            "ghz_2_4_backhaul_data_rates": {
                                "type": "str",
                                "source_key": "meshSetting.ghz24BackhaulDataRates",
                            },
                            "bridge_group_name": {
                                "type": "str",
                                "source_key": "meshSetting.bridgeGroupName",
                            },
                        }
                    ),
                },
                "power_settings": {
                    "type": "dict",
                    "options": OrderedDict(
                        {
                            "ap_power_profile_name": {
                                "type": "str",
                                "source_key": "apPowerProfileName",
                            },
                            "calendar_power_profiles": {
                                "type": "list",
                                "elements": "dict",
                                "source_key": "calendarPowerProfiles",
                                "options": OrderedDict(
                                    {
                                        "ap_power_profile_name": {
                                            "type": "str",
                                            "source_key": "powerProfileName",
                                        },
                                        "scheduler_type": {
                                            "type": "str",
                                            "source_key": "schedulerType",
                                        },
                                        "scheduler_start_time": {
                                            "type": "str",
                                            "source_key": "duration.schedulerStartTime",
                                        },
                                        "scheduler_end_time": {
                                            "type": "str",
                                            "source_key": "duration.schedulerEndTime",
                                        },
                                        "scheduler_days_list": {
                                            "type": "list",
                                            "source_key": "duration.schedulerDay",
                                        },
                                        "scheduler_dates_list": {
                                            "type": "list",
                                            "source_key": "duration.schedulerDate",
                                        },
                                    }
                                ),
                            },
                        }
                    ),
                },
                "country_code": {
                    "type": "str",
                    "source_key": "countryCode",
                    "transform": lambda code: country_code_map.get(code, None),
                },
                "time_zone": {
                    "type": "str",
                    "source_key": "timeZone",
                    # "transform": lambda x: None if x in self.values_to_nullify else x
                },
                "time_zone_offset_hour": {
                    "type": "int",
                    "source_key": "timeZoneOffsetHour",
                },
                "time_zone_offset_minutes": {
                    "type": "int",
                    "source_key": "timeZoneOffsetMinutes",
                },
                "maximum_client_limit": {"type": "int", "source_key": "clientLimit"},
            }
        )
        return ap_profile_temp_spec

    def get_wireless_access_point_profiles(
        self, network_element, component_specific_filters=None
    ):
        # Extract API family and function from network_element
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting wireless Access Point Profiles using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        # Determine parameters based on component_specific_filters
        if component_specific_filters:
            params = {}
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            params = {}
            self.log("Using global site details for API call.", "INFO")

        # Execute API call to retrieve Access Point Profiles details
        access_point_profiles_details = self.execute_get_with_pagination(
            api_family, api_function, params
        )
        self.log(
            "Retrieved Access Point Profiles details: {0}".format(
                access_point_profiles_details
            ),
            "INFO",
        )

        # Modify Access Point Profiles details using temp_spec
        ap_profiles_temp_spec = self.wireless_access_point_profiles_temp_spec()
        modified_ap_profiles_details = self.modify_parameters(
            ap_profiles_temp_spec, access_point_profiles_details
        )
        self.log(
            "Modified Access Point Profiles details: {0}".format(
                modified_ap_profiles_details
            ),
            "INFO",
        )

        ap_profiles = {"access_point_profiles": modified_ap_profiles_details}
        self.log("Modified AP Profiles: {0}".format(ap_profiles), "INFO")
        return ap_profiles

    def wireless_radio_frequency_profiles_temp_spec(self):
        radio_frequency_profiles_temp_spec = OrderedDict(
            {
                "radio_frequency_profile_name": {
                    "type": "str",
                    "source_key": "rfProfileName",
                },
                "default_rf_profile": {
                    "type": "bool",
                    "source_key": "defaultRfProfile",
                },
                "radio_bands": {
                    "type": "list",
                    "special_handling": True,
                    "transform": lambda rf_details: self.process_boolean_to_list(
                        rf_details,
                        {
                            5: "enableRadioTypeA",
                            2.4: "enableRadioTypeB",
                            6: "enableRadioType6GHz",
                        },
                    ),
                },
                "radio_bands_2_4ghz_settings": {
                    "type": "dict",
                    "source_key": "radioTypeBProperties",
                    "options": OrderedDict(
                        {
                            "parent_profile": {
                                "type": "str",
                                "source_key": "radioTypeBProperties.parentProfile",
                            },
                            "dca_channels_list": {
                                "type": "list",
                                "source_key": "radioTypeBProperties.radioChannels",
                            },
                            "supported_data_rates_list": {
                                "type": "list",
                                "source_key": "radioTypeBProperties.dataRates",
                            },
                            "mandatory_data_rates_list": {
                                "type": "list",
                                "source_key": "radioTypeBProperties.mandatoryDataRates",
                            },
                            "minimum_power_level": {
                                "type": "int",
                                "source_key": "radioTypeBProperties.minPowerLevel",
                            },
                            "maximum_power_level": {
                                "type": "int",
                                "source_key": "radioTypeBProperties.maxPowerLevel",
                            },
                            "rx_sop_threshold": {
                                "type": "str",
                                "source_key": "radioTypeBProperties.rxSopThreshold",
                            },
                            "custom_rx_sop_threshold": {
                                "type": "int",
                                "source_key": "radioTypeBProperties.customRxSopThreshold",
                            },
                            "tpc_power_threshold": {
                                "type": "int",
                                "source_key": "radioTypeBProperties.powerThresholdV1",
                            },
                            "client_limit": {
                                "type": "int",
                                "source_key": "radioTypeBProperties.maxRadioClients",
                            },
                            "coverage_hole_detection": {
                                "type": "dict",
                                # "source_key": "coverageHoleDetectionProperties",
                                "options": OrderedDict(
                                    {
                                        "minimum_client_level": {
                                            "type": "int",
                                            "source_key": "radioTypeBProperties.coverageHoleDetectionProperties.chdClientLevel",
                                        },
                                        "data_rssi_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeBProperties.coverageHoleDetectionProperties.chdDataRssiThreshold",
                                        },
                                        "voice_rssi_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeBProperties.coverageHoleDetectionProperties.chdVoiceRssiThreshold",
                                        },
                                        "exception_level": {
                                            "type": "int",
                                            "source_key": "radioTypeBProperties.coverageHoleDetectionProperties.chdExceptionLevel",
                                        },
                                    }
                                ),
                            },
                            "spatial_reuse": {
                                "type": "dict",
                                # "source_key": "spatialReuseProperties",
                                "options": OrderedDict(
                                    {
                                        "non_srg_obss_pd": {
                                            "type": "bool",
                                            "source_key": "radioTypeBProperties.spatialReuseProperties.dot11axNonSrgObssPacketDetect",
                                        },
                                        "non_srg_obss_pd_max_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeBProperties.spatialReuseProperties.dot11axNonSrgObssPacketDetectMaxThreshold",
                                        },
                                        "srg_obss_pd": {
                                            "type": "bool",
                                            "source_key": "radioTypeBProperties.spatialReuseProperties.dot11axSrgObssPacketDetect",
                                        },
                                        "srg_obss_pd_min_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeBProperties.spatialReuseProperties.dot11axSrgObssPacketDetectMinThreshold",
                                        },
                                        "srg_obss_pd_max_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeBProperties.spatialReuseProperties.dot11axSrgObssPacketDetectMaxThreshold",
                                        },
                                    }
                                ),
                            },
                        }
                    ),
                },
                "radio_bands_5ghz_settings": {
                    "type": "dict",
                    "source_key": "radioTypeAProperties",
                    "options": OrderedDict(
                        {
                            "parent_profile": {
                                "type": "str",
                                "source_key": "radioTypeAProperties.parentProfile",
                            },
                            "channel_width": {
                                "type": "str",
                                "source_key": "radioTypeAProperties.channelWidth",
                            },
                            "preamble_puncturing": {
                                "type": "bool",
                                "source_key": "radioTypeAProperties.preamblePuncture",
                            },
                            "zero_wait_dfs": {
                                "type": "bool",
                                "source_key": "radioTypeAProperties.zeroWaitDfsEnable",
                            },
                            "dca_channels_list": {
                                "type": "list",
                                "source_key": "radioTypeAProperties.radioChannels",
                            },
                            "supported_data_rates_list": {
                                "type": "list",
                                "source_key": "radioTypeAProperties.dataRates",
                            },
                            "mandatory_data_rates_list": {
                                "type": "list",
                                "source_key": "radioTypeAProperties.mandatoryDataRates",
                            },
                            "minimum_power_level": {
                                "type": "int",
                                "source_key": "radioTypeAProperties.minPowerLevel",
                            },
                            "maximum_power_level": {
                                "type": "int",
                                "source_key": "radioTypeAProperties.maxPowerLevel",
                            },
                            "rx_sop_threshold": {
                                "type": "str",
                                "source_key": "radioTypeAProperties.rxSopThreshold",
                            },
                            "custom_rx_sop_threshold": {
                                "type": "int",
                                "source_key": "radioTypeAProperties.customRxSopThreshold",
                            },
                            "tpc_power_threshold": {
                                "type": "int",
                                "source_key": "radioTypeAProperties.powerThresholdV1",
                            },
                            "client_limit": {
                                "type": "int",
                                "source_key": "radioTypeAProperties.maxRadioClients",
                            },
                            "coverage_hole_detection": {
                                "type": "dict",
                                "source_key": "coverageHoleDetectionProperties",
                                "options": OrderedDict(
                                    {
                                        "minimum_client_level": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.coverageHoleDetectionProperties.chdClientLevel",
                                        },
                                        "data_rssi_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.coverageHoleDetectionPropertieschdDataRssiThreshold",
                                        },
                                        "voice_rssi_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.coverageHoleDetectionPropertieschdVoiceRssiThreshold",
                                        },
                                        "exception_level": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.coverageHoleDetectionPropertieschdExceptionLevel",
                                        },
                                    }
                                ),
                            },
                            "flexible_radio_assigment": {
                                "type": "dict",
                                "source_key": "fraPropertiesA",
                                "options": OrderedDict(
                                    {
                                        "client_aware": {
                                            "type": "bool",
                                            "source_key": "radioTypeAProperties.fraPropertiesA.clientAware",
                                        },
                                        "client_select": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.fraPropertiesA.clientSelect",
                                        },
                                        "client_reset": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.fraPropertiesA.clientReset",
                                        },
                                    }
                                ),
                            },
                            "spatial_reuse": {
                                "type": "dict",
                                "source_key": "spatialReuseProperties",
                                "options": OrderedDict(
                                    {
                                        "non_srg_obss_pd": {
                                            "type": "bool",
                                            "source_key": "radioTypeAProperties.spatialReuseProperties.dot11axNonSrgObssPacketDetect",
                                        },
                                        "non_srg_obss_pd_max_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.spatialReuseProperties.dot11axNonSrgObssPacketDetectMaxThreshold",
                                        },
                                        "srg_obss_pd": {
                                            "type": "bool",
                                            "source_key": "radioTypeAProperties.spatialReuseProperties.dot11axSrgObssPacketDetect",
                                        },
                                        "srg_obss_pd_min_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.spatialReuseProperties.dot11axSrgObssPacketDetectMinThreshold",
                                        },
                                        "srg_obss_pd_max_threshold": {
                                            "type": "int",
                                            "source_key": "radioTypeAProperties.spatialReuseProperties.dot11axSrgObssPacketDetectMaxThreshold",
                                        },
                                    }
                                ),
                            },
                        }
                    ),
                },
                "radio_bands_6ghz_settings": {
                    "type": "dict",
                    "source_key": "radioType6GHzProperties",
                    "options": OrderedDict(
                        {
                            "parent_profile": {
                                "type": "str",
                                "source_key": "radioType6GHzProperties.parentProfile",
                            },
                            "minimum_dbs_channel_width": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.minDbsWidth",
                            },
                            "maximum_dbs_channel_width": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.maxDbsWidth",
                            },
                            "preamble_puncturing": {
                                "type": "bool",
                                "source_key": "radioType6GHzProperties.preamblePuncture",
                            },
                            "psc_enforcing_enabled": {
                                "type": "bool",
                                "source_key": "radioType6GHzProperties.pscEnforcingEnabled",
                            },
                            "dca_channels_list": {
                                "type": "list",
                                "source_key": "radioType6GHzProperties.radioChannels",
                            },
                            "supported_data_rates_list": {
                                "type": "list",
                                "source_key": "radioType6GHzProperties.dataRates",
                            },
                            "mandatory_data_rates_list": {
                                "type": "list",
                                "source_key": "radioType6GHzProperties.mandatoryDataRates",
                            },
                            "minimum_power_level": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.minPowerLevel",
                            },
                            "maximum_power_level": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.maxPowerLevel",
                            },
                            "rx_sop_threshold": {
                                "type": "str",
                                "source_key": "radioType6GHzProperties.rxSopThreshold",
                            },
                            "custom_rx_sop_threshold": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.customRxSopThreshold",
                            },
                            "tpc_power_threshold": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.powerThresholdV1",
                            },
                            "client_limit": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.maxRadioClients",
                            },
                            "coverage_hole_detection": {
                                "type": "dict",
                                # "source_key": "coverageHoleDetectionProperties",
                                "options": OrderedDict(
                                    {
                                        "minimum_client_level": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.coverageHoleDetectionProperties.chdClientLevel",
                                        },
                                        "data_rssi_threshold": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.coverageHoleDetectionProperties.chdDataRssiThreshold",
                                        },
                                        "voice_rssi_threshold": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.coverageHoleDetectionProperties.chdVoiceRssiThreshold",
                                        },
                                        "exception_level": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.coverageHoleDetectionProperties.chdExceptionLevel",
                                        },
                                    }
                                ),
                            },
                            "flexible_radio_assigment": {
                                "type": "dict",
                                # "source_key": "fraPropertiesC",
                                "options": OrderedDict(
                                    {
                                        "client_reset_count": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.fraPropertiesC.clientResetCount",
                                        },
                                        "client_utilization_thresthold": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.fraPropertiesC.clientUtilizationThreshold",
                                        },
                                    }
                                ),
                            },
                            "discovery_frames_6ghz": {
                                "type": "str",
                                "source_key": "radioType6GHzProperties.discoveryFrames6GHz",
                            },
                            "broadcast_probe_response_interval": {
                                "type": "int",
                                "source_key": "radioType6GHzProperties.broadcastProbeResponseInterval",
                            },
                            "multi_bssid": {
                                "type": "dict",
                                "source_key": "multiBssidProperties",
                                "options": OrderedDict(
                                    {
                                        "dot_11ax_parameters": {
                                            "type": "dict",
                                            "source_key": "radioType6GHzProperties.multiBssidProperties.dot11axParameters",
                                            "options": OrderedDict(
                                                {
                                                    "ofdma_downlink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11axParameters.ofdmaDownLink",
                                                    },
                                                    "ofdma_uplink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11axParameters.ofdmaUpLink",
                                                    },
                                                    "mu_mimo_downlink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11axParameters.muMimoDownLink",
                                                    },
                                                    "mu_mimo_uplink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11axParameters.muMimoUpLink",
                                                    },
                                                }
                                            ),
                                        },
                                        "dot_11be_parameters": {
                                            "type": "dict",
                                            "source_key": "multiBssidProperties.dot11beParameters",
                                            "options": OrderedDict(
                                                {
                                                    "ofdma_downlink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11beParameters.ofdmaDownLink",
                                                    },
                                                    "ofdma_uplink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11beParameters.ofdmaUpLink",
                                                    },
                                                    "mu_mimo_downlink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11beParameters.muMimoDownLink",
                                                    },
                                                    "mu_mimo_uplink": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11beParameters.muMimoUpLink",
                                                    },
                                                    "ofdma_multi_ru": {
                                                        "type": "bool",
                                                        "source_key": "radioType6GHzProperties.multiBssidProperties.dot11beParameters.ofdmaMultiRu",
                                                    },
                                                }
                                            ),
                                        },
                                        "target_waketime": {
                                            "type": "bool",
                                            "source_key": "radioType6GHzProperties.multiBssidProperties.targetWakeTime",
                                        },
                                        "twt_broadcast_support": {
                                            "type": "bool",
                                            "source_key": "radioType6GHzProperties.multiBssidProperties.twtBroadcastSupport",
                                        },
                                    }
                                ),
                            },
                            "spatial_reuse": {
                                "type": "dict",
                                "source_key": "spatialReuseProperties",
                                "options": OrderedDict(
                                    {
                                        "non_srg_obss_pd": {
                                            "type": "bool",
                                            "source_key": "radioType6GHzProperties.spatialReuseProperties.dot11axNonSrgObssPacketDetect",
                                        },
                                        "non_srg_obss_pd_max_threshold": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.spatialReuseProperties.dot11axNonSrgObssPacketDetectMaxThreshold",
                                        },
                                        "srg_obss_pd": {
                                            "type": "bool",
                                            "source_key": "radioType6GHzProperties.spatialReuseProperties.dot11axSrgObssPacketDetect",
                                        },
                                        "srg_obss_pd_min_threshold": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.spatialReuseProperties.dot11axSrgObssPacketDetectMinThreshold",
                                        },
                                        "srg_obss_pd_max_threshold": {
                                            "type": "int",
                                            "source_key": "radioType6GHzProperties.spatialReuseProperties.dot11axSrgObssPacketDetectMaxThreshold",
                                        },
                                    }
                                ),
                            },
                        }
                    ),
                },
            }
        )
        return radio_frequency_profiles_temp_spec

    def get_wireless_radio_frequency_profiles(
        self, network_element, component_specific_filters=None
    ):
        # Extract API family and function from network_element
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting wireless Radio Frequency Profiles using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        # Determine parameters based on component_specific_filters
        if component_specific_filters:
            params = {}
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            params = {}
            self.log("Using global site details for API call.", "INFO")

        # Execute API call to retrieve Radio Frequency Profiles details
        radio_frequency_profiles_details = self.execute_get_with_pagination(
            api_family, api_function, params
        )
        self.log(
            "Retrieved Radio Frequency Profiles details: {0}".format(
                radio_frequency_profiles_details
            ),
            "INFO",
        )

        # Modify Radio Frequency Profiles details using temp_spec
        rf_profiles_temp_spec = self.wireless_radio_frequency_profiles_temp_spec()
        modified_rf_profiles_details = self.modify_parameters(
            rf_profiles_temp_spec, radio_frequency_profiles_details
        )
        self.log(
            "Modified Radio Frequency Profiles details: {0}".format(
                modified_rf_profiles_details
            ),
            "INFO",
        )

        rf_profiles = {"radio_frequency_profiles": modified_rf_profiles_details}
        self.log("Modified RF Profiles: {0}".format(rf_profiles), "INFO")
        return rf_profiles

    def wireless_anchor_groups_temp_spec(self):
        priority_mapping = {"PRIMARY": 1, "SECONDARY": 2, "TERTIARY": 3}
        anchor_groups_temp_spec = OrderedDict(
            {
                "anchor_group_name": {"type": "str", "source_key": "anchorGroupName"},
                "mobility_anchors": {
                    "type": "list",
                    "elements": "dict",
                    "source_key": "mobilityAnchors",
                    "options": OrderedDict(
                        {
                            "device_name": {"type": "str", "source_key": "deviceName"},
                            "device_ip_address": {
                                "type": "str",
                                "source_key": "ipAddress",
                            },
                            "device_mac_address": {
                                "type": "str",
                                "source_key": "macAddress",
                            },
                            "device_type": {
                                "type": "str",
                                "source_key": "peerDeviceType",
                            },
                            "device_priority": {
                                "type": "str",
                                "source_key": "anchorPriority",
                                "transform": lambda priority: priority_mapping.get(
                                    priority
                                ),
                            },
                            "device_nat_ip_address": {
                                "type": "str",
                                "source_key": "privateIp",
                            },
                            "mobility_group_name": {
                                "type": "str",
                                "source_key": "mobilityGroupName",
                            },
                            "managed_device": {
                                "type": "bool",
                                "source_key": "managedAnchorWlc",
                            },
                        }
                    ),
                },
            }
        )
        return anchor_groups_temp_spec

    def get_wireless_anchor_groups(
        self, network_element, component_specific_filters=None
    ):
        # Extract API family and function from network_element
        api_family = network_element.get("api_family")
        api_function = network_element.get("api_function")
        self.log(
            "Getting wireless Anchor Groups using family '{0}' and function '{1}'.".format(
                api_family, api_function
            ),
            "INFO",
        )

        # Determine parameters based on component_specific_filters
        if component_specific_filters:
            params = {}
            self.log("Using component-specific filters for API call.", "INFO")
        else:
            params = {}
            self.log("Using global site details for API call.", "INFO")

        # Check the DNAC version and decide the API execution method
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") <= 0:
            self.log("Using 'execute_get_request' for version <= 2.3.7.9", "DEBUG")
            # Execute the GET request to retrieve anchor groups
            api_response = self.execute_get_request(api_family, api_function, params)
            # Attempt to extract anchor groups from the response
            anchor_groups_details = (
                api_response.get("response", []) if api_response else []
            )
        else:
            self.log(
                "Using 'execute_get_with_pagination' for version > 2.3.7.9", "DEBUG"
            )
            # Execute the GET request with pagination
            anchor_groups_details = (
                self.execute_get_with_pagination(api_family, api_function, params) or []
            )

        self.log(
            "Retrieved Anchor Groups details: {0}".format(anchor_groups_details), "INFO"
        )

        # Modify Anchor Groups details using temp_spec
        anchor_groups_temp_spec = self.wireless_anchor_groups_temp_spec()
        modified_anchor_groups_details = self.modify_parameters(
            anchor_groups_temp_spec, anchor_groups_details
        )
        self.log(
            "Modified Anchor Groups details: {0}".format(
                modified_anchor_groups_details
            ),
            "INFO",
        )

        anchor_groups = {"anchor_groups": modified_anchor_groups_details}
        self.log("Modified Anchor Groups: {0}".format(anchor_groups), "INFO")
        return anchor_groups

    def modify_parameters(self, temp_spec, details_list):
        self.log("Details list: {0}".format(details_list), "DEBUG")
        modified_details = []
        self.log("Starting modification of parameters based on temp_spec.", "INFO")

        for index, detail in enumerate(details_list):
            mapped_detail = OrderedDict()  # Use OrderedDict to preserve order
            self.log("Processing detail {0}: {1}".format(index, detail), "DEBUG")

            for key, spec in temp_spec.items():
                self.log(
                    "Processing key '{0}' with spec: {1}".format(key, spec), "DEBUG"
                )

                source_key = spec.get("source_key", key)
                value = detail.get(source_key)
                self.log(
                    "Retrieved value for source key '{0}': {1}".format(
                        source_key, value
                    ),
                    "DEBUG",
                )

                transform = spec.get("transform", lambda x: x)
                self.log(
                    "Using transformation function for key '{0}'.".format(key), "DEBUG"
                )

                if spec["type"] == "dict":
                    mapped_detail[key] = self.modify_parameters(
                        spec["options"], [detail]
                    )[0]
                    self.log(
                        "Mapped nested dictionary for key '{0}': {1}".format(
                            key, mapped_detail[key]
                        ),
                        "DEBUG",
                    )
                elif spec["type"] == "list":
                    if spec.get("special_handling"):
                        self.log(
                            "Special handling detected for key '{0}'.".format(key),
                            "DEBUG",
                        )
                        mapped_detail[key] = transform(detail)
                        self.log(
                            "Mapped detail for key '{0}' using special handling: {1}".format(
                                key, mapped_detail[key]
                            ),
                            "DEBUG",
                        )
                    else:
                        if isinstance(value, list):
                            mapped_detail[key] = [
                                (
                                    self.modify_parameters(spec["options"], [v])[0]
                                    if isinstance(v, dict)
                                    else transform(v)
                                )
                                for v in value
                            ]
                        else:
                            mapped_detail[key] = transform(value) if value else []
                    self.log(
                        "Mapped list for key '{0}' with transformation: {1}".format(
                            key, mapped_detail[key]
                        ),
                        "DEBUG",
                    )
                elif spec["type"] == "str" and spec.get("special_handling"):
                    self.log(
                        "Special handling for string type detected for key '{0}'.".format(
                            key
                        ),
                        "DEBUG",
                    )
                    mapped_detail[key] = transform(detail)
                    self.log(
                        "Mapped string for key '{0}' using special handling: {1}".format(
                            key, mapped_detail[key]
                        ),
                        "DEBUG",
                    )
                else:
                    mapped_detail[key] = transform(value)
                    self.log(
                        "Mapped '{0}' to '{1}' with transformed value: {2}".format(
                            source_key, key, mapped_detail[key]
                        ),
                        "DEBUG",
                    )

            modified_details.append(mapped_detail)
            self.log(
                "Finished processing detail {0}. Mapped detail: {1}".format(
                    index, mapped_detail
                ),
                "INFO",
            )

        self.log("Completed modification of all details.", "INFO")
        return modified_details

    def write_dict_to_yaml(self, data_dict, file_path):
        try:
            self.log("Starting conversion of dictionary to YAML format.", "INFO")
            yaml_content = yaml.dump(
                data_dict, Dumper=OrderedDumper, default_flow_style=False
            )
            yaml_content = "---\n" + yaml_content
            self.log("Dictionary successfully converted to YAML format.", "DEBUG")

            # Ensure the directory exists
            self.ensure_directory_exists(file_path)

            self.log(
                "Preparing to write YAML content to file: {0}".format(file_path), "INFO"
            )
            with open(file_path, "w") as yaml_file:
                yaml_file.write(yaml_content)

            self.log(
                "Successfully written YAML content to {0}.".format(file_path), "INFO"
            )
            return True

        except Exception as e:
            self.msg = "An error occurred while writing to {0}: {1}".format(
                file_path, str(e)
            )
            self.fail_and_exit(self.msg)

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

            filters = {
                key: component_specific_filters[key]
                for key in network_element.get("filters", [])
                if key in component_specific_filters
            }
            self.log("Filters for {0}: {1}".format(component, filters), "DEBUG")

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
        self.log("Starting 'get_diff_merged' operation.", "INFO")

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

        return self


def main():
    """main entry point for module execution"""
    # Define the specification for the module"s arguments
    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
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
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    # Initialize the NetworkCompliance object with the module
    ccc_wireless_design_playbook_generator = WirelessDesignPlaybookGenerator(module)
    if (
        ccc_wireless_design_playbook_generator.compare_dnac_versions(
            ccc_wireless_design_playbook_generator.get_ccc_version(), "2.3.7.9"
        )
        < 0
    ):
        ccc_wireless_design_playbook_generator.msg = (
            "The specified version '{0}' does not support the YAML Playbook generation "
            "for Wireless Design Module. Supported versions start from '2.3.7.9' onwards. "
            "Version '2.3.7.9' introduces APIs for retrieving the wireless settings for "
            "the following components: SSID(s), Interface(s), Power Profile(s), Access "
            "Point Profile(s), Radio Frequency Profile(s), Anchor Group(s) from the "
            "Catalyst Center".format(
                ccc_wireless_design_playbook_generator.get_ccc_version()
            )
        )
        ccc_wireless_design_playbook_generator.set_operation_result(
            "failed", False, ccc_wireless_design_playbook_generator.msg, "ERROR"
        ).check_return_status()

    # Get the state parameter from the provided parameters
    state = ccc_wireless_design_playbook_generator.params.get("state")

    # Check if the state is valid
    if state not in ccc_wireless_design_playbook_generator.supported_states:
        ccc_wireless_design_playbook_generator.status = "invalid"
        ccc_wireless_design_playbook_generator.msg = "State {0} is invalid".format(
            state
        )
        ccc_wireless_design_playbook_generator.check_return_status()

    # Validate the input parameters and check the return status
    ccc_wireless_design_playbook_generator.validate_input().check_return_status()

    # Iterate over the validated configuration parameters
    for config in ccc_wireless_design_playbook_generator.validated_config:
        ccc_wireless_design_playbook_generator.reset_values()
        ccc_wireless_design_playbook_generator.get_want(
            config, state
        ).check_return_status()
        ccc_wireless_design_playbook_generator.get_diff_state_apply[
            state
        ]().check_return_status()

    module.exit_json(**ccc_wireless_design_playbook_generator.result)


if __name__ == "__main__":
    main()
