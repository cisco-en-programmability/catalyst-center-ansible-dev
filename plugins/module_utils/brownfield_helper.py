#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
import datetime
import os
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
__metaclass__ = type
from abc import ABCMeta



class BrownFieldHelper():

    """Class contains members which can be reused for all workflow brownfield modules"""

    __metaclass__ = ABCMeta

    def __init__(self):
        pass

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

            # Start the loop for paginated API calls
            while True:
                # Update parameters for pagination
                update_params(offset, limit)

                try:
                    # Execute the API call
                    self.log(
                        "Attempting API call with {0} offset and limit for family '{1}', function '{2}': {3}".format(
                            offset,
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
        invalid_components = []

        for component in components_list:
            if component not in network_elements:
                invalid_components.append(component)

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
        invalid_filters = []
        for filter_name in component_specific_filters.keys():
            if filter_name == "components_list":
                self.log(
                    "Skipping 'components_list' filter validation for module '{0}'.".format(
                        self.module_name
                    ),
                    "DEBUG",
                )
                continue

            filter_params_list = component_specific_filters.get(filter_name, {})
            if not filter_params_list:
                self.log(
                    "No filters provided for '{0}' in module '{1}'. Skipping validation.".format(
                        filter_name, self.module_name
                    ),
                    "DEBUG",
                )
                continue
            # Check if the filter name is valid
            for item in filter_params_list:
                for param in item.keys():
                    if param not in valid_filters:
                        self.log(
                            "Invalid filter '{0}' provided for module '{1}'. Valid filters are: {2}".format(
                                param, self.module_name, valid_filters
                            ),
                            "ERROR",
                        )
                        # Add invalid filter to the list
                        invalid_filters.append(param)

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

    def write_dict_to_yaml(self, data_dict, file_path):
        """
        Converts a dictionary to YAML format and writes it to a specified file path.

        Args:
            data_dict (dict): The dictionary to convert to YAML format.
            file_path (str): The path where the YAML file will be written.

        Returns:
            bool: True if the YAML file was successfully written, False otherwise.
        """

        self.log(
            "Starting to write dictionary to YAML file at: {0}".format(file_path), "DEBUG"
        )
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

    def modify_parameters(self, temp_spec, details_list):
        """
        Modifies the parameters of the provided details_list based on the temp_spec.

        Args:
            temp_spec (OrderedDict): An ordered dictionary defining the structure and transformation rules for the parameters.
            details_list (list): A list of dictionaries containing the details to be modified.

        Returns:
            list: A list of dictionaries containing the modified details based on the temp_spec.
        """

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
                        # Handle nested dictionary mapping
                        self.log(
                            "Mapping nested dictionary for key '{0}'.".format(key),
                            "DEBUG",
                        )
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
                    mapped_detail[key] = transform(detail)
                    self.log(
                        "Mapped detail for key '{0}' using special handling: {1}".format(
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

    def get_site_id_from_fabric_site_or_zones(self, fabric_id, fabric_type):
        """
        Retrieves the site ID from fabric sites or zones based on the provided fabric ID and type.
        Args:
            fabric_id (str): The ID of the fabric site or zone.
            fabric_type (str): The type of fabric, either "fabric_site" or "fabric_zone".
        Returns:
            str: The site ID retrieved from the fabric site or zones.
        Raises:
            Exception: If an error occurs while retrieving the site ID.
        """

        site_id = None
        self.log(
            "Retrieving site ID from fabric site or zones for fabric_id: {0}, fabric_type: {1}".format(
                fabric_id, fabric_type
            ),
            "DEBUG"
        )

        if fabric_type == "fabric_site":
            function_name = "get_fabric_sites"
        else:
            function_name = "get_fabric_zones"

        try:
            response = self.dnac._exec(
                family="sda",
                function=function_name,
                op_modifies=False,
                params={"id": fabric_id},
            )
            response = response.get("response")
            self.log(
                "Received API response from '{0}': {1}".format(
                    function_name, str(response)
                ),
                "DEBUG"
            )

            if not response:
                self.msg = "No fabric sites or zones found for fabric_id: {0} with type: {1}".format(
                    fabric_id, fabric_type
                )
                return site_id

            site_id = response[0].get("siteId")
            self.log(
                "Retrieved site ID: {0} from fabric site or zones.".format(site_id),
                "DEBUG"
            )

        except Exception as e:
            self.msg = """Error while getting the details of fabric site or zones with ID '{0}' and type '{1}': {2}""".format(
                fabric_id, fabric_type, str(e)
            )
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        return site_id

    def analyse_fabric_site_or_zone_details(self, fabric_id):
        """
        Analyzes the fabric site or zone details to determine the site ID and fabric type.
        Args:
            fabric_id (str): The ID of the fabric site or zone.
        Returns:
            tuple: A tuple containing the site ID and fabric type.
                - site_id (str): The ID of the fabric site or zone.
                - fabric_type (str): The type of fabric, either "fabric_site" or "fabric_zone".
        """

        self.log(
            "Analyzing fabric site or zone details for fabric_id: {0}".format(fabric_id),
            "DEBUG"
        )
        site_id, fabric_type = None, None

        site_id = self.get_site_id_from_fabric_site_or_zones(fabric_id, "fabric_site")
        if not site_id:
            site_id = self.get_site_id_from_fabric_site_or_zones(fabric_id, "fabric_zone")
            if not site_id:
                return None, None

            self.log(
                "Fabric zone ID '{0}' retrieved successfully.".format(site_id),
                "DEBUG"
            )
            return site_id, "fabric_zone"

        self.log(
            "Fabric site ID '{0}' retrieved successfully.".format(site_id),
            "DEBUG"
        )
        return site_id, "fabric_site"

    def get_site_name(self, site_id):
        """
        Retrieves the site name hierarchy for a given site ID.
        Args:
            site_id (str): The ID of the site for which to retrieve the name hierarchy.
        Returns:
            str: The name hierarchy of the site.
        Raises:
            Exception: If an error occurs while retrieving the site name hierarchy.
        """

        self.log(
            "Retrieving site name hierarchy for site_id: {0}".format(site_id), "DEBUG"
        )
        api_family, api_function, params = "site_design", "get_sites", {}
        site_details = self.execute_get_with_pagination(
            api_family, api_function, params
        )
        if not site_details:
            self.msg = "No site details found for site_id: {0}".format(site_id)
            self.fail_and_exit(self.msg)

        site_name_hierarchy = None
        for site in site_details:
            if site.get("id") == site_id:
                site_name_hierarchy = site.get("nameHierarchy")
                break

        # If site_name_hierarchy is not found, log an error and exit
        if not site_name_hierarchy:
            self.msg = "Site name hierarchy not found for site_id: {0}".format(site_id)
            self.fail_and_exit(self.msg)

        self.log(
            "Site name hierarchy for site_id '{0}': {1}".format(
                site_id, site_name_hierarchy
            ),
            "INFO"
        )

        return site_name_hierarchy

    def get_site_id_name_mapping(self):
        """
        Retrieves the site name hierarchy for a given site ID.
        Args:
            
        Returns:
            str: The name hierarchy of the site.
        Raises:
            Exception: If an error occurs while retrieving the site name hierarchy.
        """

        self.log(
            "Retrieving site name hierarchy for all sites.", "DEBUG"
        )
        self.log("Executing 'get_sites' API call to retrieve all sites.", "DEBUG")
        site_id_name_mapping = {}

        api_family, api_function, params = "site_design", "get_sites", {}
        site_details = self.execute_get_with_pagination(
            api_family, api_function, params
        )

        for site in site_details:
            site_id = site.get("id")
            if site_id:
                site_id_name_mapping[site_id] = site.get("nameHierarchy")

        return site_id_name_mapping


def main():
    pass


if __name__ == "__main__":
    main()
