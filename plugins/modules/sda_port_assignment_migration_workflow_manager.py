#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to migrate SD-Access port assignments and port channels between fabric devices in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Rugvedi Kapse"
DOCUMENTATION = r"""
---
module: sda_port_assignment_migration_workflow_manager
short_description: Migrate SDA port assignments and port channels between fabric devices
  in Cisco Catalyst Center.
description:
  - This module migrates SD-Access (SDA) port assignments and port channels from a source device
    to a destination device within the same fabric site on Cisco Catalyst Center.
  - Both the source and destination devices must be provisioned in the same SD-Access fabric site.
  - The migration is idempotent. Existing configuration on the destination that already matches
    the source is skipped, configuration that differs is updated, and missing configuration is
    created.
  - Supports migrating using the SAME interface names on both devices, or selective migration
    with explicit interface mapping that supports interface renaming (for example, when moving
    configuration between different hardware models or stack member numbers).
  - When an interface mapping is provided, ALL member interfaces of a port channel must be
    covered by the mapping. Port channels with partially-mapped members are treated as a
    configuration error.
  - Port channels are matched between source and destination by intersection of their member
    interface names (after applying any interface mapping). Catalyst Center does not allow the
    BGP protocol (ON / LACP / PAGP) of a port channel to be updated once created. Attempting
    a protocol change results in a hard failure.
  - Supports Cisco Catalyst Center versions 2.3.7.6 and later.
version_added: '6.45.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Rugvedi Kapse (@rukapse)
options:
  config_verify:
    description:
      - Set to C(true) to verify the Cisco Catalyst Center configuration after applying the
        playbook. When enabled, the module re-reads the destination device's port assignments
        and port channels after migration and logs any discrepancies from the source.
    type: bool
    default: false
  state:
    description:
      - The desired state of the migration operation.
      - Only C(merged) is supported - the module migrates (creates or updates) port
        assignments and port channels from source to destination.
    type: str
    choices: ["merged"]
    default: merged
  sda_fabric_port_channel_limit:
    description:
      - Maximum number of port channels to include in a single API batch.
      - Applied to both the C(add_port_channels) and C(update_port_channels) API calls.
    type: int
    default: 20
  config:
    description:
      - List of migration configuration entries. Each entry defines one source-to-destination
        migration within a fabric site.
    type: list
    elements: dict
    required: true
    suboptions:
      fabric_site_name_hierarchy:
        description:
          - Full site hierarchy path of the SD-Access fabric site where BOTH the source and
            destination devices are provisioned.
          - Must start with C(Global/).
        type: str
        required: true
      source_device:
        description:
          - Dictionary identifying the source device from which port assignments and port
            channels will be read.
          - At least one of C(ip_address) or C(hostname) must be provided.
          - The source device must be reachable, in C(Managed) collection status, must be
            a switch or router (not a C(Unified AP)), and must be provisioned in the specified
            fabric site.
          - The source device must have at least one port assignment configured, otherwise the
            module fails - there is nothing to migrate.
        type: dict
        required: true
        suboptions:
          ip_address:
            description:
              - Management IP address of the source device as shown in Catalyst Center
                inventory.
            type: str
          hostname:
            description:
              - Hostname of the source device as shown in Catalyst Center inventory.
            type: str
      destination_device:
        description:
          - Dictionary identifying the destination device where port assignments and port
            channels will be migrated to.
          - At least one of C(ip_address) or C(hostname) must be provided.
          - Must reference a DIFFERENT device than the source. Identical C(ip_address) or
            C(hostname) across source and destination is a configuration error.
          - The destination device must be reachable, in C(Managed) collection status, must be
            a switch or router, and must be provisioned in the specified fabric site.
          - Any interface referenced by the migration (either directly or via interface mapping)
            must exist on the destination device.
        type: dict
        required: true
        suboptions:
          ip_address:
            description:
              - Management IP address of the destination device as shown in Catalyst Center
                inventory.
            type: str
          hostname:
            description:
              - Hostname of the destination device as shown in Catalyst Center inventory.
            type: str
      interface_mapping:
        description:
          - Optional list of interface-name translation entries.
          - When omitted, ALL source port assignments and port channels are migrated using the
            SAME interface names on the destination device. The destination must have all of
            those interfaces.
          - When provided, ONLY the source interfaces listed are migrated as port assignments.
            Their port assignment is applied to the corresponding C(destination_interface).
          - For port channels, the mapping is applied to each member interface. If a port
            channel's members are not ALL covered by the mapping, the module fails with an
            error - partial mapping is not supported because it would produce ambiguous results.
          - Must not contain duplicate C(source_interface) values or duplicate
            C(destination_interface) values.
        type: list
        elements: dict
        suboptions:
          source_interface:
            description:
              - Interface name on the source device. Must match an existing interface on the
                source device. For port assignment migration, the interface must also have a
                port assignment configured on the source device.
            type: str
            required: true
          destination_interface:
            description:
              - Interface name on the destination device. Must match an existing interface on
                the destination device.
            type: str
            required: true

requirements:
  - dnacentersdk >= 2.9.2
  - python >= 3.9
notes:
  - SDK Methods used are
    - devices.Devices.get_device_list
    - devices.Devices.get_interface_info_by_id
    - sites.Sites.get_site
    - site_design.SiteDesigns.get_sites
    - sda.Sda.get_fabric_sites
    - sda.Sda.get_fabric_devices
    - sda.Sda.get_port_assignments
    - sda.Sda.add_port_assignments
    - sda.Sda.update_port_assignments
    - sda.Sda.get_port_channels
    - sda.Sda.add_port_channels
    - sda.Sda.update_port_channels
    - task.Task.get_tasks_by_id
    - task.Task.get_task_details_by_id
  - Paths used are
    - GET /dna/intent/api/v1/network-device
    - GET /dna/intent/api/v1/interface/network-device/{deviceId}
    - GET /dna/intent/api/v1/site
    - GET /dna/intent/api/v1/sda/fabricSites
    - GET /dna/intent/api/v1/sda/fabricDevices
    - GET /dna/intent/api/v1/sda/portAssignments
    - POST /dna/intent/api/v1/sda/portAssignments
    - PUT /dna/intent/api/v1/sda/portAssignments
    - GET /dna/intent/api/v1/sda/portChannels
    - POST /dna/intent/api/v1/sda/portChannels
    - PUT /dna/intent/api/v1/sda/portChannels
"""

EXAMPLES = r"""
---
- name: Migrate all port assignments and port channels using IP addresses
    (source and destination have the same interface names)
  cisco.dnac.sda_port_assignment_migration_workflow_manager:
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
    config_verify: true
    config:
      - fabric_site_name_hierarchy: "Global/USA/SAN-JOSE/BLDG23"
        source_device:
          ip_address: "204.1.2.5"
        destination_device:
          ip_address: "204.1.2.6"

- name: Migrate all port assignments and port channels using device hostnames
  cisco.dnac.sda_port_assignment_migration_workflow_manager:
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
    config_verify: true
    config:
      - fabric_site_name_hierarchy: "Global/USA/SAN-JOSE/BLDG23"
        source_device:
          hostname: "IAC-TB4-SJ-EN1-9300"
        destination_device:
          hostname: "IAC-TB4-SJ-EN2-9300"

- name: Migrate selected port assignments with same interface names
    (each listed source_interface is migrated to an identically named
    destination_interface)
  cisco.dnac.sda_port_assignment_migration_workflow_manager:
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
    config_verify: true
    config:
      - fabric_site_name_hierarchy: "Global/USA/SAN-JOSE/BLDG23"
        source_device:
          ip_address: "204.1.2.5"
        destination_device:
          ip_address: "204.1.2.6"
        interface_mapping:
          - source_interface: "GigabitEthernet1/0/5"
            destination_interface: "GigabitEthernet1/0/5"
          - source_interface: "GigabitEthernet1/0/6"
            destination_interface: "GigabitEthernet1/0/6"
          - source_interface: "GigabitEthernet1/0/8"
            destination_interface: "GigabitEthernet1/0/8"

- name: Migrate port assignments with interface renaming across switch stack members
    (useful when replacing a single-member switch with a stack,
    or migrating between different hardware models)
  cisco.dnac.sda_port_assignment_migration_workflow_manager:
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
    config_verify: true
    config:
      - fabric_site_name_hierarchy: "Global/USA/SAN-JOSE/BLDG23"
        source_device:
          ip_address: "204.1.2.5"
        destination_device:
          ip_address: "204.1.2.6"
        interface_mapping:
          - source_interface: "GigabitEthernet1/0/1"
            destination_interface: "GigabitEthernet2/0/1"
          - source_interface: "GigabitEthernet1/0/2"
            destination_interface: "GigabitEthernet2/0/2"
          - source_interface: "GigabitEthernet1/0/3"
            destination_interface: "GigabitEthernet2/0/3"

- name: Migrate both port assignments and port channels using identical interface names
    (port channels are ALWAYS migrated along with port assignments - this example
    explicitly highlights that behavior. With no interface_mapping, the source
    device's port channel member interfaces must exist on the destination device.)
  cisco.dnac.sda_port_assignment_migration_workflow_manager:
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
    config_verify: true
    config:
      - fabric_site_name_hierarchy: "Global/USA/SAN-JOSE/BLDG23"
        source_device:
          ip_address: "204.1.2.5"
        destination_device:
          ip_address: "204.1.2.6"

- name: Migrate port assignments and port channels with interface mapping that covers
    ALL port channel member interfaces
    (assume source has port channel Po1 with members Gi1/0/10 and Gi1/0/11, and
    port channel Po2 with members Gi1/0/20 and Gi1/0/21. The mapping MUST include
    every member of every port channel on the source device, otherwise the module
    fails with a partial-mapping error.)
  cisco.dnac.sda_port_assignment_migration_workflow_manager:
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
    config_verify: true
    config:
      - fabric_site_name_hierarchy: "Global/USA/SAN-JOSE/BLDG23"
        source_device:
          ip_address: "204.1.2.5"
        destination_device:
          ip_address: "204.1.2.6"
        interface_mapping:
          # Standalone port-assignment interfaces
          - source_interface: "GigabitEthernet1/0/5"
            destination_interface: "GigabitEthernet2/0/5"
          - source_interface: "GigabitEthernet1/0/6"
            destination_interface: "GigabitEthernet2/0/6"
          # Port channel Po1 members - both members must be mapped
          - source_interface: "GigabitEthernet1/0/10"
            destination_interface: "GigabitEthernet2/0/10"
          - source_interface: "GigabitEthernet1/0/11"
            destination_interface: "GigabitEthernet2/0/11"
          # Port channel Po2 members - both members must be mapped
          - source_interface: "GigabitEthernet1/0/20"
            destination_interface: "GigabitEthernet2/0/20"
          - source_interface: "GigabitEthernet1/0/21"
            destination_interface: "GigabitEthernet2/0/21"
"""

RETURN = r"""
#Case 1: Successful migration of port assignments and port channels
response_1:
  description: Dictionary summarising what was added, updated, and skipped on the destination
    device. Interface lists are reported per operation type.
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "Add Port Assignment(s) Task Succeeded for following interface(s)": {
          "success_count": 3,
          "success_interfaces": ["GigabitEthernet2/0/1", "GigabitEthernet2/0/2", "GigabitEthernet2/0/3"]
        },
        "Update Port Assignment(s) Task Succeeded for following interface(s)": {
          "success_count": 1,
          "success_interfaces": ["GigabitEthernet2/0/4"]
        },
        "Port assignment does not needs any update for following interface(s)": {
          "success_count": 2,
          "port_assignments_no_update_needed": ["GigabitEthernet2/0/5", "GigabitEthernet2/0/6"]
        },
        "Add Port Channel(s) Task Succeeded for following port channel(s)": {
          "success_count": 1,
          "success_port_channels": ["Port-channel1"]
        }
      },
      "msg": String
    }

#Case 2: Idempotent run - no changes required (destination already matches source)
response_2:
  description: Dictionary reporting that every requested port assignment and port channel
    on the destination already matches the source. The C(changed) flag is C(false).
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "Port assignment does not needs any update for following interface(s)": {
          "success_count": 7,
          "port_assignments_no_update_needed": [
            "GigabitEthernet2/0/1", "GigabitEthernet2/0/2", "GigabitEthernet2/0/3",
            "GigabitEthernet2/0/4", "GigabitEthernet2/0/5", "GigabitEthernet2/0/6",
            "GigabitEthernet2/0/7"
          ]
        },
        "Port channel does not needs any update for following port channel(s)": {
          "success_count": 2,
          "port_channels_no_update_needed": ["Port-channel1", "Port-channel2"]
        }
      },
      "msg": String
    }

#Case 3: Port channel added and updated on the destination
response_3:
  description: Dictionary summarising port channel operations when a mix of create and
    update is performed on the destination (in addition to any port assignment operations).
    Port channels are reported by their C(portChannelName) as shown in Catalyst Center.
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "Add Port Channel(s) Task Succeeded for following port channel(s)": {
          "success_count": 2,
          "success_port_channels": ["Port-channel1", "Port-channel2"]
        },
        "Update Port Channel(s) Task Succeeded for following port channel(s)": {
          "success_count": 1,
          "success_port_channels": ["Port-channel3"]
        }
      },
      "msg": String
    }
"""


import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class SDAPortAssignmentMigration(DnacBase):
    """
    Migrate SDA port assignments and port channels between fabric devices in Cisco Catalyst Center.

    The module reads port assignments and port channels from a source fabric device and applies
    equivalent configuration to a destination fabric device within the SAME SD-Access fabric site.
    The operation is idempotent - identical configuration on the destination is skipped.
    """

    # Minimum Catalyst Center version that exposes the port assignment / port channel APIs.
    MIN_SUPPORTED_CCC_VERSION = "2.3.7.6"

    # Version from which `nativeVlanId` / `allowedVlanRanges` became first-class fields.
    NATIVE_VLAN_MIN_VERSION = "3.1.3.0"

    # API camelCase -> internal snake_case field mapping for port assignments.
    # Kept in one place so the comparison, payload building, and result code stay consistent.
    PORT_ASSIGNMENT_FIELD_MAP = [
        ("interfaceName", "interface_name"),
        ("connectedDeviceType", "connected_device_type"),
        ("dataVlanName", "data_vlan_name"),
        ("voiceVlanName", "voice_vlan_name"),
        ("authenticateTemplateName", "authentication_template_name"),
        ("interfaceDescription", "interface_description"),
        ("securityGroupName", "security_group_name"),
        ("nativeVlanId", "native_vlan_id"),
        ("allowedVlanRanges", "allowed_vlan_ranges"),
    ]

    # API camelCase -> internal snake_case field mapping for port channels.
    PORT_CHANNEL_FIELD_MAP = [
        ("portChannelName", "port_channel_name"),
        ("interfaceNames", "interface_names"),
        ("connectedDeviceType", "connected_device_type"),
        ("protocol", "protocol"),
        ("description", "description"),
        ("nativeVlanId", "native_vlan_id"),
        ("allowedVlanRanges", "allowed_vlan_ranges"),
    ]

    # Port channel connected device types (per Catalyst Center schema).
    VALID_PORT_CHANNEL_DEVICE_TYPES = {"TRUNK", "EXTENDED_NODE"}

    # Port channel protocols (per Catalyst Center schema). Catalyst Center rejects updates to
    # this field once a channel is created, so any attempted change is a hard failure.
    VALID_PORT_CHANNEL_PROTOCOLS = {"ON", "LACP", "PAGP"}

    # Loose sanity check for Cisco interface names - starts with letters, then digits,
    # optionally followed by slash-separated digit groups. Catalyst Center is the authority
    # on which interface names exist on a given device; this regex only catches obvious typos.
    INTERFACE_NAME_REGEX = re.compile(r"^[A-Za-z]+\d+(/\d+){0,3}(\.\d+)?$")

    def __init__(self, module):
        """
        Initialize an instance of the SDA Port Assignment Migration module.

        Args:
            module (AnsibleModule): The Ansible module instance holding the playbook parameters.

        Returns:
            None

        Description:
            Sets the list of supported states (only "merged" for migration) and defers the
            remainder of the initialization to the DnacBase parent class, which establishes
            SDK client, logger, result dict, and version fields.
        """
        self.supported_states = ["merged"]
        super().__init__(module)

    # --------------------------------------------------------------------
    # Input validation
    # --------------------------------------------------------------------

    def validate_input(self):
        """
        Validate the playbook configuration against the module's input schema and semantic rules.

        Returns:
            self (SDAPortAssignmentMigration): The same instance, with
                - self.validated_config populated on success.
                - self.msg set to a descriptive message.
                - self.status set to "success" or "failed".

        Description:
            Validation is performed in two passes. First, the structural / type validation is
            delegated to validate_list_of_dicts() using a temp_spec that mirrors the module's
            DOCUMENTATION suboptions. Second, a set of semantic checks specific to the migration
            use case is executed. If any check fails, set_operation_result is called with a failed
            status and the caller (main) is expected to invoke check_return_status() to exit.
        """
        if not self.config:
            self.msg = "Configuration is not available in the playbook for validation."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Structural schema. validate_list_of_dicts does not recurse into 'options', so nested
        # dicts (source_device, destination_device, interface_mapping entries) are validated
        # manually below.
        temp_spec = {
            "fabric_site_name_hierarchy": {"type": "str", "required": True},
            "source_device": {"type": "dict", "required": True},
            "destination_device": {"type": "dict", "required": True},
            "interface_mapping": {
                "type": "list",
                "elements": "dict",
                "required": False,
            },
        }

        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)
        if invalid_params:
            self.msg = (
                "Invalid parameters in playbook: {0}".format(invalid_params)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Semantic validation per config entry. Any failure here calls fail_and_exit via the
        # helpers, which short-circuits module execution with a clear error message.
        for index, config_entry in enumerate(valid_temp):
            self.log(
                "Validating config entry #{0}: {1}".format(index, config_entry),
                "DEBUG",
            )
            self._validate_fabric_site_hierarchy(config_entry.get("fabric_site_name_hierarchy"))
            self._validate_device_config(config_entry.get("source_device"), "source_device")
            self._validate_device_config(config_entry.get("destination_device"), "destination_device")
            self._validate_source_destination_not_same(
                config_entry.get("source_device"),
                config_entry.get("destination_device"),
            )
            self._validate_interface_mapping(config_entry.get("interface_mapping"))

        self.validated_config = valid_temp
        self.msg = (
            "Successfully validated the playbook configuration parameters for "
            "the SDA port assignment migration workflow."
        )
        self.set_operation_result("success", False, self.msg, "INFO")
        return self

    def _validate_fabric_site_hierarchy(self, hierarchy):
        """
        Validate that the fabric_site_name_hierarchy is non-empty and begins with "Global/".

        Args:
            hierarchy (str): The site hierarchy string from the playbook config entry.

        Returns:
            None

        Description:
            Catalyst Center site hierarchies always start at the "Global" root. Anything that
            does not is either a typo or refers to an unrelated path. This check catches those
            before we call out to the get_site API (which would also fail, but less clearly).
            Calls fail_and_exit with an actionable error on any failure.
        """
        if not hierarchy or not hierarchy.strip():
            self.fail_and_exit(
                "The 'fabric_site_name_hierarchy' is required and cannot be empty."
            )

        if not hierarchy.startswith("Global/") and hierarchy != "Global":
            self.fail_and_exit(
                "The 'fabric_site_name_hierarchy' must start with 'Global/' "
                "(for example, 'Global/USA/SAN-JOSE/BLDG23'). Received: '{0}'.".format(hierarchy)
            )

    def _validate_device_config(self, device_config, role):
        """
        Validate a source_device or destination_device dictionary.

        Args:
            device_config (dict): The device config dict from the playbook (expected keys:
                ip_address and/or hostname).
            role (str): Human-readable role identifier - either "source_device" or
                "destination_device" - used to produce clear error messages.

        Returns:
            None

        Description:
            Enforces the requirements that the device dict exists, contains at least one of
            ip_address or hostname as a non-empty string, and that any supplied ip_address is
            a valid IPv4 address (reusing DnacBase.is_valid_ipv4). The API layer could surface
            these issues later, but validating up front lets us fail before any network calls
            are made.
        """
        if not isinstance(device_config, dict):
            self.fail_and_exit(
                "The '{0}' must be a dictionary with at least one of 'ip_address' or "
                "'hostname'.".format(role)
            )

        ip_address = (device_config.get("ip_address") or "").strip()
        hostname = (device_config.get("hostname") or "").strip()

        if not ip_address and not hostname:
            self.fail_and_exit(
                "The '{0}' must provide at least one of 'ip_address' or 'hostname'.".format(role)
            )

        if ip_address and not self.is_valid_ipv4(ip_address):
            self.fail_and_exit(
                "The 'ip_address' provided in '{0}' is not a valid IPv4 address: '{1}'.".format(
                    role, ip_address
                )
            )

    def _validate_source_destination_not_same(self, source_device, destination_device):
        """
        Ensure the source and destination devices refer to different devices.

        Args:
            source_device (dict): The source device config.
            destination_device (dict): The destination device config.

        Returns:
            None

        Description:
            Compares ip_address to ip_address and hostname to hostname. A migration that points
            at the same device on both sides is a no-op at best and a data-corruption risk at
            worst (the module could mis-classify existing state as "requested" state). We fail
            fast rather than attempt to migrate.
        """
        src_ip = (source_device.get("ip_address") or "").strip()
        src_hostname = (source_device.get("hostname") or "").strip()
        dest_ip = (destination_device.get("ip_address") or "").strip()
        dest_hostname = (destination_device.get("hostname") or "").strip()

        if src_ip and dest_ip and src_ip == dest_ip:
            self.fail_and_exit(
                "'source_device' and 'destination_device' cannot reference the same device "
                "(ip_address: '{0}'). The migration target must be distinct from the source.".format(src_ip)
            )

        if src_hostname and dest_hostname and src_hostname == dest_hostname:
            self.fail_and_exit(
                "'source_device' and 'destination_device' cannot reference the same device "
                "(hostname: '{0}'). The migration target must be distinct from the source.".format(src_hostname)
            )

    def _validate_interface_mapping(self, interface_mapping):
        """
        Validate the optional interface_mapping list.

        Args:
            interface_mapping (list | None): The optional list of source-to-destination
                interface translations from the playbook config entry.

        Returns:
            None

        Description:
            When interface_mapping is omitted (None), there is nothing to validate - the module
            migrates all port assignments and port channels using the same interface names.
            When supplied, the following rules apply and produce a fail_and_exit on violation:
                - The list must be non-empty (an empty list means the user intended to constrain
                  the migration; an empty constraint is ambiguous).
                - Every entry must be a dict with non-empty string 'source_interface' and
                  'destination_interface' fields.
                - Interface names must pass a basic Cisco interface name sanity check.
                - No duplicate source_interface values and no duplicate destination_interface
                  values are permitted.
        """
        if interface_mapping is None:
            return

        if not isinstance(interface_mapping, list):
            self.fail_and_exit(
                "'interface_mapping' must be a list of dictionaries."
            )

        if len(interface_mapping) == 0:
            self.fail_and_exit(
                "'interface_mapping' cannot be an empty list. Omit the key entirely to migrate "
                "all interfaces using the same names, or provide at least one mapping entry."
            )

        seen_source = set()
        seen_destination = set()

        for index, entry in enumerate(interface_mapping):
            if not isinstance(entry, dict):
                self.fail_and_exit(
                    "Each 'interface_mapping' entry must be a dictionary. "
                    "Entry at index {0} is not a dictionary: {1}".format(index, entry)
                )

            source_interface = (entry.get("source_interface") or "").strip()
            destination_interface = (entry.get("destination_interface") or "").strip()

            if not source_interface:
                self.fail_and_exit(
                    "'interface_mapping' entry at index {0} has a missing or empty "
                    "'source_interface'.".format(index)
                )
            if not destination_interface:
                self.fail_and_exit(
                    "'interface_mapping' entry at index {0} has a missing or empty "
                    "'destination_interface'.".format(index)
                )

            if not self.INTERFACE_NAME_REGEX.match(source_interface):
                self.fail_and_exit(
                    "'source_interface' value '{0}' in 'interface_mapping' entry at index {1} "
                    "does not look like a valid Cisco interface name "
                    "(expected format like 'GigabitEthernet1/0/1').".format(source_interface, index)
                )
            if not self.INTERFACE_NAME_REGEX.match(destination_interface):
                self.fail_and_exit(
                    "'destination_interface' value '{0}' in 'interface_mapping' entry at index "
                    "{1} does not look like a valid Cisco interface name "
                    "(expected format like 'GigabitEthernet2/0/1').".format(destination_interface, index)
                )

            if source_interface in seen_source:
                self.fail_and_exit(
                    "Duplicate 'source_interface' value '{0}' in 'interface_mapping'. Each "
                    "source interface may appear at most once.".format(source_interface)
                )
            seen_source.add(source_interface)

            if destination_interface in seen_destination:
                self.fail_and_exit(
                    "Duplicate 'destination_interface' value '{0}' in 'interface_mapping'. "
                    "Each destination interface may appear at most once.".format(destination_interface)
                )
            seen_destination.add(destination_interface)

    # --------------------------------------------------------------------
    # State collection orchestration (get_have)
    # --------------------------------------------------------------------

    def get_have(self, config):
        """
        Collect the current state from Catalyst Center required to plan the migration.

        Args:
            config (dict): A single validated config entry from the playbook, as returned by
                validate_input().

        Returns:
            self (SDAPortAssignmentMigration): The instance with self.have populated. Key
                entries in self.have:
                    - fabric_id (str)
                    - source_device_id (str), source_device_ip (str)
                    - destination_device_id (str), destination_device_ip (str)
                    - source_port_assignments (list of API dicts in camelCase)
                    - destination_port_assignments (list of API dicts in camelCase)
                    - source_port_channels (list of API dicts in camelCase)
                    - destination_port_channels (list of API dicts in camelCase)
                    - interface_mapping (dict or None): {source_iface: dest_iface}

        Description:
            Performs every API-backed validation in the order described in the module-level
            documentation, in a fail-fast manner. No state-changing API call is issued during
            state collection. Each helper is responsible for its own error messaging and exits
            via fail_and_exit on failure.
        """
        fabric_site_name_hierarchy = config.get("fabric_site_name_hierarchy")
        source_device_config = config.get("source_device")
        destination_device_config = config.get("destination_device")
        interface_mapping_list = config.get("interface_mapping")

        self.log(
            "Starting state collection for migration within fabric site '{0}'.".format(
                fabric_site_name_hierarchy
            ),
            "INFO",
        )

        # 1. Resolve the fabric site. This must come first - without a fabric_id every
        #    downstream fabric device / port assignment / port channel API call is meaningless.
        fabric_id = self._resolve_fabric_id(fabric_site_name_hierarchy)

        # 2. Resolve source + destination devices. _resolve_device handles inventory presence,
        #    reachability, managed status, and the "not a Unified AP" guard.
        source_device_id, source_device_ip = self._resolve_device(
            source_device_config, "source_device"
        )
        destination_device_id, destination_device_ip = self._resolve_device(
            destination_device_config, "destination_device"
        )

        # 3. Both devices must be provisioned in the fabric site identified in step 1.
        self._validate_device_in_fabric(
            fabric_id,
            source_device_id,
            source_device_ip,
            fabric_site_name_hierarchy,
            "source_device",
        )
        self._validate_device_in_fabric(
            fabric_id,
            destination_device_id,
            destination_device_ip,
            fabric_site_name_hierarchy,
            "destination_device",
        )

        # 4. Fetch the physical interface list for each device. These sets are used to validate
        #    that every interface referenced by the migration (directly or via the interface
        #    mapping) actually exists on the target device.
        source_device_interfaces = self._get_device_interfaces(
            source_device_id, source_device_ip, "source_device"
        )
        destination_device_interfaces = self._get_device_interfaces(
            destination_device_id, destination_device_ip, "destination_device"
        )

        # 5. Fetch the port assignment state on both devices.
        source_port_assignments = self._get_port_assignments(
            fabric_id, source_device_id, "source_device", source_device_ip
        )
        destination_port_assignments = self._get_port_assignments(
            fabric_id, destination_device_id, "destination_device", destination_device_ip
        )

        # 6. Fetch the port channel state on both devices.
        source_port_channels = self._get_port_channels(
            fabric_id, source_device_id, "source_device", source_device_ip
        )
        destination_port_channels = self._get_port_channels(
            fabric_id, destination_device_id, "destination_device", destination_device_ip
        )

        # 7. Guard against a source device that has nothing to migrate.
        if not source_port_assignments and not source_port_channels:
            self.fail_and_exit(
                "Source device '{0}' has no port assignments and no port channels configured "
                "in fabric site '{1}'. There is nothing to migrate.".format(
                    source_device_ip, fabric_site_name_hierarchy
                )
            )

        # 8. Normalise the interface mapping into a lookup dict. When omitted, we build an
        #    identity mapping - every source interface maps to itself on the destination.
        interface_mapping = self._build_interface_mapping_lookup(
            interface_mapping_list,
            source_port_assignments,
            source_port_channels,
        )

        # 9. API-backed validation of the interface mapping. When interface_mapping was
        #    provided, validate each entry against the actual interfaces on source and
        #    destination. When it was not provided, validate that every interface we implicitly
        #    plan to migrate exists on the destination device.
        self._validate_interface_mapping_against_devices(
            interface_mapping_provided=(interface_mapping_list is not None),
            interface_mapping=interface_mapping,
            source_device_interfaces=source_device_interfaces,
            destination_device_interfaces=destination_device_interfaces,
            source_port_assignments=source_port_assignments,
            source_port_channels=source_port_channels,
            source_device_ip=source_device_ip,
            destination_device_ip=destination_device_ip,
        )

        # 10. Port-channel-specific semantic checks. These rely on the mapping having been
        #     validated above and on both source / destination port channel lists being
        #     available. Failures here point to protocol update attempts or destination-side
        #     membership conflicts that would be rejected by the Catalyst Center API later.
        self._validate_port_channels_consistency(
            source_port_channels=source_port_channels,
            destination_port_channels=destination_port_channels,
            interface_mapping=interface_mapping,
            source_device_ip=source_device_ip,
            destination_device_ip=destination_device_ip,
        )

        self.have = {
            "fabric_id": fabric_id,
            "fabric_site_name_hierarchy": fabric_site_name_hierarchy,
            "source_device_id": source_device_id,
            "source_device_ip": source_device_ip,
            "destination_device_id": destination_device_id,
            "destination_device_ip": destination_device_ip,
            "source_device_interfaces": source_device_interfaces,
            "destination_device_interfaces": destination_device_interfaces,
            "source_port_assignments": source_port_assignments,
            "destination_port_assignments": destination_port_assignments,
            "source_port_channels": source_port_channels,
            "destination_port_channels": destination_port_channels,
            "interface_mapping": interface_mapping,
        }

        self.log(
            "State collection complete. Source device '{0}' has {1} port assignment(s) and "
            "{2} port channel(s). Destination device '{3}' has {4} port assignment(s) and "
            "{5} port channel(s).".format(
                source_device_ip,
                len(source_port_assignments),
                len(source_port_channels),
                destination_device_ip,
                len(destination_port_assignments),
                len(destination_port_channels),
            ),
            "INFO",
        )

        self.msg = (
            "Successfully collected the current state for migration within fabric site '{0}'."
        ).format(fabric_site_name_hierarchy)
        self.status = "success"
        return self

    # --------------------------------------------------------------------
    # Resolution helpers (used by get_have)
    # --------------------------------------------------------------------

    def _resolve_fabric_id(self, fabric_site_name_hierarchy):
        """
        Resolve a site hierarchy string to a Catalyst Center fabric site ID.

        Args:
            fabric_site_name_hierarchy (str): Full "Global/..." hierarchy of the fabric site.

        Returns:
            str: The fabric_id (UUID) of the site.

        Description:
            First resolves the hierarchy to a site_id using DnacBase.get_site_id, then calls
            sda.get_fabric_sites to confirm the site is configured as an SDA fabric site and
            obtain its fabric_id. A site that exists in the hierarchy but is not a fabric site
            is a hard error.
        """
        self.log(
            "Resolving fabric_id for site '{0}'.".format(fabric_site_name_hierarchy),
            "DEBUG",
        )

        site_exists, site_id = self.get_site_id(fabric_site_name_hierarchy)
        if not site_exists or not site_id:
            # get_site_id typically calls fail_and_exit itself on missing site, but guard
            # defensively in case that behaviour changes.
            self.fail_and_exit(
                "Site '{0}' was not found in Catalyst Center. Create the site before running "
                "the port assignment migration.".format(fabric_site_name_hierarchy)
            )

        response = self.execute_get_request(
            "sda",
            "get_fabric_sites",
            {"site_id": site_id},
        )
        fabric_sites = (response or {}).get("response") or []

        if not fabric_sites:
            self.fail_and_exit(
                "Site '{0}' (site_id '{1}') is not configured as an SDA fabric site. Add the "
                "site to an SDA fabric before running the port assignment migration.".format(
                    fabric_site_name_hierarchy, site_id
                )
            )

        fabric_id = fabric_sites[0].get("id")
        if not fabric_id:
            self.fail_and_exit(
                "Received unexpected response from 'get_fabric_sites' for site '{0}': missing "
                "'id' field in response.".format(fabric_site_name_hierarchy)
            )

        self.log(
            "Resolved fabric_id '{0}' for site '{1}'.".format(
                fabric_id, fabric_site_name_hierarchy
            ),
            "DEBUG",
        )
        return fabric_id

    def _resolve_device(self, device_config, role):
        """
        Resolve a device config (IP or hostname) to (device_id, management_ip) and validate
        that the device is in a usable state for fabric operations.

        Args:
            device_config (dict): A source_device or destination_device dict with at least one
                of 'ip_address' or 'hostname'.
            role (str): "source_device" or "destination_device", used for error messages.

        Returns:
            tuple[str, str]: (device_id, management_ip_address).

        Description:
            Makes a single call to devices.get_device_list filtering by IP or hostname. Checks
            that the response contains exactly one device and that the device satisfies all
            migration prerequisites:
                - reachabilityStatus == "Reachable"
                - collectionStatus in {"Managed", "In Progress"}
                - family != "Unified AP"
            Any failure results in fail_and_exit with a role-aware error message.
        """
        ip_address = (device_config.get("ip_address") or "").strip()
        hostname = (device_config.get("hostname") or "").strip()
        identifier = ip_address if ip_address else hostname

        self.log(
            "Resolving {0} with identifier '{1}' from Catalyst Center inventory.".format(
                role, identifier
            ),
            "DEBUG",
        )

        if ip_address:
            api_params = {"management_ip_address": ip_address}
        else:
            api_params = {"hostname": hostname}

        response = self.execute_get_request("devices", "get_device_list", api_params)
        devices = (response or {}).get("response") or []

        if not devices:
            self.fail_and_exit(
                "The {0} '{1}' was not found in Catalyst Center inventory. Verify that the "
                "device is discovered and that the provided {2} is correct.".format(
                    role,
                    identifier,
                    "'ip_address'" if ip_address else "'hostname'",
                )
            )

        if len(devices) > 1:
            # A hostname filter can (in theory) return multiple devices if hostnames are not
            # unique. IP filters should not. Either way, we require an unambiguous match.
            self.fail_and_exit(
                "The {0} identifier '{1}' matched multiple devices in Catalyst Center "
                "inventory. Use a more specific identifier (for example, 'ip_address').".format(
                    role, identifier
                )
            )

        device = devices[0]
        device_id = device.get("id")
        management_ip = device.get("managementIpAddress")
        reachability_status = device.get("reachabilityStatus")
        collection_status = device.get("collectionStatus")
        device_family = device.get("family")

        if not device_id or not management_ip:
            self.fail_and_exit(
                "Received an unexpected response while resolving the {0} '{1}': the device "
                "record is missing 'id' or 'managementIpAddress'.".format(role, identifier)
            )

        if device_family == "Unified AP":
            self.fail_and_exit(
                "The {0} '{1}' is a Unified AP (family: '{2}') and cannot be used as a "
                "port-assignment migration endpoint. Only switches and routers are supported.".format(
                    role, identifier, device_family
                )
            )

        if reachability_status != "Reachable":
            self.fail_and_exit(
                "The {0} '{1}' is not reachable from Catalyst Center (reachabilityStatus: "
                "'{2}'). Restore reachability and resync the device before retrying the "
                "migration.".format(role, identifier, reachability_status)
            )

        if collection_status not in ("Managed", "In Progress"):
            self.fail_and_exit(
                "The {0} '{1}' is not in a manageable collection state (collectionStatus: "
                "'{2}'). Only devices with collectionStatus 'Managed' or 'In Progress' can be "
                "targets of a port-assignment migration.".format(
                    role, identifier, collection_status
                )
            )

        self.log(
            "Resolved {0} '{1}' -> device_id '{2}', management_ip '{3}'.".format(
                role, identifier, device_id, management_ip
            ),
            "DEBUG",
        )
        return device_id, management_ip

    def _validate_device_in_fabric(
        self, fabric_id, device_id, device_ip, fabric_site_name_hierarchy, role
    ):
        """
        Assert that a device is provisioned in the given SDA fabric site.

        Args:
            fabric_id (str): The fabric site UUID.
            device_id (str): The device UUID.
            device_ip (str): The device management IP (used only in error messages).
            fabric_site_name_hierarchy (str): The human-readable fabric site hierarchy.
            role (str): "source_device" or "destination_device" for contextual errors.

        Returns:
            None

        Description:
            Calls sda.get_fabric_devices with the (fabric_id, device_id) pair. An empty response
            means the device exists in the inventory but is not provisioned in the specified
            fabric. We fail with a message that tells the user to provision the device first,
            rather than letting the downstream port-assignment API return an opaque error.
        """
        response = self.execute_get_request(
            "sda",
            "get_fabric_devices",
            {"fabric_id": fabric_id, "network_device_id": device_id},
        )
        fabric_devices = (response or {}).get("response") or []

        if not fabric_devices:
            self.fail_and_exit(
                "The {0} '{1}' is not provisioned in fabric site '{2}'. Provision the device "
                "in the fabric before running the port-assignment migration.".format(
                    role, device_ip, fabric_site_name_hierarchy
                )
            )

        self.log(
            "Confirmed {0} '{1}' is provisioned in fabric site '{2}'. Device roles: {3}".format(
                role,
                device_ip,
                fabric_site_name_hierarchy,
                fabric_devices[0].get("deviceRoles"),
            ),
            "DEBUG",
        )

    def _get_device_interfaces(self, device_id, device_ip, role):
        """
        Return the set of physical interface names on a device.

        Args:
            device_id (str): The device UUID.
            device_ip (str): The device management IP (used for logging).
            role (str): "source_device" or "destination_device".

        Returns:
            set[str]: Set of portName strings for every interface on the device.

        Description:
            Used to validate that every interface referenced by the migration (either the
            source port-assignment interfaces themselves, or the source_interface /
            destination_interface in an interface_mapping) actually exists on the relevant
            device. A separate query per device keeps responsibilities clean.
        """
        response = self.execute_get_request(
            "devices",
            "get_interface_info_by_id",
            {"device_id": device_id},
        )
        interface_records = (response or {}).get("response") or []
        interfaces = {
            record.get("portName")
            for record in interface_records
            if record.get("portName")
        }

        self.log(
            "Fetched {0} interface name(s) for {1} '{2}'.".format(
                len(interfaces), role, device_ip
            ),
            "DEBUG",
        )
        return interfaces

    # --------------------------------------------------------------------
    # Paginated port assignment + port channel fetch
    # --------------------------------------------------------------------

    def _get_port_assignments(self, fabric_id, device_id, role, device_ip):
        """
        Retrieve every port assignment configured on a fabric device using pagination.

        Args:
            fabric_id (str): The fabric site UUID.
            device_id (str): The device UUID.
            role (str): "source_device" or "destination_device".
            device_ip (str): The device management IP (used for logging).

        Returns:
            list[dict]: Raw port assignment records from the API, in camelCase. An empty list
                means the device has no port assignments configured in the fabric.

        Description:
            Iterates pages of sda.get_port_assignments with offset/limit until the API returns
            fewer records than the page size (signalling the last page). Any API exception is
            converted to a fail_and_exit with the role and device IP to help the operator locate
            the problem.
        """
        offset = 1
        limit = 500
        assignments = []

        while True:
            api_params = {
                "fabric_id": fabric_id,
                "network_device_id": device_id,
                "offset": offset,
                "limit": limit,
            }
            response = self.execute_get_request(
                "sda", "get_port_assignments", api_params
            )
            page = (response or {}).get("response") or []
            if not page:
                break

            assignments.extend(page)

            if len(page) < limit:
                break
            offset += limit

        self.log(
            "Retrieved {0} port assignment(s) for {1} '{2}'.".format(
                len(assignments), role, device_ip
            ),
            "DEBUG",
        )
        return assignments

    def _get_port_channels(self, fabric_id, device_id, role, device_ip):
        """
        Retrieve every port channel configured on a fabric device using pagination.

        Args:
            fabric_id (str): The fabric site UUID.
            device_id (str): The device UUID.
            role (str): "source_device" or "destination_device".
            device_ip (str): The device management IP (used for logging).

        Returns:
            list[dict]: Raw port channel records from the API, in camelCase.

        Description:
            Mirrors the port-assignment fetch, using sda.get_port_channels. Port channel
            records contain the (system-generated) portChannelName, interfaceNames,
            connectedDeviceType, protocol, description, and (on Catalyst Center >= 3.1.3.0)
            nativeVlanId / allowedVlanRanges.
        """
        offset = 1
        limit = 500
        channels = []

        while True:
            api_params = {
                "fabric_id": fabric_id,
                "network_device_id": device_id,
                "offset": offset,
                "limit": limit,
            }
            response = self.execute_get_request(
                "sda", "get_port_channels", api_params
            )
            page = (response or {}).get("response") or []
            if not page:
                break

            channels.extend(page)

            if len(page) < limit:
                break
            offset += limit

        self.log(
            "Retrieved {0} port channel(s) for {1} '{2}'.".format(
                len(channels), role, device_ip
            ),
            "DEBUG",
        )
        return channels

    # --------------------------------------------------------------------
    # Interface mapping construction and validation
    # --------------------------------------------------------------------

    def _build_interface_mapping_lookup(
        self, interface_mapping_list, source_port_assignments, source_port_channels
    ):
        """
        Convert the interface_mapping list (or its absence) into a lookup dict.

        Args:
            interface_mapping_list (list | None): The playbook-supplied mapping list, already
                validated for shape and duplicates by validate_input.
            source_port_assignments (list): The source device's port assignments from the API.
            source_port_channels (list): The source device's port channels from the API.

        Returns:
            dict[str, str]: A {source_interface: destination_interface} dictionary. When the
                playbook did not supply a mapping, this is an identity map built from every
                source interface we intend to migrate (port assignment interfaces and port
                channel member interfaces).

        Description:
            Centralising the mapping as a dict keeps the remainder of the code simple - both
            the "no mapping" and "explicit mapping" cases look identical to downstream code.
            This method does not perform API-backed validation; it only normalises the shape.
        """
        if interface_mapping_list is not None:
            return {
                entry["source_interface"]: entry["destination_interface"]
                for entry in interface_mapping_list
            }

        identity_mapping = {}

        for assignment in source_port_assignments:
            source_interface = assignment.get("interfaceName")
            if source_interface:
                identity_mapping[source_interface] = source_interface

        for channel in source_port_channels:
            for source_interface in channel.get("interfaceNames") or []:
                identity_mapping[source_interface] = source_interface

        return identity_mapping

    def _validate_interface_mapping_against_devices(
        self,
        interface_mapping_provided,
        interface_mapping,
        source_device_interfaces,
        destination_device_interfaces,
        source_port_assignments,
        source_port_channels,
        source_device_ip,
        destination_device_ip,
    ):
        """
        Perform API-backed validation of the interface mapping against source and destination
        device state.

        Args:
            interface_mapping_provided (bool): True if the user supplied an interface_mapping in
                the playbook, False if we built an identity mapping implicitly.
            interface_mapping (dict): {source_interface: destination_interface} lookup.
            source_device_interfaces (set[str]): Physical interfaces on the source device.
            destination_device_interfaces (set[str]): Physical interfaces on the destination.
            source_port_assignments (list): Source port assignments (API camelCase).
            source_port_channels (list): Source port channels (API camelCase).
            source_device_ip (str): Source device management IP (for error messages).
            destination_device_ip (str): Destination device management IP (for error messages).

        Returns:
            None

        Description:
            Enforces three families of rules:
                A. When an explicit mapping was supplied, every source_interface must exist on
                   the source device, every destination_interface must exist on the destination
                   device, and every source_interface listed in the mapping must correspond to
                   something the module actually intends to migrate (a port assignment or a
                   port channel member) - otherwise the mapping entry has no effect and is
                   almost certainly a user mistake.
                B. Port channel members must be FULLY covered by the mapping. A partial mapping
                   (some members present, some missing) would produce an ambiguous migration
                   result and is rejected outright.
                C. When no explicit mapping was supplied, every port assignment interface and
                   every port channel member interface must exist on the destination device,
                   otherwise the migration cannot proceed with identical interface names.
            All failures terminate the module with a clear, operator-friendly message.
        """
        source_assigned_interfaces = {
            assignment.get("interfaceName")
            for assignment in source_port_assignments
            if assignment.get("interfaceName")
        }
        source_port_channel_members = {
            member
            for channel in source_port_channels
            for member in (channel.get("interfaceNames") or [])
        }
        migratable_source_interfaces = source_assigned_interfaces | source_port_channel_members

        if interface_mapping_provided:
            # Rule A: explicit mapping validation.
            for source_interface, destination_interface in interface_mapping.items():
                if source_interface not in source_device_interfaces:
                    self.fail_and_exit(
                        "The 'source_interface' '{0}' in 'interface_mapping' does not exist on "
                        "the source device '{1}'. Verify the interface name against the device "
                        "inventory.".format(source_interface, source_device_ip)
                    )
                if destination_interface not in destination_device_interfaces:
                    self.fail_and_exit(
                        "The 'destination_interface' '{0}' in 'interface_mapping' does not "
                        "exist on the destination device '{1}'. Verify the interface name "
                        "against the device inventory.".format(
                            destination_interface, destination_device_ip
                        )
                    )
                if source_interface not in migratable_source_interfaces:
                    self.fail_and_exit(
                        "The 'source_interface' '{0}' in 'interface_mapping' exists on the "
                        "source device '{1}' but has no port assignment and is not a member "
                        "of any port channel. There is nothing to migrate for this "
                        "interface.".format(source_interface, source_device_ip)
                    )

        # Rule B: port channel members must be fully mapped (applies regardless of whether
        # the mapping was supplied by the user or built implicitly as an identity mapping -
        # in the implicit case, by construction every member maps to itself, so this check
        # only fires when the user supplied an explicit mapping that omits some members).
        for channel in source_port_channels:
            port_channel_name = channel.get("portChannelName") or "<unnamed>"
            member_interfaces = channel.get("interfaceNames") or []
            unmapped = [
                member for member in member_interfaces if member not in interface_mapping
            ]
            if unmapped:
                self.fail_and_exit(
                    "Port channel '{0}' on the source device '{1}' has member interface(s) "
                    "{2} that are not covered by 'interface_mapping'. Partial port channel "
                    "mapping is not supported - include every member interface in the mapping, "
                    "or omit 'interface_mapping' entirely to migrate all interfaces using their "
                    "original names.".format(
                        port_channel_name, source_device_ip, unmapped
                    )
                )

        # Rule C: if no explicit mapping was supplied, every interface we implicitly plan to
        # migrate must exist on the destination device. _build_interface_mapping_lookup built
        # an identity mapping covering exactly those interfaces, so we can iterate its keys.
        if not interface_mapping_provided:
            for source_interface in interface_mapping:
                if source_interface not in destination_device_interfaces:
                    self.fail_and_exit(
                        "The source interface '{0}' does not exist on the destination device "
                        "'{1}'. Either ensure the destination device has matching interface "
                        "names, or supply 'interface_mapping' to rename interfaces during "
                        "migration.".format(source_interface, destination_device_ip)
                    )

    # --------------------------------------------------------------------
    # Port channel semantic validation (API-backed)
    # --------------------------------------------------------------------

    def _validate_port_channels_consistency(
        self,
        source_port_channels,
        destination_port_channels,
        interface_mapping,
        source_device_ip,
        destination_device_ip,
    ):
        """
        Validate that source port channels can be legally migrated to the destination.

        Args:
            source_port_channels (list): Source device port channels (API camelCase).
            destination_port_channels (list): Destination device port channels (API camelCase).
            interface_mapping (dict): {source_interface: destination_interface} lookup.
            source_device_ip (str): Source device management IP (for error messages).
            destination_device_ip (str): Destination device management IP (for error messages).

        Returns:
            None

        Description:
            Catalyst Center has two hard rules for port channel updates that the API enforces
            by returning an error, but we enforce them up front so the operator gets a clearer
            message and the module can fail fast before issuing any write:
                - Protocol (ON / LACP / PAGP) of a port channel cannot be changed once the
                  channel is created.
                - A connectedDeviceType transition from TRUNK to EXTENDED_NODE is only allowed
                  when the protocol is already PAGP.
            Additionally, a source port channel whose translated member interfaces overlap with
            a DIFFERENT existing port channel on the destination (i.e., matched by interface
            intersection but with a different portChannelName) is a configuration conflict -
            the Catalyst Center API would reject the request, and we surface it here with a
            clearer message that names both channels involved.
        """
        if not source_port_channels:
            return

        # Pre-build a lookup on the destination side: for each destination port channel, keep
        # the set of its member interface names. This lets us detect interface-set overlap
        # cheaply.
        destination_channels_by_name = {
            channel.get("portChannelName"): {
                "id": channel.get("id"),
                "interfaceNames": set(channel.get("interfaceNames") or []),
                "protocol": channel.get("protocol"),
                "connectedDeviceType": channel.get("connectedDeviceType"),
            }
            for channel in destination_port_channels
            if channel.get("portChannelName")
        }

        for source_channel in source_port_channels:
            source_channel_name = source_channel.get("portChannelName") or "<unnamed>"
            source_members = source_channel.get("interfaceNames") or []
            source_protocol = source_channel.get("protocol")
            source_connected_device_type = source_channel.get("connectedDeviceType")

            # Translate the member interfaces through the interface mapping. Every member is
            # guaranteed to be present in the mapping at this point because
            # _validate_interface_mapping_against_devices enforces full coverage.
            translated_members = {
                interface_mapping.get(member, member) for member in source_members
            }
            if not translated_members:
                continue

            matched_destination_name = None
            overlapping_destinations = []

            for dest_name, dest_info in destination_channels_by_name.items():
                overlap = translated_members & dest_info["interfaceNames"]
                if not overlap:
                    continue
                # Overlap is only acceptable if the destination channel's members exactly
                # equal the translated source members. Anything else is a cross-channel
                # membership conflict.
                if dest_info["interfaceNames"] == translated_members:
                    matched_destination_name = dest_name
                else:
                    overlapping_destinations.append(dest_name)

            if overlapping_destinations and matched_destination_name is None:
                self.fail_and_exit(
                    "Source port channel '{0}' on '{1}' (members {2} after mapping) "
                    "overlaps with an existing port channel on destination '{3}': {4}. "
                    "Catalyst Center does not allow the same interface to belong to multiple "
                    "port channels. Resolve the conflict on the destination device before "
                    "retrying the migration.".format(
                        source_channel_name,
                        source_device_ip,
                        sorted(translated_members),
                        destination_device_ip,
                        overlapping_destinations,
                    )
                )

            if matched_destination_name is not None:
                dest_info = destination_channels_by_name[matched_destination_name]

                # Protocol is immutable on existing port channels.
                if (
                    source_protocol
                    and dest_info["protocol"]
                    and source_protocol != dest_info["protocol"]
                ):
                    self.fail_and_exit(
                        "Port channel '{0}' on destination '{1}' already exists with "
                        "protocol '{2}', but the source device port channel '{3}' uses "
                        "protocol '{4}'. Catalyst Center does not allow the protocol of a "
                        "port channel to be updated. Delete the destination port channel "
                        "and rerun the migration, or adjust the source device to match.".format(
                            matched_destination_name,
                            destination_device_ip,
                            dest_info["protocol"],
                            source_channel_name,
                            source_protocol,
                        )
                    )

                # TRUNK -> EXTENDED_NODE transitions require the existing protocol to be PAGP.
                if (
                    dest_info["connectedDeviceType"] == "TRUNK"
                    and source_connected_device_type == "EXTENDED_NODE"
                    and dest_info["protocol"] != "PAGP"
                ):
                    self.fail_and_exit(
                        "Cannot migrate port channel '{0}' from source '{1}' to destination "
                        "'{2}': transitioning 'connectedDeviceType' from TRUNK to "
                        "EXTENDED_NODE requires the existing port channel protocol to be "
                        "PAGP (found '{3}').".format(
                            source_channel_name,
                            source_device_ip,
                            destination_device_ip,
                            dest_info["protocol"],
                        )
                    )

    # --------------------------------------------------------------------
    # Desired state construction (get_want)
    # --------------------------------------------------------------------

    def get_want(self, config):
        """
        Build the desired state from self.have and produce the API-ready payloads.

        Args:
            config (dict): The original config entry (kept for signature symmetry with the
                DnacBase workflow manager pattern - the actual inputs come from self.have,
                which was populated by get_have()).

        Returns:
            self (SDAPortAssignmentMigration): The instance with self.want populated. Key
                entries in self.want:
                    - add_port_assignments_params (dict | None): API payload for POST.
                    - update_port_assignments_params (dict | None): API payload for PUT.
                    - no_update_port_assignments (list[str]): interface names unchanged.
                    - add_port_channels_params (dict | None): API payload for POST.
                    - update_port_channels_params (dict | None): API payload for PUT.
                    - no_update_port_channels (list[str]): port channel names unchanged.
                    - add_port_assignment_interfaces (list[str]): interface names being added.
                    - update_port_assignment_interfaces (list[str]): interface names being updated.
                    - add_port_channel_names (list[str]): port channels being added.
                    - update_port_channel_names (list[str]): port channels being updated.

        Description:
            Executes the classification step (what to add, update, or skip) and builds the
            API-ready payloads. All classification works with the snake_case internal form;
            the payload builders translate to camelCase at the API boundary. This separation
            keeps the comparison code readable and the API payload code focused on formatting.
        """
        fabric_id = self.have["fabric_id"]
        destination_device_id = self.have["destination_device_id"]
        interface_mapping = self.have["interface_mapping"]

        self.log(
            "Building desired state for migration to destination device '{0}'.".format(
                self.have["destination_device_ip"]
            ),
            "INFO",
        )

        # 1. Port assignments: translate source records through the mapping and convert to
        #    the internal snake_case form, then classify against the destination state.
        requested_port_assignments = self._build_requested_port_assignments(
            source_port_assignments=self.have["source_port_assignments"],
            interface_mapping=interface_mapping,
        )

        (
            port_assignments_to_add,
            port_assignments_to_update,
            port_assignments_no_change,
        ) = self._classify_port_assignments(
            destination_port_assignments=self.have["destination_port_assignments"],
            requested_port_assignments=requested_port_assignments,
        )

        # 2. Port channels: mirror the above. Port channels are matched differently (by
        #    interface-name intersection rather than exact interface name), so they get their
        #    own classification helper.
        requested_port_channels = self._build_requested_port_channels(
            source_port_channels=self.have["source_port_channels"],
            interface_mapping=interface_mapping,
        )

        (
            port_channels_to_add,
            port_channels_to_update,
            port_channels_no_change,
        ) = self._classify_port_channels(
            destination_port_channels=self.have["destination_port_channels"],
            requested_port_channels=requested_port_channels,
        )

        # 3. Build API-ready payloads. A payload is produced only when there is at least one
        #    record for that operation; the downstream execution step uses the presence of
        #    these dict values to decide whether to issue the API call.
        add_port_assignments_params = None
        if port_assignments_to_add:
            add_port_assignments_params = self._build_add_port_assignments_payload(
                fabric_id=fabric_id,
                network_device_id=destination_device_id,
                port_assignments=port_assignments_to_add,
            )

        update_port_assignments_params = None
        if port_assignments_to_update:
            update_port_assignments_params = self._build_update_port_assignments_payload(
                fabric_id=fabric_id,
                network_device_id=destination_device_id,
                port_assignments=port_assignments_to_update,
            )

        add_port_channels_params = None
        if port_channels_to_add:
            add_port_channels_params = self._build_add_port_channels_payload(
                fabric_id=fabric_id,
                network_device_id=destination_device_id,
                port_channels=port_channels_to_add,
            )

        update_port_channels_params = None
        if port_channels_to_update:
            update_port_channels_params = self._build_update_port_channels_payload(
                fabric_id=fabric_id,
                network_device_id=destination_device_id,
                port_channels=port_channels_to_update,
            )

        self.want = {
            # Port assignment payloads + reporting lists
            "add_port_assignments_params": add_port_assignments_params,
            "update_port_assignments_params": update_port_assignments_params,
            "no_update_port_assignments": [
                record.get("interfaceName") for record in port_assignments_no_change
                if record.get("interfaceName")
            ],
            "add_port_assignment_interfaces": [
                record["interface_name"] for record in port_assignments_to_add
            ],
            "update_port_assignment_interfaces": [
                record["interface_name"] for record in port_assignments_to_update
            ],
            # Port channel payloads + reporting lists
            "add_port_channels_params": add_port_channels_params,
            "update_port_channels_params": update_port_channels_params,
            "no_update_port_channels": [
                record.get("portChannelName") for record in port_channels_no_change
                if record.get("portChannelName")
            ],
            "add_port_channel_member_interfaces": [
                sorted(record["interface_names"]) for record in port_channels_to_add
            ],
            "update_port_channel_names": [
                record["port_channel_name"] for record in port_channels_to_update
                if record.get("port_channel_name")
            ],
        }

        self.log(
            "Classification summary: port_assignments(add={0}, update={1}, no_change={2}), "
            "port_channels(add={3}, update={4}, no_change={5}).".format(
                len(port_assignments_to_add),
                len(port_assignments_to_update),
                len(port_assignments_no_change),
                len(port_channels_to_add),
                len(port_channels_to_update),
                len(port_channels_no_change),
            ),
            "INFO",
        )
        self.msg = (
            "Successfully built the desired state for migration to destination device '{0}'."
        ).format(self.have["destination_device_ip"])
        self.status = "success"
        return self

    # --------------------------------------------------------------------
    # Internal (snake_case) representation builders - apply mapping, strip noise
    # --------------------------------------------------------------------

    def _build_requested_port_assignments(self, source_port_assignments, interface_mapping):
        """
        Translate source port assignments to the destination-side internal representation.

        Args:
            source_port_assignments (list[dict]): Source device port assignments in API
                camelCase form.
            interface_mapping (dict): {source_interface: destination_interface} lookup.

        Returns:
            list[dict]: Port assignments in snake_case form with 'interface_name' already
                translated to the destination interface. When an explicit mapping was supplied
                and a source assignment's interface is not in the mapping, that assignment is
                dropped (the user explicitly scoped the migration to the mapped interfaces
                only). When no mapping was supplied (identity mapping), every assignment is
                kept as-is.

        Description:
            This is the sole place where we decide "which source assignments are we actually
            migrating". Downstream code can operate on the returned list without needing to
            know whether a mapping was supplied.
        """
        requested = []
        for source_assignment in source_port_assignments:
            source_interface = source_assignment.get("interfaceName")
            if source_interface is None:
                # Defensive: the API should always populate interfaceName.
                continue

            # A source interface that is not in the mapping is not being migrated.
            if source_interface not in interface_mapping:
                continue

            destination_interface = interface_mapping[source_interface]
            internal_record = self._convert_port_assignment_api_to_internal(source_assignment)
            internal_record["interface_name"] = destination_interface
            requested.append(internal_record)

        return requested

    def _build_requested_port_channels(self, source_port_channels, interface_mapping):
        """
        Translate source port channels to the destination-side internal representation.

        Args:
            source_port_channels (list[dict]): Source device port channels in API camelCase form.
            interface_mapping (dict): {source_interface: destination_interface} lookup.

        Returns:
            list[dict]: Port channels in snake_case form with 'interface_names' already
                translated. A source channel whose members are not all in the mapping would
                have been rejected earlier in get_have's validation step; at this point every
                member is guaranteed to have a mapping entry.

        Description:
            Source port channels are already known to have fully-covered mappings (checked in
            _validate_interface_mapping_against_devices). Partial coverage cannot occur here,
            so the conversion is a simple per-member translation.
        """
        requested = []
        for source_channel in source_port_channels:
            internal_record = self._convert_port_channel_api_to_internal(source_channel)
            source_members = source_channel.get("interfaceNames") or []
            internal_record["interface_names"] = [
                interface_mapping.get(member, member) for member in source_members
            ]
            requested.append(internal_record)

        return requested

    def _convert_port_assignment_api_to_internal(self, api_record):
        """
        Convert a port assignment from API camelCase to the module's internal snake_case form.

        Args:
            api_record (dict): A port assignment dict as returned by sda.get_port_assignments.

        Returns:
            dict: A dict keyed by the snake_case field names from PORT_ASSIGNMENT_FIELD_MAP.
                Only keys whose values are non-None in the source record are included.

        Description:
            Centralising the camelCase->snake_case conversion here means downstream comparison
            and payload-building code can ignore the naming duality entirely. The API's 'id'
            field is preserved verbatim so classify_port_assignments can tag update records
            with the record identifier.
        """
        internal = {}
        for api_key, internal_key in self.PORT_ASSIGNMENT_FIELD_MAP:
            value = api_record.get(api_key)
            if value is not None:
                internal[internal_key] = value

        # Keep the raw API 'id' - required for update payload construction.
        if api_record.get("id") is not None:
            internal["id"] = api_record["id"]

        return internal

    def _convert_port_channel_api_to_internal(self, api_record):
        """
        Convert a port channel from API camelCase to the module's internal snake_case form.

        Args:
            api_record (dict): A port channel dict as returned by sda.get_port_channels.

        Returns:
            dict: A dict keyed by the snake_case field names from PORT_CHANNEL_FIELD_MAP.
                Only keys whose values are non-None in the source record are included.

        Description:
            Same semantics as _convert_port_assignment_api_to_internal but driven by
            PORT_CHANNEL_FIELD_MAP. The API 'id' is preserved for update payload construction
            and the 'portChannelName' is kept both in its internal form ('port_channel_name')
            and remains accessible via record['port_channel_name'] throughout.
        """
        internal = {}
        for api_key, internal_key in self.PORT_CHANNEL_FIELD_MAP:
            value = api_record.get(api_key)
            if value is not None:
                internal[internal_key] = value

        if api_record.get("id") is not None:
            internal["id"] = api_record["id"]

        return internal

    # --------------------------------------------------------------------
    # Classification - what to add, what to update, what to leave alone
    # --------------------------------------------------------------------

    def _classify_port_assignments(
        self, destination_port_assignments, requested_port_assignments
    ):
        """
        Split the requested port assignments into add, update, and no-change buckets.

        Args:
            destination_port_assignments (list[dict]): Existing port assignments on the
                destination device, in API camelCase form.
            requested_port_assignments (list[dict]): Port assignments we want present on the
                destination, in internal snake_case form (already mapped).

        Returns:
            tuple(list, list, list): (to_add, to_update, no_change).
                - to_add: internal records with no existing match on the destination.
                - to_update: internal records differing from the existing destination record
                  for the same interface; includes the existing record's 'id'.
                - no_change: the ORIGINAL destination records (API camelCase) that match the
                  requested state and need no update. Returning the destination-side records
                  for this bucket lets the reporting code show what's already correct.

        Description:
            Matching is done by exact interfaceName (which is how Catalyst Center keys port
            assignments on a device). Field-level comparison is delegated to
            _port_assignment_differs, which handles the No-Authentication and empty-description
            equivalences correctly.
        """
        destination_by_interface = {
            record.get("interfaceName"): record
            for record in destination_port_assignments
            if record.get("interfaceName")
        }

        to_add = []
        to_update = []
        no_change = []

        for requested in requested_port_assignments:
            interface_name = requested.get("interface_name")
            destination_record = destination_by_interface.get(interface_name)

            if destination_record is None:
                to_add.append(requested)
                continue

            if self._port_assignment_differs(destination_record, requested):
                update_record = dict(requested)
                update_record["id"] = destination_record.get("id")
                to_update.append(update_record)
            else:
                no_change.append(destination_record)

        return to_add, to_update, no_change

    def _classify_port_channels(self, destination_port_channels, requested_port_channels):
        """
        Split the requested port channels into add, update, and no-change buckets.

        Args:
            destination_port_channels (list[dict]): Existing port channels on the destination
                device, in API camelCase form.
            requested_port_channels (list[dict]): Port channels we want present on the
                destination, in internal snake_case form (members already mapped).

        Returns:
            tuple(list, list, list): (to_add, to_update, no_change).
                - to_add: internal records with no matching destination port channel.
                - to_update: internal records whose matching destination channel differs;
                  includes destination 'id' and 'port_channel_name' for the update payload.
                - no_change: the ORIGINAL destination records (API camelCase) that already
                  match.

        Description:
            Port channel matching uses set equality on the translated member interface names.
            _validate_port_channels_consistency has already guaranteed (a) overlapping-but-not-
            equal membership is treated as a hard conflict, and (b) protocol changes / illegal
            TRUNK->EXTENDED_NODE transitions have been rejected, so the matching logic here
            can assume any set-equal match is a legal update candidate.
        """
        # Build a lookup of destination channels keyed by the frozenset of their member
        # interfaces.
        destination_by_members = {}
        for record in destination_port_channels:
            members = frozenset(record.get("interfaceNames") or [])
            if members:
                destination_by_members[members] = record

        to_add = []
        to_update = []
        no_change = []

        for requested in requested_port_channels:
            requested_members = frozenset(requested.get("interface_names") or [])
            if not requested_members:
                # Defensive: a channel with no members is invalid. Skip it rather than
                # crash on empty frozenset lookups.
                self.log(
                    "Skipping a requested port channel with no member interfaces: {0}".format(
                        requested
                    ),
                    "WARNING",
                )
                continue

            destination_record = destination_by_members.get(requested_members)
            if destination_record is None:
                to_add.append(requested)
                continue

            if self._port_channel_differs(destination_record, requested):
                update_record = dict(requested)
                update_record["id"] = destination_record.get("id")
                update_record["port_channel_name"] = destination_record.get("portChannelName")
                to_update.append(update_record)
            else:
                no_change.append(destination_record)

        return to_add, to_update, no_change

    # --------------------------------------------------------------------
    # Field-level comparison helpers - determine whether an update is needed
    # --------------------------------------------------------------------

    def _port_assignment_differs(self, existing_api, requested_internal):
        """
        Compare an existing port assignment (API camelCase) with a requested one (snake_case).

        Args:
            existing_api (dict): Existing port assignment from sda.get_port_assignments.
            requested_internal (dict): Requested port assignment in internal snake_case form.

        Returns:
            bool: True if at least one field differs and an update is required; False
                otherwise.

        Description:
            Catalyst Center represents a "no authentication template" assignment with the
            literal string 'No Authentication', whereas the module's internal form uses the
            absence of the key. Likewise, 'interfaceDescription' of '' is equivalent to an
            absent description. These cases are normalised here so idempotent reruns do not
            trigger spurious updates.

            Version-gated fields (nativeVlanId, allowedVlanRanges) are only compared when the
            running Catalyst Center version supports them. On older versions the API neither
            returns nor accepts those fields, so comparing them would misclassify every
            TRUNKING_DEVICE assignment as "needs update".
        """
        fields_to_compare = [
            ("interfaceName", "interface_name"),
            ("connectedDeviceType", "connected_device_type"),
            ("authenticateTemplateName", "authentication_template_name"),
            ("dataVlanName", "data_vlan_name"),
            ("voiceVlanName", "voice_vlan_name"),
            ("interfaceDescription", "interface_description"),
            ("securityGroupName", "security_group_name"),
        ]

        if self.compare_dnac_versions(
            self.current_version, self.NATIVE_VLAN_MIN_VERSION
        ) >= 0:
            fields_to_compare.extend(
                [
                    ("nativeVlanId", "native_vlan_id"),
                    ("allowedVlanRanges", "allowed_vlan_ranges"),
                ]
            )

        for api_key, internal_key in fields_to_compare:
            existing_value = existing_api.get(api_key)
            requested_value = requested_internal.get(internal_key)

            # 'No Authentication' on the existing side equals an absent / falsy value on the
            # requested side. The reverse is also true: the requested side may explicitly ask
            # for 'No Authentication' even when the existing side simply omits the field.
            if api_key == "authenticateTemplateName":
                if existing_value == "No Authentication" and not requested_value:
                    continue
                if not existing_value and requested_value == "No Authentication":
                    continue

            # An empty-string description on the API side equals an absent description on the
            # requested side.
            if api_key == "interfaceDescription":
                if existing_value == "" and not requested_value:
                    continue
                if not existing_value and requested_value == "":
                    continue

            if existing_value != requested_value:
                # A requested value of None paired with an API value that is not present in
                # the existing record should not force an update. But once we reach here, at
                # least one side has a non-trivial value, so the mismatch is material.
                if requested_value is None and existing_value is None:
                    continue
                self.log(
                    "Port assignment field '{0}' differs for interface '{1}': "
                    "existing='{2}', requested='{3}'.".format(
                        api_key,
                        existing_api.get("interfaceName"),
                        existing_value,
                        requested_value,
                    ),
                    "DEBUG",
                )
                return True

        return False

    def _port_channel_differs(self, existing_api, requested_internal):
        """
        Compare an existing port channel (API camelCase) with a requested one (snake_case).

        Args:
            existing_api (dict): Existing port channel from sda.get_port_channels.
            requested_internal (dict): Requested port channel in internal snake_case form.

        Returns:
            bool: True if at least one comparable field differs and an update is required;
                False otherwise.

        Description:
            'portChannelName' is system-generated by Catalyst Center and never appears on the
            requested side, so it is excluded from the comparison. 'protocol' is compared but
            a mismatch is treated as "needs update" in this check; the actual "protocol cannot
            be changed" enforcement happens earlier in _validate_port_channels_consistency to
            produce a clearer error message. Version-gated fields are handled the same way as
            in port assignments.
        """
        fields_to_compare = [
            ("connectedDeviceType", "connected_device_type"),
            ("protocol", "protocol"),
            ("description", "description"),
        ]

        if self.compare_dnac_versions(
            self.current_version, self.NATIVE_VLAN_MIN_VERSION
        ) >= 0:
            fields_to_compare.extend(
                [
                    ("nativeVlanId", "native_vlan_id"),
                    ("allowedVlanRanges", "allowed_vlan_ranges"),
                ]
            )

        # Interface membership is compared as sets (order independent).
        existing_members = set(existing_api.get("interfaceNames") or [])
        requested_members = set(requested_internal.get("interface_names") or [])
        if existing_members != requested_members:
            self.log(
                "Port channel members differ for '{0}': existing={1}, requested={2}.".format(
                    existing_api.get("portChannelName"),
                    sorted(existing_members),
                    sorted(requested_members),
                ),
                "DEBUG",
            )
            return True

        for api_key, internal_key in fields_to_compare:
            existing_value = existing_api.get(api_key)
            requested_value = requested_internal.get(internal_key)

            # An empty-string description equals an absent description on the requested side.
            if api_key == "description":
                if existing_value in ("", None) and requested_value in ("", None):
                    continue

            if existing_value != requested_value:
                if requested_value is None and existing_value is None:
                    continue
                self.log(
                    "Port channel field '{0}' differs for '{1}': existing='{2}', "
                    "requested='{3}'.".format(
                        api_key,
                        existing_api.get("portChannelName"),
                        existing_value,
                        requested_value,
                    ),
                    "DEBUG",
                )
                return True

        return False

    # --------------------------------------------------------------------
    # API payload builders - internal snake_case -> camelCase for POST/PUT
    # --------------------------------------------------------------------

    def _build_add_port_assignments_payload(
        self, fabric_id, network_device_id, port_assignments
    ):
        """
        Build the API payload for sda.add_port_assignments.

        Args:
            fabric_id (str): The destination fabric site UUID.
            network_device_id (str): The destination device UUID.
            port_assignments (list[dict]): Internal snake_case records to be added.

        Returns:
            dict: {"payload": [<one API record per assignment>]} as expected by the SDA
                add_port_assignments endpoint.

        Description:
            For every internal record, builds a camelCase API record containing the required
            fields (fabricId, networkDeviceId, interfaceName, connectedDeviceType) and any
            optional fields that are present (data VLAN, voice VLAN, description, security
            group, authentication template).

            Two Catalyst Center behaviours are normalised here:
                - When the connectedDeviceType is TRUNKING_DEVICE on a Catalyst Center
                  version >= 3.1.3.0, nativeVlanId and allowedVlanRanges are populated with
                  sensible defaults (1 and 'all') when missing. This matches the behaviour of
                  the Catalyst Center UI for trunking ports.
                - When no authentication template is specified, 'No Authentication' is set
                  explicitly. The API requires an explicit value; omitting it causes the
                  request to be rejected.
        """
        version_supports_native = self.compare_dnac_versions(
            self.current_version, self.NATIVE_VLAN_MIN_VERSION
        ) >= 0

        payload_records = []
        for record in port_assignments:
            api_record = {
                "fabricId": fabric_id,
                "networkDeviceId": network_device_id,
                "interfaceName": record.get("interface_name"),
                "connectedDeviceType": (record.get("connected_device_type") or "").upper(),
            }

            optional_field_map = [
                ("dataVlanName", "data_vlan_name"),
                ("voiceVlanName", "voice_vlan_name"),
                ("securityGroupName", "security_group_name"),
                ("interfaceDescription", "interface_description"),
            ]
            for api_key, internal_key in optional_field_map:
                value = record.get(internal_key)
                if value not in (None, ""):
                    api_record[api_key] = value

            authentication_template = record.get("authentication_template_name")
            api_record["authenticateTemplateName"] = (
                authentication_template if authentication_template else "No Authentication"
            )

            if (
                version_supports_native
                and api_record["connectedDeviceType"] == "TRUNKING_DEVICE"
            ):
                api_record["nativeVlanId"] = record.get("native_vlan_id", 1)
                api_record["allowedVlanRanges"] = record.get("allowed_vlan_ranges", "all")

            payload_records.append(api_record)

        return {"payload": payload_records}

    def _build_update_port_assignments_payload(
        self, fabric_id, network_device_id, port_assignments
    ):
        """
        Build the API payload for sda.update_port_assignments.

        Args:
            fabric_id (str): The destination fabric site UUID.
            network_device_id (str): The destination device UUID.
            port_assignments (list[dict]): Internal snake_case update records. Each record
                must carry the existing Catalyst Center 'id'.

        Returns:
            dict: {"payload": [<one API record per assignment>]} as expected by the SDA
                update_port_assignments endpoint.

        Description:
            Mirrors _build_add_port_assignments_payload with two additions: the API 'id' is
            included (required by the PUT endpoint), and for TRUNKING_DEVICE connections the
            authentication template is forced to 'No Authentication'. The existing module's
            behaviour is that TRUNKING_DEVICE ports cannot carry an authentication profile,
            and sending one causes the PUT to fail; forcing the value here keeps the update
            path resilient to stale playbook state.
        """
        version_supports_native = self.compare_dnac_versions(
            self.current_version, self.NATIVE_VLAN_MIN_VERSION
        ) >= 0

        payload_records = []
        for record in port_assignments:
            api_record = {
                "id": record.get("id"),
                "fabricId": fabric_id,
                "networkDeviceId": network_device_id,
                "interfaceName": record.get("interface_name"),
                "connectedDeviceType": (record.get("connected_device_type") or "").upper(),
            }

            optional_field_map = [
                ("dataVlanName", "data_vlan_name"),
                ("voiceVlanName", "voice_vlan_name"),
                ("securityGroupName", "security_group_name"),
                ("interfaceDescription", "interface_description"),
            ]
            for api_key, internal_key in optional_field_map:
                value = record.get(internal_key)
                if value not in (None, ""):
                    api_record[api_key] = value

            if api_record["connectedDeviceType"] == "TRUNKING_DEVICE":
                api_record["authenticateTemplateName"] = "No Authentication"
            else:
                authentication_template = record.get("authentication_template_name")
                api_record["authenticateTemplateName"] = (
                    authentication_template
                    if authentication_template
                    else "No Authentication"
                )

            if (
                version_supports_native
                and api_record["connectedDeviceType"] == "TRUNKING_DEVICE"
            ):
                api_record["nativeVlanId"] = record.get("native_vlan_id", 1)
                api_record["allowedVlanRanges"] = record.get("allowed_vlan_ranges", "all")

            payload_records.append(api_record)

        return {"payload": payload_records}

    def _build_add_port_channels_payload(
        self, fabric_id, network_device_id, port_channels
    ):
        """
        Build the API payload for sda.add_port_channels.

        Args:
            fabric_id (str): The destination fabric site UUID.
            network_device_id (str): The destination device UUID.
            port_channels (list[dict]): Internal snake_case port channel records to be added.

        Returns:
            dict: {"payload": [<one API record per port channel>]} as expected by the SDA
                add_port_channels endpoint.

        Description:
            Required fields are fabricId, networkDeviceId, interfaceNames,
            connectedDeviceType, and protocol. Description is optional. For TRUNK device type
            on Catalyst Center >= 3.1.3.0, nativeVlanId and allowedVlanRanges default to 1 and
            'all' respectively (matching the Catalyst Center UI defaults). portChannelName is
            never sent in the add payload - Catalyst Center assigns the name (for example,
            'Port-channel1') at create time and returns it in the response.
        """
        version_supports_native = self.compare_dnac_versions(
            self.current_version, self.NATIVE_VLAN_MIN_VERSION
        ) >= 0

        payload_records = []
        for record in port_channels:
            connected_device_type = (record.get("connected_device_type") or "").upper()
            api_record = {
                "fabricId": fabric_id,
                "networkDeviceId": network_device_id,
                "interfaceNames": list(record.get("interface_names") or []),
                "connectedDeviceType": connected_device_type,
                "protocol": (record.get("protocol") or "").upper(),
            }

            description = record.get("description")
            if description not in (None, ""):
                api_record["description"] = description

            if version_supports_native and connected_device_type == "TRUNK":
                api_record["nativeVlanId"] = record.get("native_vlan_id", 1)
                api_record["allowedVlanRanges"] = record.get("allowed_vlan_ranges", "all")

            payload_records.append(api_record)

        return {"payload": payload_records}

    def _build_update_port_channels_payload(
        self, fabric_id, network_device_id, port_channels
    ):
        """
        Build the API payload for sda.update_port_channels.

        Args:
            fabric_id (str): The destination fabric site UUID.
            network_device_id (str): The destination device UUID.
            port_channels (list[dict]): Internal snake_case update records. Each record must
                carry the existing Catalyst Center 'id' and 'port_channel_name' set by
                _classify_port_channels.

        Returns:
            dict: {"payload": [<one API record per port channel>]} as expected by the SDA
                update_port_channels endpoint.

        Description:
            The update endpoint requires both 'id' (the record UUID) and 'portChannelName'
            (the stable user-visible name). Protocol is included but a change to protocol
            would have been rejected earlier in _validate_port_channels_consistency; we send
            the existing protocol value to keep the request well-formed.
        """
        version_supports_native = self.compare_dnac_versions(
            self.current_version, self.NATIVE_VLAN_MIN_VERSION
        ) >= 0

        payload_records = []
        for record in port_channels:
            connected_device_type = (record.get("connected_device_type") or "").upper()
            api_record = {
                "id": record.get("id"),
                "fabricId": fabric_id,
                "networkDeviceId": network_device_id,
                "portChannelName": record.get("port_channel_name"),
                "interfaceNames": list(record.get("interface_names") or []),
                "connectedDeviceType": connected_device_type,
                "protocol": (record.get("protocol") or "").upper(),
            }

            description = record.get("description")
            if description not in (None, ""):
                api_record["description"] = description

            if version_supports_native and connected_device_type == "TRUNK":
                api_record["nativeVlanId"] = record.get("native_vlan_id", 1)
                api_record["allowedVlanRanges"] = record.get("allowed_vlan_ranges", "all")

            payload_records.append(api_record)

        return {"payload": payload_records}

    # --------------------------------------------------------------------
    # Migration execution (get_diff_merged)
    # --------------------------------------------------------------------

    def get_diff_merged(self):
        """
        Execute the port assignment and port channel migration against Catalyst Center.

        Returns:
            self (SDAPortAssignmentMigration): The instance with self.result populated via
                set_operation_result. self.msg holds the detailed per-operation result
                dictionary (see RETURN block for shape), and self.result["changed"] reflects
                whether any create or update was actually performed.

        Description:
            Executes the migration in a deterministic, ordered sequence:

                1. Port assignments - add (if any)
                2. Port assignments - update (if any)
                3. Port channels - add (if any, batched by sda_fabric_port_channel_limit)
                4. Port channels - update (if any, batched by sda_fabric_port_channel_limit)

            Each step is a no-op if there is nothing to do. Tasks are polled synchronously via
            DnacBase.get_task_status_from_tasks_by_id; a task failure immediately aborts the
            module via check_return_status, consistent with the fail-fast behaviour of the
            other workflow managers in the collection.

            Port channels are batched because Catalyst Center enforces an implicit per-request
            cap; the batch size is governed by the module-level 'sda_fabric_port_channel_limit'
            parameter (default 20, matching sda_host_port_onboarding_workflow_manager).

            The final result is aggregated into a dictionary that matches the human-readable
            style produced by sda_host_port_onboarding_workflow_manager, so operations teams
            see a consistent output across both modules.
        """
        self.log(
            "Starting migration execution against destination device '{0}'.".format(
                self.have["destination_device_ip"]
            ),
            "INFO",
        )

        result_details = {}
        changed = False

        # 1. Port assignments - add.
        add_port_assignments_params = self.want.get("add_port_assignments_params")
        if add_port_assignments_params and add_port_assignments_params.get("payload"):
            interfaces = self.want.get("add_port_assignment_interfaces") or []
            self._execute_port_assignments_operation(
                operation="add",
                api_function="add_port_assignments",
                payload=add_port_assignments_params,
                interfaces=interfaces,
            )
            result_details[
                "Add Port Assignment(s) Task Succeeded for following interface(s)"
            ] = {
                "success_count": len(interfaces),
                "success_interfaces": interfaces,
            }
            changed = True

        # 2. Port assignments - update.
        update_port_assignments_params = self.want.get("update_port_assignments_params")
        if update_port_assignments_params and update_port_assignments_params.get("payload"):
            interfaces = self.want.get("update_port_assignment_interfaces") or []
            self._execute_port_assignments_operation(
                operation="update",
                api_function="update_port_assignments",
                payload=update_port_assignments_params,
                interfaces=interfaces,
            )
            result_details[
                "Update Port Assignment(s) Task Succeeded for following interface(s)"
            ] = {
                "success_count": len(interfaces),
                "success_interfaces": interfaces,
            }
            changed = True

        # 3. Port channels - add (batched).
        add_port_channels_params = self.want.get("add_port_channels_params")
        if add_port_channels_params and add_port_channels_params.get("payload"):
            added_channel_names = self._execute_port_channels_operation(
                operation="add",
                api_function="add_port_channels",
                payload=add_port_channels_params,
            )
            result_details[
                "Add Port Channel(s) Task Succeeded for following port channel(s)"
            ] = {
                "success_count": len(added_channel_names),
                "success_port_channels": added_channel_names,
            }
            changed = True

        # 4. Port channels - update (batched).
        update_port_channels_params = self.want.get("update_port_channels_params")
        if update_port_channels_params and update_port_channels_params.get("payload"):
            updated_channel_names = self.want.get("update_port_channel_names") or []
            self._execute_port_channels_operation(
                operation="update",
                api_function="update_port_channels",
                payload=update_port_channels_params,
            )
            result_details[
                "Update Port Channel(s) Task Succeeded for following port channel(s)"
            ] = {
                "success_count": len(updated_channel_names),
                "success_port_channels": updated_channel_names,
            }
            changed = True

        # 5. Fold in the "already-correct" buckets so the result reports them too. These are
        # not changes (they do not flip the 'changed' flag), but reporting them helps
        # operators confirm that the migration is fully reconciled.
        no_update_port_assignments = self.want.get("no_update_port_assignments") or []
        if no_update_port_assignments:
            result_details[
                "Port assignment does not needs any update for following interface(s)"
            ] = {
                "success_count": len(no_update_port_assignments),
                "port_assignments_no_update_needed": no_update_port_assignments,
            }

        no_update_port_channels = self.want.get("no_update_port_channels") or []
        if no_update_port_channels:
            result_details[
                "Port channel does not needs any update for following port channel(s)"
            ] = {
                "success_count": len(no_update_port_channels),
                "port_channels_no_update_needed": no_update_port_channels,
            }

        if not result_details:
            self.msg = (
                "No port assignments or port channels on the source device required migration "
                "to the destination device '{0}'.".format(
                    self.have["destination_device_ip"]
                )
            )
            self.set_operation_result("success", False, self.msg, "INFO")
            return self

        # self.msg is the structured result dict so the user sees per-operation detail in
        # the response. operation status is always "success" here because any API-level
        # failure would already have called fail_and_exit via check_return_status.
        self.msg = result_details
        self.set_operation_result("success", changed, self.msg, "INFO")
        self.log(
            "Migration execution complete. Changed={0}. Summary: {1}".format(
                changed, result_details
            ),
            "INFO",
        )
        return self

    def _execute_port_assignments_operation(
        self, operation, api_function, payload, interfaces
    ):
        """
        Execute a single SDA port assignment create-or-update API call and poll its task.

        Args:
            operation (str): "add" or "update" - used to produce human-readable log and
                success messages.
            api_function (str): The SDK function name: either "add_port_assignments" or
                "update_port_assignments".
            payload (dict): The full API payload as built by the payload builders.
            interfaces (list[str]): The destination-side interface names being affected by
                this operation, used for logging and error messages only.

        Returns:
            None

        Description:
            Delegates to DnacBase.get_taskid_post_api_call and DnacBase.get_task_status_from_
            tasks_by_id. Both helpers are the canonical path used by every workflow manager
            in the collection, so we benefit from their rate-limit handling, timeout
            enforcement, and consistent logging. A failure in either step calls fail_and_exit
            via check_return_status, so control does not return to get_diff_merged on error.
        """
        self.log(
            "Issuing '{0}' API call for {1} port assignment(s) on interface(s) {2}.".format(
                api_function, len(interfaces), interfaces
            ),
            "INFO",
        )
        task_id = self.get_taskid_post_api_call("sda", api_function, payload)
        if not task_id:
            self.fail_and_exit(
                "Catalyst Center did not return a task id for the '{0}' API call. Unable to "
                "track completion of the port assignment {1} operation.".format(
                    api_function, operation
                )
            )

        task_name = (
            "Add Port Assignment(s) Task"
            if operation == "add"
            else "Update Port Assignment(s) Task"
        )
        success_msg = (
            "{0} succeeded on destination device '{1}' for interface(s) {2}.".format(
                task_name, self.have["destination_device_ip"], interfaces
            )
        )
        self.get_task_status_from_tasks_by_id(
            task_id, task_name, success_msg
        ).check_return_status()

    def _execute_port_channels_operation(self, operation, api_function, payload):
        """
        Execute an SDA port channel create-or-update API call, batching by the module-level
        'sda_fabric_port_channel_limit'.

        Args:
            operation (str): "add" or "update" - used in task naming.
            api_function (str): The SDK function name: "add_port_channels" or
                "update_port_channels".
            payload (dict): {"payload": [<port channel API record>, ...]}.

        Returns:
            list[str]: The port channel names involved in the operation, in the order they
                appear in the incoming payload. For "add", these names are inferred from the
                destination-side member-interface lists since Catalyst Center generates the
                portChannelName server-side; for "update", the portChannelName is already
                present on each record.

        Description:
            Catalyst Center caps the number of port channels per request; large migrations
            are split into chunks controlled by the module parameter
            'sda_fabric_port_channel_limit' (default 20). Each chunk is sent as a separate
            API call and its task is polled synchronously before the next chunk is sent. Any
            chunk failure aborts the module via check_return_status.
        """
        records = payload.get("payload") or []
        batch_limit = self.params.get("sda_fabric_port_channel_limit") or 20

        task_name = (
            "Add Port Channel(s) Task"
            if operation == "add"
            else "Update Port Channel(s) Task"
        )

        # For add operations, Catalyst Center assigns the portChannelName at creation. We log
        # the member-interface lists to provide traceability; the verify step or a re-fetch
        # can be used later to confirm the assigned names.
        channel_identifiers = []
        for record in records:
            if operation == "update":
                channel_identifiers.append(record.get("portChannelName"))
            else:
                channel_identifiers.append(
                    "members={0}".format(sorted(record.get("interfaceNames") or []))
                )

        total = len(records)
        self.log(
            "Issuing '{0}' API call for {1} port channel(s) in batches of {2}.".format(
                api_function, total, batch_limit
            ),
            "INFO",
        )

        for batch_start in range(0, total, batch_limit):
            batch_records = records[batch_start:batch_start + batch_limit]
            batch_payload = {"payload": batch_records}
            batch_index = batch_start // batch_limit + 1
            self.log(
                "Port channel batch {0}: {1} record(s).".format(
                    batch_index, len(batch_records)
                ),
                "DEBUG",
            )

            task_id = self.get_taskid_post_api_call("sda", api_function, batch_payload)
            if not task_id:
                self.fail_and_exit(
                    "Catalyst Center did not return a task id for port channel {0} "
                    "operation batch {1}. Unable to track completion.".format(
                        operation, batch_index
                    )
                )

            success_msg = (
                "{0} (batch {1}) succeeded on destination device '{2}'.".format(
                    task_name, batch_index, self.have["destination_device_ip"]
                )
            )
            self.get_task_status_from_tasks_by_id(
                task_id, task_name, success_msg
            ).check_return_status()

        return channel_identifiers

    # --------------------------------------------------------------------
    # Post-operation verification (verify_diff_merged)
    # --------------------------------------------------------------------

    def verify_diff_merged(self):
        """
        Re-read the destination device's fabric state after migration and log any residual
        differences from the source.

        Returns:
            self (SDAPortAssignmentMigration): The instance (unchanged result dict on
                successful verification; warnings logged for any discrepancies).

        Description:
            When the playbook sets 'config_verify: true', this method runs after
            get_diff_merged. It re-fetches the destination device's port assignments and port
            channels and compares them against the requested state that was computed in
            get_want. Each mismatch is logged as a WARNING; verification never fails the
            module. This is deliberate: by the time verify runs, get_diff_merged has already
            reported success to the user; a transient read-after-write inconsistency should
            not retroactively fail a successful migration. Operators are expected to treat
            verification warnings as actionable follow-up, not as a build break.
        """
        if not self.have:
            self.log(
                "verify_diff_merged called with no state in self.have; nothing to verify.",
                "DEBUG",
            )
            return self

        self.log(
            "Starting post-migration verification against destination device '{0}'.".format(
                self.have["destination_device_ip"]
            ),
            "INFO",
        )

        fabric_id = self.have["fabric_id"]
        destination_device_id = self.have["destination_device_id"]
        destination_device_ip = self.have["destination_device_ip"]
        interface_mapping = self.have["interface_mapping"]

        # Re-fetch live destination state.
        refreshed_port_assignments = self._get_port_assignments(
            fabric_id,
            destination_device_id,
            "destination_device",
            destination_device_ip,
        )
        refreshed_port_channels = self._get_port_channels(
            fabric_id,
            destination_device_id,
            "destination_device",
            destination_device_ip,
        )

        # Rebuild the requested state from the (unchanged) source-side records in self.have.
        # get_want cleared its internal requested lists into payloads; rebuilding here keeps
        # verification orthogonal to the exact shape of self.want.
        requested_port_assignments = self._build_requested_port_assignments(
            source_port_assignments=self.have["source_port_assignments"],
            interface_mapping=interface_mapping,
        )
        requested_port_channels = self._build_requested_port_channels(
            source_port_channels=self.have["source_port_channels"],
            interface_mapping=interface_mapping,
        )

        self._verify_port_assignments_match(
            refreshed_port_assignments, requested_port_assignments
        )
        self._verify_port_channels_match(
            refreshed_port_channels, requested_port_channels
        )

        self.log("Post-migration verification complete.", "INFO")
        return self

    def _verify_port_assignments_match(
        self, refreshed_port_assignments, requested_port_assignments
    ):
        """
        Compare the refreshed destination port assignments against the requested state and
        log any discrepancies.

        Args:
            refreshed_port_assignments (list[dict]): Freshly fetched destination port
                assignments (API camelCase form).
            requested_port_assignments (list[dict]): Requested port assignments in internal
                snake_case form.

        Returns:
            None

        Description:
            For each requested record, confirm the destination has a matching record (by
            interfaceName) and that field-level comparison yields no differences (using
            _port_assignment_differs to preserve the same equivalence semantics as the
            classification step). Discrepancies are logged as WARNING entries for operator
            follow-up.
        """
        destination_by_interface = {
            record.get("interfaceName"): record
            for record in refreshed_port_assignments
            if record.get("interfaceName")
        }

        for requested in requested_port_assignments:
            interface_name = requested.get("interface_name")
            destination_record = destination_by_interface.get(interface_name)
            if destination_record is None:
                self.log(
                    "Verification: requested port assignment for interface '{0}' is missing "
                    "on destination device '{1}' after migration.".format(
                        interface_name, self.have["destination_device_ip"]
                    ),
                    "WARNING",
                )
                continue

            if self._port_assignment_differs(destination_record, requested):
                self.log(
                    "Verification: port assignment for interface '{0}' on destination '{1}' "
                    "does not fully match the source-derived desired state.".format(
                        interface_name, self.have["destination_device_ip"]
                    ),
                    "WARNING",
                )

    def _verify_port_channels_match(
        self, refreshed_port_channels, requested_port_channels
    ):
        """
        Compare the refreshed destination port channels against the requested state and log
        any discrepancies.

        Args:
            refreshed_port_channels (list[dict]): Freshly fetched destination port channels
                (API camelCase form).
            requested_port_channels (list[dict]): Requested port channels in internal
                snake_case form.

        Returns:
            None

        Description:
            Port channels are matched by member-interface set equality (the same matching
            rule the classification step uses). Missing port channels and field-level
            deviations are logged as warnings.
        """
        destination_by_members = {}
        for record in refreshed_port_channels:
            members = frozenset(record.get("interfaceNames") or [])
            if members:
                destination_by_members[members] = record

        for requested in requested_port_channels:
            requested_members = frozenset(requested.get("interface_names") or [])
            if not requested_members:
                continue

            destination_record = destination_by_members.get(requested_members)
            if destination_record is None:
                self.log(
                    "Verification: requested port channel with members {0} is missing on "
                    "destination device '{1}' after migration.".format(
                        sorted(requested_members), self.have["destination_device_ip"]
                    ),
                    "WARNING",
                )
                continue

            if self._port_channel_differs(destination_record, requested):
                self.log(
                    "Verification: port channel '{0}' on destination '{1}' does not fully "
                    "match the source-derived desired state.".format(
                        destination_record.get("portChannelName"),
                        self.have["destination_device_ip"],
                    ),
                    "WARNING",
                )


def main():
    """
    Entry point for module execution.

    Description:
        Builds the module argument spec (including the SDA-fabric-specific
        `sda_fabric_port_channel_limit` option), enforces the minimum Catalyst Center
        version requirement, runs input validation, and then iterates the validated
        configuration list calling the standard DnacBase workflow lifecycle in order:
        reset_values -> get_have -> get_want -> get_diff_merged -> (optional)
        verify_diff_merged. Each step calls check_return_status so a failure at any
        point aborts with a clear error.
    """
    # Module argument specification. Connection parameters mirror every other workflow
    # manager in the cisco.dnac collection so playbooks can reuse the same variable set.
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
        "sda_fabric_port_channel_limit": {"type": "int", "default": 20},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    ccc_sda_port_assignment_migration = SDAPortAssignmentMigration(module)
    ccc_sda_port_assignment_migration.current_version = (
        ccc_sda_port_assignment_migration.get_ccc_version()
    )

    # Minimum Catalyst Center version gate. The SDA port-assignment and port-channel APIs
    # this module depends on were introduced in 2.3.7.6. Running against an older version
    # would surface as opaque 404s or missing-method errors further down, so we gate the
    # execution here with a message that points the operator at the required upgrade.
    if (
        ccc_sda_port_assignment_migration.compare_dnac_versions(
            ccc_sda_port_assignment_migration.current_version,
            ccc_sda_port_assignment_migration.MIN_SUPPORTED_CCC_VERSION,
        )
        < 0
    ):
        ccc_sda_port_assignment_migration.msg = (
            "The specified Catalyst Center version '{0}' does not support the SDA Port "
            "Assignment Migration feature. Supported versions start from '{1}' onwards. "
            "Upgrade Catalyst Center or connect the module to a supported instance.".format(
                ccc_sda_port_assignment_migration.current_version,
                ccc_sda_port_assignment_migration.MIN_SUPPORTED_CCC_VERSION,
            )
        )
        ccc_sda_port_assignment_migration.set_operation_result(
            "failed", False, ccc_sda_port_assignment_migration.msg, "ERROR"
        ).check_return_status()

    state = ccc_sda_port_assignment_migration.params.get("state")
    if state not in ccc_sda_port_assignment_migration.supported_states:
        ccc_sda_port_assignment_migration.status = "invalid"
        ccc_sda_port_assignment_migration.msg = (
            "State '{0}' is invalid for this module. Only 'merged' is supported.".format(state)
        )
        ccc_sda_port_assignment_migration.check_return_status()

    ccc_sda_port_assignment_migration.validate_input().check_return_status()

    config_verify = ccc_sda_port_assignment_migration.params.get("config_verify")

    # Iterate every validated configuration entry independently. reset_values clears
    # self.have and self.want between iterations so state does not leak across entries.
    for config in ccc_sda_port_assignment_migration.validated_config:
        ccc_sda_port_assignment_migration.reset_values()
        ccc_sda_port_assignment_migration.get_have(config).check_return_status()
        ccc_sda_port_assignment_migration.get_want(config).check_return_status()
        ccc_sda_port_assignment_migration.get_diff_merged().check_return_status()

        if config_verify:
            ccc_sda_port_assignment_migration.verify_diff_merged().check_return_status()

    module.exit_json(**ccc_sda_port_assignment_migration.result)


if __name__ == "__main__":
    main()
