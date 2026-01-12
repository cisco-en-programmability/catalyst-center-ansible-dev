#  Copyright (c) 2026 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Authors:
#   Generated based on test_sda_fabric_virtual_networks_workflow_manager pattern
#
# Description:
#   Unit tests for the Ansible module `brownfield_inventory_playbook_generator`.
#   These tests cover various inventory generation scenarios using mocked
#   Catalyst Center responses and file operations.
from __future__ import absolute_import, division, print_function

__metaclass__ = type
from unittest.mock import patch
from ansible_collections.cisco.dnac.plugins.modules import brownfield_inventory_playbook_generator
from .dnac_module import TestDnacModule, set_module_args, loadPlaybookData


class TestBrownfieldInventoryPlaybookGenerator(TestDnacModule):

    module = brownfield_inventory_playbook_generator
    test_data = loadPlaybookData("brownfield_inventory_playbook_generator")

    # Map all playbook configs from fixtures to class attributes
    playbook_config_generate_all_configurations = test_data.get("playbook_config_generate_all_configurations")
    playbook_config_generate_all_with_custom_path = test_data.get("playbook_config_generate_all_with_custom_path")
    playbook_config_filter_by_ip_address = test_data.get("playbook_config_filter_by_ip_address")
    playbook_config_filter_single_device_by_ip = test_data.get("playbook_config_filter_single_device_by_ip")
    playbook_config_filter_network_devices_by_ip = test_data.get("playbook_config_filter_network_devices_by_ip")
    playbook_config_filter_by_hostname = test_data.get("playbook_config_filter_by_hostname")
    playbook_config_filter_core_switches_by_hostname = test_data.get("playbook_config_filter_core_switches_by_hostname")
    playbook_config_filter_access_switches_by_hostname = test_data.get("playbook_config_filter_access_switches_by_hostname")
    playbook_config_filter_by_serial_number = test_data.get("playbook_config_filter_by_serial_number")
    playbook_config_filter_hardware_units_by_serial = test_data.get("playbook_config_filter_hardware_units_by_serial")
    playbook_config_mixed_device_identification = test_data.get("playbook_config_mixed_device_identification")
    playbook_config_explicit_components_list = test_data.get("playbook_config_explicit_components_list")
    playbook_config_compute_devices = test_data.get("playbook_config_compute_devices")
    playbook_config_wireless_controllers = test_data.get("playbook_config_wireless_controllers")
    playbook_config_third_party_devices = test_data.get("playbook_config_third_party_devices")
    playbook_config_meraki_devices = test_data.get("playbook_config_meraki_devices")
    playbook_config_firepower_management_systems = test_data.get("playbook_config_firepower_management_systems")
    playbook_config_datacenter_devices = test_data.get("playbook_config_datacenter_devices")
    playbook_config_campus_network_devices = test_data.get("playbook_config_campus_network_devices")
    playbook_config_branch_office_devices = test_data.get("playbook_config_branch_office_devices")
    playbook_config_snmpv3_credentials = test_data.get("playbook_config_snmpv3_credentials")
    playbook_config_ssh_credentials = test_data.get("playbook_config_ssh_credentials")
    playbook_config_http_credentials = test_data.get("playbook_config_http_credentials")
    playbook_config_default_file_path = test_data.get("playbook_config_default_file_path")
    playbook_config_lab_environment_defaults = test_data.get("playbook_config_lab_environment_defaults")
    playbook_config_distribution_layer_switches = test_data.get("playbook_config_distribution_layer_switches")
    playbook_config_access_layer_switches = test_data.get("playbook_config_access_layer_switches")
    playbook_config_core_routers = test_data.get("playbook_config_core_routers")
    playbook_config_building_specific_infrastructure = test_data.get("playbook_config_building_specific_infrastructure")
    playbook_config_disaster_recovery_site = test_data.get("playbook_config_disaster_recovery_site")
    playbook_config_multi_site_bulk_operation = test_data.get("playbook_config_multi_site_bulk_operation")
    playbook_config_large_deployment = test_data.get("playbook_config_large_deployment")
    playbook_config_access_role_devices = test_data.get("playbook_config_access_role_devices")
    playbook_config_core_role_devices = test_data.get("playbook_config_core_role_devices")
    playbook_config_distribution_role_devices = test_data.get("playbook_config_distribution_role_devices")

    def setUp(self):
        super(TestBrownfieldInventoryPlaybookGenerator, self).setUp()

        # Patch DNAC SDK init/exec to avoid real connections
        self.mock_dnac_init = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK.__init__"
        )
        self.run_dnac_init = self.mock_dnac_init.start()
        self.run_dnac_init.side_effect = [None]

        self.mock_dnac_exec = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK._exec"
        )
        self.run_dnac_exec = self.mock_dnac_exec.start()
        # Return a generic successful response for any SDK call if invoked
        self.run_dnac_exec.return_value = {"response": [], "version": "2.3.7.9"}

        # Patch the generator to avoid network and file system operations
        self.mock_get_details = patch(
            "ansible_collections.cisco.dnac.plugins.modules.brownfield_inventory_playbook_generator.InventoryPlaybookGenerator.get_inventory_workflow_manager_details",
            return_value=[
                {
                    "ip_address_list": ["192.168.1.10"],
                    "username": "admin",
                    "password": "dummy",
                    "snmp_version": "v3"
                }
            ],
        )
        self.run_get_details = self.mock_get_details.start()

        self.mock_write_yaml = patch(
            "ansible_collections.cisco.dnac.plugins.modules.brownfield_inventory_playbook_generator.InventoryPlaybookGenerator.write_dict_to_yaml",
            return_value=True,
        )
        self.run_write_yaml = self.mock_write_yaml.start()

    def tearDown(self):
        super(TestBrownfieldInventoryPlaybookGenerator, self).tearDown()
        self.mock_write_yaml.stop()
        self.mock_get_details.stop()
        self.mock_dnac_exec.stop()
        self.mock_dnac_init.stop()

    def _common_args(self, config):
        return dict(
            dnac_host="1.1.1.1",
            dnac_username="dummy",
            dnac_password="dummy",
            dnac_version="2.3.7.9",
            dnac_log=True,
            config_verify=True,
            state="merged",
            config=config,
        )

    # --- Test cases for each fixture entry ---

    def test_brownfield_inventory_generate_all_configurations(self):
        set_module_args(self._common_args(self.playbook_config_generate_all_configurations))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_generate_all_with_custom_path(self):
        set_module_args(self._common_args(self.playbook_config_generate_all_with_custom_path))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_by_ip_address(self):
        set_module_args(self._common_args(self.playbook_config_filter_by_ip_address))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_single_device_by_ip(self):
        set_module_args(self._common_args(self.playbook_config_filter_single_device_by_ip))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_network_devices_by_ip(self):
        set_module_args(self._common_args(self.playbook_config_filter_network_devices_by_ip))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_by_hostname(self):
        set_module_args(self._common_args(self.playbook_config_filter_by_hostname))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_core_switches_by_hostname(self):
        set_module_args(self._common_args(self.playbook_config_filter_core_switches_by_hostname))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_access_switches_by_hostname(self):
        set_module_args(self._common_args(self.playbook_config_filter_access_switches_by_hostname))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_by_serial_number(self):
        set_module_args(self._common_args(self.playbook_config_filter_by_serial_number))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_filter_hardware_units_by_serial(self):
        set_module_args(self._common_args(self.playbook_config_filter_hardware_units_by_serial))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_mixed_device_identification(self):
        set_module_args(self._common_args(self.playbook_config_mixed_device_identification))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_explicit_components_list(self):
        set_module_args(self._common_args(self.playbook_config_explicit_components_list))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_compute_devices(self):
        set_module_args(self._common_args(self.playbook_config_compute_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_wireless_controllers(self):
        set_module_args(self._common_args(self.playbook_config_wireless_controllers))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_third_party_devices(self):
        set_module_args(self._common_args(self.playbook_config_third_party_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_meraki_devices(self):
        set_module_args(self._common_args(self.playbook_config_meraki_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_firepower_management_systems(self):
        set_module_args(self._common_args(self.playbook_config_firepower_management_systems))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_datacenter_devices(self):
        set_module_args(self._common_args(self.playbook_config_datacenter_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_campus_network_devices(self):
        set_module_args(self._common_args(self.playbook_config_campus_network_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_branch_office_devices(self):
        set_module_args(self._common_args(self.playbook_config_branch_office_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_snmpv3_credentials(self):
        set_module_args(self._common_args(self.playbook_config_snmpv3_credentials))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_ssh_credentials(self):
        set_module_args(self._common_args(self.playbook_config_ssh_credentials))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_http_credentials(self):
        set_module_args(self._common_args(self.playbook_config_http_credentials))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_default_file_path(self):
        set_module_args(self._common_args(self.playbook_config_default_file_path))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_lab_environment_defaults(self):
        set_module_args(self._common_args(self.playbook_config_lab_environment_defaults))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_distribution_layer_switches(self):
        set_module_args(self._common_args(self.playbook_config_distribution_layer_switches))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_access_layer_switches(self):
        set_module_args(self._common_args(self.playbook_config_access_layer_switches))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_core_routers(self):
        set_module_args(self._common_args(self.playbook_config_core_routers))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_building_specific_infrastructure(self):
        set_module_args(self._common_args(self.playbook_config_building_specific_infrastructure))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_disaster_recovery_site(self):
        set_module_args(self._common_args(self.playbook_config_disaster_recovery_site))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_multi_site_bulk_operation(self):
        set_module_args(self._common_args(self.playbook_config_multi_site_bulk_operation))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_large_deployment(self):
        set_module_args(self._common_args(self.playbook_config_large_deployment))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_access_role_devices(self):
        set_module_args(self._common_args(self.playbook_config_access_role_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_core_role_devices(self):
        set_module_args(self._common_args(self.playbook_config_core_role_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))

    def test_brownfield_inventory_distribution_role_devices(self):
        set_module_args(self._common_args(self.playbook_config_distribution_role_devices))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn("Successfully generated", result.get("msg", ""))
