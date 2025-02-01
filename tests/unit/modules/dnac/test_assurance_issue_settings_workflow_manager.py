# Copyright (c) 2025 Cisco and/or its affiliates.
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

# Make coding more python3-ish
from __future__ import absolute_import, division, print_function

__metaclass__ = type
from unittest.mock import patch
from ansible_collections.cisco.dnac.plugins.modules import assurance_issue_settings_workflow_manager
from .dnac_module import TestDnacModule, set_module_args, loadPlaybookData


class TestDnacAssuranceSettings(TestDnacModule):
    module = assurance_issue_settings_workflow_manager
    test_data = loadPlaybookData("assurance_issue_settings_workflow_manager")
    playbook_config_updation = test_data.get("playbook_config_updation")
    playbook_config_creation = test_data.get("playbook_config_creation")
    playbook_config_deletion = test_data.get("playbook_config_deletion")
    playbook_config_system_issue_updation = test_data.get("playbook_config_system_issue_updation")
    playbook_config_command_execution = test_data.get("playbook_config_command_execution")
    playbook_config_No_data_found = test_data.get("playbook_config_No_data_found")
    playbook_config_resolution = test_data.get("playbook_config_resolution")
    playbook_config_ignore = test_data.get("playbook_config_ignore")
    playbook_config_invalid_severity = test_data.get("playbook_config_invalid_severity")
    playbook_config_invalid_duration = test_data.get("playbook_config_invalid_duration")
    playbook_config_invalid_name = test_data.get("playbook_config_invalid_name")
    playbook_config_invalid_priority = test_data.get("playbook_config_invalid_priority")
    playbook_config_invalid_time_format = test_data.get("playbook_config_invalid_time_format")

    def setUp(self):
        super(TestDnacAssuranceSettings, self).setUp()

        self.mock_dnac_init = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK.__init__")
        self.run_dnac_init = self.mock_dnac_init.start()
        self.run_dnac_init.side_effect = [None]
        self.mock_dnac_exec = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK._exec"
        )
        self.run_dnac_exec = self.mock_dnac_exec.start()

        self.load_fixtures()

    def tearDown(self):
        super(TestDnacAssuranceSettings, self).tearDown()
        self.mock_dnac_exec.stop()
        self.mock_dnac_init.stop()

    def load_fixtures(self, response=None, device=""):
        """
        Load fixtures for user.
        """
        if "updation" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("issue_exist"),
                self.test_data.get("prev_issue_exist"),
                self.test_data.get("issue_updation"),
                self.test_data.get("issue_exist_after_updation")
            ]

        if "creation" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("Testing_creation_exit"),
                self.test_data.get("issue_creation"),
                self.test_data.get("exist_after_creation"),
            ]

        if "deletion" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_API_response_deletion"),
                Exception(),
                self.test_data.get("after_deletion_get_response"),
            ]

        if "update_system_issue" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_system_issue"),
                self.test_data.get("get_system_issue2"),
                self.test_data.get("system_issue_update"),
                self.test_data.get("get_updated_system_issue_1"),
                self.test_data.get("get_updated_system_issue_2")
            ]

        if "command_execution" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_issue_ids_command_execution"),
                self.test_data.get("command_execution"),
                self.test_data.get("get_business_api_execution_details")
            ]

        if "No_data_found" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_issue_ids_No_data_found"),
            ]

        if "resolution" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_issue_ids_resolution"),
                self.test_data.get("Issue_resolve_response"),
            ]

        if "ignore" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_issue_ids_resolution"),
                self.test_data.get("Issue_ignore_response"),
            ]

        if "invalid_time_format" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_issue_ids_resolution"),
            ]

    def test_assurance_issue_settings_workflow_manager_updation(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager

        when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_updation
            )
        )
        result = self.execute_module(changed=True, failed=False)
        print(result['response'][0]['assurance_user_defined_issue_settings']['response'])
        self.assertEqual(
            result['response'][0]['assurance_user_defined_issue_settings']['response'],
            {'updated user defined issue Details': {'name': 'test_user_defined', 'description': 'testing settings 1', 'rules':
             [{'severity': '2', 'facility': 'redundancy', 'mnemonic': 'peer monitor event', 'pattern': 'issue test', 'occurrences': 1,
              'duration_in_minutes': 2}], 'is_enabled': True, 'priority': 'P2', 'is_notification_enabled': True, 'prev_name': 'test_seema_1'}}
        )

    def test_assurance_issue_settings_workflow_manager_creation(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager

        when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_creation
            )
        )
        result = self.execute_module(changed=True, failed=False)
        print(result['response'][0]['assurance_user_defined_issue_settings']['response'])
        self.assertEqual(
            result['response'][0]['assurance_user_defined_issue_settings']['response'],
            {'created user-defined issue': {'name': 'Testing_creation', 'description': 'testing settings 1',
             'rules': [{'severity': '2', 'facility': 'Alert', 'mnemonic': 'peer monitor event', 'pattern': 'issue test',
                        'occurrences': 1, 'duration_in_minutes': 2}], 'is_enabled': True, 'priority': 'P2', 'is_notification_enabled': True}}
        )

    def test_assurance_issue_settings_workflow_manager_deletion(self):
        """
        Test case for assurance issue settings workflow manager when creating a device credential.

        This test case checks the behavior of the assurance issue settings workflow manager

        when deleting assurance user defined issue in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="deleted",
                dnac_version="2.3.7.9",
                config=self.playbook_config_deletion,
                config_verify=True
            )
        )
        result = self.execute_module(changed=True, failed=False)
        print(result['response'][0]['assurance_user_defined_issue_settings']['msg'])
        self.assertEqual(
            result['response'][0]['assurance_user_defined_issue_settings']['msg'],
            {'ippo': 'Assurance user issue deleted successfully'}
        )

    def test_assurance_issue_settings_workflow_manager_update_system_issue(self):
        """
        Test case for assurance issue settings workflow manager when creating a device credential.

        This test case checks the behavior of the assurance issue settings workflow manager

        when deleting assurance user defined issue in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                dnac_version="2.3.7.9",
                config=self.playbook_config_system_issue_updation,
                config_verify=True
            )
        )
        result = self.execute_module(changed=True, failed=False)
        print(result['response'][1]['assurance_system_issue_settings']['msg'])
        self.assertEqual(
            result['response'][1]['assurance_system_issue_settings']['msg'],
            {'AP Reboot Crash': 'System issue Updated Successfully'}
        )

    def test_assurance_issue_settings_workflow_manager_command_execution(self):
        """
        Test case for assurance issue settings workflow manager when creating a device credential.

        This test case checks the behavior of the assurance issue settings workflow manager when

        deleting assurance user defined issue in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                dnac_version="2.3.7.9",
                config=self.playbook_config_command_execution,
                config_verify=True
            )
        )
        result = self.execute_module(changed=True, failed=False)
        print(result['response']['input_isssue_config'])
        self.assertEqual(
            result['response']['input_isssue_config'],
            [{'issue_name': 'jan8_1', 'issue_process_type': 'command_execution'}]
        )

    def test_assurance_issue_settings_workflow_manager_No_data_found(self):
        """
        Test case for assurance issue settings workflow manager when creating a device credential.

        This test case checks the behavior of the assurance issue settings workflow manager when

        deleting assurance user defined issue in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                dnac_version="2.3.7.9",
                config=self.playbook_config_No_data_found,
                config_verify=True
            )
        )
        result = self.execute_module(changed=False, failed=True)
        print(result)
        self.assertEqual(
            result['msg'],
            "No data received for the issue: {'issue_name': 'jan8_1', 'issue_process_type': 'resolution'}"
        )

    def test_assurance_issue_settings_workflow_manager_resolution(self):
        """
        Test case for assurance issue settings workflow manager when creating a device credential.

        This test case checks the behavior of the assurance issue settings workflow manager when

        deleting assurance user defined issue in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                dnac_version="2.3.7.9",
                config=self.playbook_config_resolution,
                config_verify=True
            )
        )
        result = self.execute_module(changed=True, failed=False)
        print(result['msg'])
        self.assertEqual(
            result['msg'],
            "Issue resolution verified successfully for '[{'issue_name': 'Rangatestlink', 'issue_process_type': 'resolution'}]'."
        )

    def test_assurance_issue_settings_workflow_manager_ignore(self):
        """
        Test case for assurance issue settings workflow manager when creating a device credential.

        This test case checks the behavior of the assurance issue settings workflow manager when

        deleting assurance user defined issue in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                dnac_version="2.3.7.9",
                config=self.playbook_config_ignore,
                config_verify=True
            )
        )
        result = self.execute_module(changed=False, failed=True)
        print(result['response']['input_isssue_config'])
        self.assertEqual(
            result['response']['input_isssue_config'],
            [{'issue_name': 'Excessive time lag between Cisco Catalyst Center and device "DC-T-9300"', 'issue_process_type': 'ignore'}]
        )

    def test_assurance_issue_settings_workflow_manager_invalid_severity(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_invalid_severity
            )
        )
        result = self.execute_module(changed=False, failed=True)
        self.assertIn("Invalid parameters in playbook config", result['response'])

    def test_assurance_issue_settings_workflow_manager_invalid_duration(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_invalid_duration
            )
        )
        result = self.execute_module(changed=False, failed=True)
        self.assertIn("Invalid parameters in playbook config", result['response'])

    def test_assurance_issue_settings_workflow_manager_invalid_priority(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_invalid_priority
            )
        )
        result = self.execute_module(changed=False, failed=True)
        self.assertIn("Invalid parameters in playbook config", result['response'])

    def test_assurance_issue_settings_workflow_manager_invalid_time_format(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_invalid_time_format
            )
        )
        result = self.execute_module(changed=False, failed=True)
        self.assertIn("Invalid parameters in playbook config", result['response'])
        self.assertIn("Unable to validate Start date time, end date time", result['response'])
        self.assertIn("time data '2024-12-41 16:00:00' does not match format", result['response'])
