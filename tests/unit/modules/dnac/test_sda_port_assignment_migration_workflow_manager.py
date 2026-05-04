# Copyright (c) 2024 Cisco and/or its affiliates.
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
"""
Unit tests for sda_port_assignment_migration_workflow_manager.

The fixtures used here were captured from a real integration-test run against a live
Catalyst Center fabric (TB4). For each scenario, the per-scenario block of API responses
from dnac.log was extracted by tests/workflow/extract_fixtures_from_log.py into
tests/unit/modules/dnac/fixtures/sda_port_assignment_migration_workflow_manager.json.

Each test method here mirrors one integration-test scenario:

    scenario_01 -> test_migrate_with_mapping_add_path
    scenario_02 -> test_migrate_with_mapping_idempotent
    scenario_03 -> test_migrate_with_mapping_by_hostname
    scenario_04 -> test_invalid_fabric_hierarchy_prefix
    scenario_05 -> test_invalid_source_device_missing_identifier
    scenario_06 -> test_invalid_source_device_bad_ipv4
    scenario_07 -> test_invalid_same_source_and_destination
    scenario_08 -> test_invalid_empty_interface_mapping
    scenario_09 -> test_invalid_duplicate_source_interface
    scenario_10 -> test_invalid_duplicate_destination_interface
    scenario_11 -> test_invalid_source_device_not_in_inventory
    scenario_12 -> test_invalid_fabric_site_not_found
    scenario_13 -> test_invalid_mapping_source_interface_not_on_device
    scenario_14 -> test_invalid_mapping_destination_interface_not_on_device

The positive scenarios rely on the recorded GET/POST/task-poll responses; the offline
negative scenarios (4-10) short-circuit in validate_input() without any API traffic and
therefore need no fixtures. The API-backed negative scenarios (11-14) use the captured
partial response streams up to the point at which the module raises its validation error.
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import patch

from ansible_collections.cisco.dnac.plugins.modules import (
    sda_port_assignment_migration_workflow_manager,
)
from .dnac_module import TestDnacModule, set_module_args, loadPlaybookData


# ---------------------------------------------------------------------------
# Shared per-scenario input payloads. Mirror the vars file used by the
# integration test (tests/integration/ccc_sda_port_assignment_migration_management/
# vars/vars_sda_port_assignment_migration_management.yml) so the same config is
# asserted against the captured responses.
# ---------------------------------------------------------------------------

_FABRIC = "Global/USA/San Jose/BLDG23"
_SRC_IP = "204.1.2.5"
_DEST_IP = "204.1.2.6"
_SRC_HOSTNAME = "IAC-TB4-SJ-EN1-9300.cisco.com"
_DEST_HOSTNAME = "IAC-TB4-SJ-EN2-9300.cisco.com"

_FULL_MAPPING = [
    {"source_interface": "GigabitEthernet1/0/5",
     "destination_interface": "GigabitEthernet2/0/5"},
    {"source_interface": "GigabitEthernet1/0/6",
     "destination_interface": "GigabitEthernet2/0/6"},
    {"source_interface": "GigabitEthernet1/0/8",
     "destination_interface": "GigabitEthernet2/0/8"},
]


def _migrate_with_mapping_cfg(src, dest):
    return {
        "fabric_site_name_hierarchy": _FABRIC,
        "source_device": src,
        "destination_device": dest,
        "interface_mapping": _FULL_MAPPING,
    }


CFG_SCENARIO_01 = _migrate_with_mapping_cfg(
    {"ip_address": _SRC_IP}, {"ip_address": _DEST_IP}
)
CFG_SCENARIO_02 = CFG_SCENARIO_01  # identical input, fixture data differs
CFG_SCENARIO_03 = _migrate_with_mapping_cfg(
    {"hostname": _SRC_HOSTNAME}, {"hostname": _DEST_HOSTNAME}
)

CFG_SCENARIO_04 = {
    "fabric_site_name_hierarchy": "USA/San Jose/BLDG23",
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _DEST_IP},
}
CFG_SCENARIO_05 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {},
    "destination_device": {"ip_address": _DEST_IP},
}
CFG_SCENARIO_06 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": "not.an.ip.addr"},
    "destination_device": {"ip_address": _DEST_IP},
}
CFG_SCENARIO_07 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _SRC_IP},
}
CFG_SCENARIO_08 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _DEST_IP},
    "interface_mapping": [],
}
CFG_SCENARIO_09 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _DEST_IP},
    "interface_mapping": [
        {"source_interface": "GigabitEthernet1/0/5",
         "destination_interface": "GigabitEthernet2/0/5"},
        {"source_interface": "GigabitEthernet1/0/5",
         "destination_interface": "GigabitEthernet2/0/6"},
    ],
}
CFG_SCENARIO_10 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _DEST_IP},
    "interface_mapping": [
        {"source_interface": "GigabitEthernet1/0/5",
         "destination_interface": "GigabitEthernet2/0/5"},
        {"source_interface": "GigabitEthernet1/0/6",
         "destination_interface": "GigabitEthernet2/0/5"},
    ],
}
CFG_SCENARIO_11 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": "10.255.255.254"},
    "destination_device": {"ip_address": _DEST_IP},
    "interface_mapping": [
        {"source_interface": "GigabitEthernet1/0/5",
         "destination_interface": "GigabitEthernet2/0/5"},
    ],
}
CFG_SCENARIO_12 = {
    "fabric_site_name_hierarchy": "Global/USA/San Jose/NONEXISTENT_BUILDING",
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _DEST_IP},
    "interface_mapping": [
        {"source_interface": "GigabitEthernet1/0/5",
         "destination_interface": "GigabitEthernet2/0/5"},
    ],
}
CFG_SCENARIO_13 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _DEST_IP},
    "interface_mapping": [
        {"source_interface": "GigabitEthernet9/9/9",
         "destination_interface": "GigabitEthernet2/0/5"},
    ],
}
CFG_SCENARIO_14 = {
    "fabric_site_name_hierarchy": _FABRIC,
    "source_device": {"ip_address": _SRC_IP},
    "destination_device": {"ip_address": _DEST_IP},
    "interface_mapping": [
        {"source_interface": "GigabitEthernet1/0/5",
         "destination_interface": "GigabitEthernet9/9/9"},
    ],
}


# Minimum module-parameter boilerplate shared by every test. Matches dnac_version to
# the real TB4 version under test (the module gates on MIN_SUPPORTED_CCC_VERSION
# 2.3.7.6 and tests in dnac_version < 2.3.7.6 would short-circuit).
_BASE_ARGS = dict(
    dnac_host="1.1.1.1",
    dnac_port="443",
    dnac_username="admin",
    dnac_password="dummy",
    dnac_verify=False,
    dnac_version="3.1.6.0",
    dnac_debug=False,
    dnac_log=False,
    dnac_log_level="DEBUG",
    dnac_log_append=False,
    config_verify=True,
    state="merged",
)


def _fixture_events_to_side_effect(events):
    """
    Convert the captured event stream from the fixture file into an ordered list of
    values suitable as the side_effect of a DNACSDK._exec() mock.

    - GET and POST responses are the raw dict that _exec() returns, so pass through.
    - Task-detail events record the INNER "response" value from get_tasks_by_id()'s
      log line, so re-wrap them as {"response": <value>} to match the shape _exec()
      returns in get_tasks_by_id.
    """
    side_effect = []
    for event in events:
        if event["kind"] == "task_detail":
            side_effect.append({"response": event["value"]})
        else:
            side_effect.append(event["value"])
    return side_effect


# ---------------------------------------------------------------------------
# Synthetic fixture builders.
#
# The integration testbed can only exercise a subset of the module's code paths
# (the testbed's destination device starts either empty or identical to the
# source). The helpers below fabricate Catalyst Center API responses that let
# us drive the update / port-channel / verification / sad-path code paths
# without needing live infrastructure.
#
# Every builder returns the same shape the real Catalyst Center SDK returns
# so the module's response-parsing code sees nothing unusual.
# ---------------------------------------------------------------------------

class _Synth:
    """Namespace of stateless factory helpers for synthetic fixtures."""

    FABRIC_ID = "fab-synthetic-0001"
    SITE_ID = "site-synthetic-0001"
    SITE_HIERARCHY = "Global/Lab/Bldg1"
    SRC_DEVICE_ID = "src-dev-id-0001"
    DEST_DEVICE_ID = "dest-dev-id-0001"
    SRC_IP = "10.10.10.5"
    DEST_IP = "10.10.10.6"
    SRC_HOSTNAME = "src.lab.local"
    DEST_HOSTNAME = "dest.lab.local"

    @staticmethod
    def get_sites():
        return {
            "response": [{
                "id": _Synth.SITE_ID,
                "siteHierarchyId": "root-id/bldg-id/{0}".format(_Synth.SITE_ID),
                "parentId": "bldg-parent-id",
                "name": "Bldg1",
                "nameHierarchy": _Synth.SITE_HIERARCHY,
                "type": "building",
            }],
            "version": "1.0",
        }

    @staticmethod
    def get_fabric_sites(fabric_id=None):
        return {
            "response": [{
                "id": fabric_id or _Synth.FABRIC_ID,
                "siteId": _Synth.SITE_ID,
                "authenticationProfileName": "No Authentication",
            }],
            "version": "1.0",
        }

    @staticmethod
    def get_device(
        device_id, ip, hostname,
        reachable="Reachable",
        collection="Managed",
        family="Switches and Hubs",
    ):
        return {
            "response": [{
                "id": device_id,
                "managementIpAddress": ip,
                "hostname": hostname,
                "family": family,
                "reachabilityStatus": reachable,
                "collectionStatus": collection,
            }],
            "version": "1.0",
        }

    @staticmethod
    def empty_device_list():
        return {"response": [], "version": "1.0"}

    @staticmethod
    def multiple_devices(records):
        return {"response": records, "version": "1.0"}

    @staticmethod
    def get_fabric_devices(device_id, fabric_id=None, roles=None):
        return {
            "response": [{
                "id": "fd-{0}".format(device_id),
                "fabricId": fabric_id or _Synth.FABRIC_ID,
                "networkDeviceId": device_id,
                "deviceRoles": roles or ["EDGE_NODE"],
            }],
            "version": "1.0",
        }

    @staticmethod
    def empty_fabric_devices():
        return {"response": [], "version": "1.0"}

    @staticmethod
    def get_interfaces(device_id, interface_names):
        return {
            "response": [
                {
                    "portName": name,
                    "deviceId": device_id,
                    "interfaceType": "Physical",
                }
                for name in interface_names
            ],
            "version": "1.0",
        }

    @staticmethod
    def port_assignment(
        device_id, interface_name,
        vlan="VLAN_A",
        connected="USER_DEVICE",
        auth="No Authentication",
        record_id=None,
        fabric_id=None,
    ):
        return {
            "id": record_id or "pa-{0}-{1}".format(
                device_id, interface_name.replace("/", "_")
            ),
            "fabricId": fabric_id or _Synth.FABRIC_ID,
            "networkDeviceId": device_id,
            "interfaceName": interface_name,
            "connectedDeviceType": connected,
            "dataVlanName": vlan,
            "authenticateTemplateName": auth,
        }

    @staticmethod
    def get_port_assignments(records):
        return {"response": records, "version": "1.0"}

    @staticmethod
    def port_channel(
        device_id, channel_name, interface_names,
        protocol="ON",
        connected="TRUNK",
        record_id=None,
        fabric_id=None,
        description="",
    ):
        return {
            "id": record_id or "pc-{0}-{1}".format(device_id, channel_name),
            "fabricId": fabric_id or _Synth.FABRIC_ID,
            "networkDeviceId": device_id,
            "portChannelName": channel_name,
            "interfaceNames": list(interface_names),
            "connectedDeviceType": connected,
            "protocol": protocol,
            "description": description,
        }

    @staticmethod
    def get_port_channels(records):
        return {"response": records, "version": "1.0"}

    @staticmethod
    def post_task_response(task_id):
        return {
            "response": {
                "taskId": task_id,
                "url": "/dna/intent/api/v1/task/{0}".format(task_id),
            },
            "version": "1.0",
        }

    @staticmethod
    def task_detail(task_id, status="SUCCESS"):
        """Wrap a task-detail payload as _exec would return from get_tasks_by_id."""
        detail = {
            "id": task_id,
            "status": status,
            "startTime": 1000,
            "resultLocation": "/dna/intent/api/v1/tasks/{0}/detail".format(task_id),
        }
        # Only SUCCESS and FAILURE task states populate endTime; the poll loop
        # treats a missing endTime as "not finished yet".
        if status in ("SUCCESS", "FAILURE"):
            detail["endTime"] = 2000
        return {"response": detail}

    @staticmethod
    def collect_interfaces(port_assignments, port_channels):
        interfaces = set()
        for pa in port_assignments:
            name = pa.get("interfaceName")
            if name:
                interfaces.add(name)
        for pc in port_channels:
            for intf in pc.get("interfaceNames") or []:
                interfaces.add(intf)
        return interfaces

    @staticmethod
    def prelude(
        source_pa, dest_pa, source_pc, dest_pc,
        src_interfaces=None,
        dest_interfaces=None,
        src_device=None,
        dest_device=None,
        src_fabric=None,
        dest_fabric=None,
    ):
        """
        Build the 12 API calls every successful get_have path goes through:
        get_sites, get_fabric_sites, get_device_list (src), get_device_list (dest),
        get_fabric_devices (src), get_fabric_devices (dest), get_interface_info_by_id
        (src), get_interface_info_by_id (dest), get_port_assignments (src), get_port_
        assignments (dest), get_port_channels (src), get_port_channels (dest).
        """
        if src_interfaces is None:
            src_interfaces = _Synth.collect_interfaces(source_pa, source_pc)
        if dest_interfaces is None:
            dest_interfaces = _Synth.collect_interfaces(dest_pa, dest_pc)

        return [
            _Synth.get_sites(),
            _Synth.get_fabric_sites(),
            src_device if src_device is not None else _Synth.get_device(
                _Synth.SRC_DEVICE_ID, _Synth.SRC_IP, _Synth.SRC_HOSTNAME
            ),
            dest_device if dest_device is not None else _Synth.get_device(
                _Synth.DEST_DEVICE_ID, _Synth.DEST_IP, _Synth.DEST_HOSTNAME
            ),
            src_fabric if src_fabric is not None else _Synth.get_fabric_devices(
                _Synth.SRC_DEVICE_ID
            ),
            dest_fabric if dest_fabric is not None else _Synth.get_fabric_devices(
                _Synth.DEST_DEVICE_ID
            ),
            _Synth.get_interfaces(_Synth.SRC_DEVICE_ID, sorted(src_interfaces)),
            _Synth.get_interfaces(_Synth.DEST_DEVICE_ID, sorted(dest_interfaces)),
            _Synth.get_port_assignments(source_pa),
            _Synth.get_port_assignments(dest_pa),
            _Synth.get_port_channels(source_pc),
            _Synth.get_port_channels(dest_pc),
        ]

    @staticmethod
    def task_chain(task_id, num_polls=1):
        """One POST that returns taskId, then num_polls task_detail SUCCESS polls."""
        return [_Synth.post_task_response(task_id)] + [
            _Synth.task_detail(task_id, "SUCCESS") for unused_idx in range(num_polls)
        ]

    @staticmethod
    def verify_epilogue(dest_pa, dest_pc):
        """The 2 additional API calls verify_diff_merged makes on the destination."""
        return [
            _Synth.get_port_assignments(dest_pa),
            _Synth.get_port_channels(dest_pc),
        ]


# Base config used by every synthetic test.
_SYNTH_BASE_CFG = {
    "fabric_site_name_hierarchy": _Synth.SITE_HIERARCHY,
    "source_device": {"ip_address": _Synth.SRC_IP},
    "destination_device": {"ip_address": _Synth.DEST_IP},
}


class TestSDAPortAssignmentMigrationWorkflowManager(TestDnacModule):
    """Driver for all 14 scenarios captured from the integration test."""

    module = sda_port_assignment_migration_workflow_manager
    fixture_data = loadPlaybookData(
        "sda_port_assignment_migration_workflow_manager"
    )

    # Mapping from test-method-name substring to scenario_XX fixture key.
    _METHOD_TO_SCENARIO = {
        "migrate_with_mapping_add_path": "scenario_01",
        "migrate_with_mapping_idempotent": "scenario_02",
        "migrate_with_mapping_by_hostname": "scenario_03",
        "invalid_fabric_hierarchy_prefix": "scenario_04",
        "invalid_source_device_missing_identifier": "scenario_05",
        "invalid_source_device_bad_ipv4": "scenario_06",
        "invalid_same_source_and_destination": "scenario_07",
        "invalid_empty_interface_mapping": "scenario_08",
        "invalid_duplicate_source_interface": "scenario_09",
        "invalid_duplicate_destination_interface": "scenario_10",
        "invalid_source_device_not_in_inventory": "scenario_11",
        "invalid_fabric_site_not_found": "scenario_12",
        "invalid_mapping_source_interface_not_on_device": "scenario_13",
        "invalid_mapping_destination_interface_not_on_device": "scenario_14",
    }

    def setUp(self):
        super().setUp()
        self.mock_dnac_init = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK.__init__"
        )
        self.run_dnac_init = self.mock_dnac_init.start()
        self.run_dnac_init.side_effect = [None]
        self.mock_dnac_exec = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK._exec"
        )
        self.run_dnac_exec = self.mock_dnac_exec.start()

    def tearDown(self):
        super().tearDown()
        self.mock_dnac_init.stop()
        self.mock_dnac_exec.stop()

    def load_fixtures(self, response=None, device=""):
        """
        Select the scenario fixture that matches the currently running test method and
        install its event stream as the side_effect of the DNACSDK._exec mock.

        Captured-scenario tests pick from the JSON fixture file; synthetic tests stash
        their pre-computed side_effect list on the instance as `_synth_side_effect`
        before calling execute_module(). Scenarios with neither (the offline
        validation ones) leave side_effect empty - the module is expected to fail
        before any API call is made.
        """
        for method_fragment, scenario_key in self._METHOD_TO_SCENARIO.items():
            if method_fragment in self._testMethodName:
                events = self.fixture_data.get(scenario_key) or []
                self.run_dnac_exec.side_effect = _fixture_events_to_side_effect(events)
                return

        # Synthetic tests stash their own side_effect list for load_fixtures to apply.
        synth = getattr(self, "_synth_side_effect", None)
        if synth is not None:
            self.run_dnac_exec.side_effect = list(synth)
            return

        # Offline validation tests fall through here with an empty list.
        self.run_dnac_exec.side_effect = []

    # ---------------------------------------------------------------------
    # Positive scenarios
    # ---------------------------------------------------------------------

    def test_migrate_with_mapping_add_path(self):
        """
        Scenario 1: destination is clean, all three source port assignments must be
        added to the destination via the single add_port_assignments API call.
        Expected: changed=true, result describes the add operation.
        """
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_01]))
        result = self.execute_module(changed=True, failed=False)
        msg = result.get("msg") or {}
        self.assertIsInstance(msg, dict)
        self.assertIn(
            "Add Port Assignment(s) Task Succeeded for following interface(s)",
            msg,
        )
        added_bucket = msg[
            "Add Port Assignment(s) Task Succeeded for following interface(s)"
        ]
        self.assertEqual(added_bucket.get("success_count"), 3)
        self.assertEqual(
            sorted(added_bucket.get("success_interfaces") or []),
            [
                "GigabitEthernet2/0/5",
                "GigabitEthernet2/0/6",
                "GigabitEthernet2/0/8",
            ],
        )

    def test_migrate_with_mapping_idempotent(self):
        """
        Scenario 2: destination already matches source. All three interfaces should be
        classified as no_update; no add/update API calls are made.
        """
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_02]))
        result = self.execute_module(changed=False, failed=False)
        msg = result.get("msg") or {}
        self.assertIsInstance(msg, dict)
        self.assertIn(
            "Port assignment does not needs any update for following interface(s)",
            msg,
        )
        no_update = msg[
            "Port assignment does not needs any update for following interface(s)"
        ]
        self.assertEqual(no_update.get("success_count"), 3)
        self.assertEqual(
            sorted(no_update.get("port_assignments_no_update_needed") or []),
            [
                "GigabitEthernet2/0/5",
                "GigabitEthernet2/0/6",
                "GigabitEthernet2/0/8",
            ],
        )

    def test_migrate_with_mapping_by_hostname(self):
        """
        Scenario 3: same as idempotent, but source/destination identified by hostname.
        Exercises the hostname branch of _resolve_device (get_device_list with
        {"hostname": ...}).
        """
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_03]))
        result = self.execute_module(changed=False, failed=False)
        msg = result.get("msg") or {}
        self.assertIsInstance(msg, dict)
        self.assertIn(
            "Port assignment does not needs any update for following interface(s)",
            msg,
        )

    # ---------------------------------------------------------------------
    # Offline negative scenarios (no API traffic - fail in validate_input)
    # ---------------------------------------------------------------------

    def test_invalid_fabric_hierarchy_prefix(self):
        """Scenario 4: hierarchy missing the 'Global/' prefix -> validate fails."""
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_04]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "must start with 'Global/'",
            self._msg_text(result),
        )

    def test_invalid_source_device_missing_identifier(self):
        """Scenario 5: source_device lacks both ip_address and hostname."""
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_05]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "must provide at least one of 'ip_address' or 'hostname'",
            self._msg_text(result),
        )

    def test_invalid_source_device_bad_ipv4(self):
        """Scenario 6: invalid IPv4 address in source_device.ip_address."""
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_06]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn("is not a valid IPv4 address", self._msg_text(result))

    def test_invalid_same_source_and_destination(self):
        """Scenario 7: source and destination resolve to the same device."""
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_07]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "cannot reference the same device",
            self._msg_text(result),
        )

    def test_invalid_empty_interface_mapping(self):
        """Scenario 8: interface_mapping supplied as an empty list."""
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_08]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "'interface_mapping' cannot be an empty list",
            self._msg_text(result),
        )

    def test_invalid_duplicate_source_interface(self):
        """Scenario 9: duplicate source_interface entries in interface_mapping."""
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_09]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "Duplicate 'source_interface'",
            self._msg_text(result),
        )

    def test_invalid_duplicate_destination_interface(self):
        """Scenario 10: duplicate destination_interface entries in interface_mapping."""
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_10]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "Duplicate 'destination_interface'",
            self._msg_text(result),
        )

    # ---------------------------------------------------------------------
    # API-backed negative scenarios (partial fixture streams until fail)
    # ---------------------------------------------------------------------

    def test_invalid_source_device_not_in_inventory(self):
        """
        Scenario 11: source device IP returns an empty device list from
        get_device_list - _resolve_device should raise a "not found" error.
        """
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_11]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "was not found in Catalyst Center inventory",
            self._msg_text(result),
        )

    def test_invalid_fabric_site_not_found(self):
        """
        Scenario 12: fabric site hierarchy does not resolve. get_site_id returns
        a non-matching / empty result and _resolve_fabric_id fails.
        """
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_12]))
        result = self.execute_module(failed=True, changed=False)
        text = self._msg_text(result)
        # The failure originates in DnacBase.get_site_id which phrases the error as
        # "does not exist in the Catalyst Center". Our own fallback ("was not found in
        # Catalyst Center") is reached only if get_site_id returns instead of raising;
        # and a site-present-but-not-fabric path would produce "not configured as an
        # SDA fabric site". Accept any of those three.
        self.assertTrue(
            "does not exist in the" in text
            or "was not found in Catalyst Center" in text
            or "not configured as an SDA fabric site" in text,
            "Unexpected failure message: {0}".format(text),
        )

    def test_invalid_mapping_source_interface_not_on_device(self):
        """
        Scenario 13: interface_mapping references a source_interface that does not
        exist on the source device. Exercises Rule A in
        _validate_interface_mapping_against_devices.
        """
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_13]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "does not exist on the source device",
            self._msg_text(result),
        )

    def test_invalid_mapping_destination_interface_not_on_device(self):
        """
        Scenario 14: interface_mapping references a destination_interface that does
        not exist on the destination device. Exercises Rule A (destination side).
        """
        set_module_args(dict(_BASE_ARGS, config=[CFG_SCENARIO_14]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "does not exist on the destination device",
            self._msg_text(result),
        )

    # ---------------------------------------------------------------------
    # Additional synthetic validation tests (no fixture replay required)
    #
    # These cover validation code paths that the integration testbed cannot
    # exercise (e.g., destination-side variants of the source-side checks,
    # unsupported states, old Catalyst Center versions, malformed mapping
    # entries, port-channel member mapping rules). They are offline checks
    # handled by validate_input() or the main() prelude; no API calls occur.
    # ---------------------------------------------------------------------

    def test_unsupported_state_deleted_fails(self):
        """The module only supports state=merged. state=deleted must be rejected."""
        self.run_dnac_exec.side_effect = []
        cfg = _migrate_with_mapping_cfg(
            {"ip_address": _SRC_IP}, {"ip_address": _DEST_IP}
        )
        args = dict(_BASE_ARGS, config=[cfg])
        args["state"] = "deleted"
        set_module_args(args)
        # Ansible's AnsibleModule will reject an invalid choice at argspec
        # validation time, which surfaces as a failure.
        result = self.execute_module(failed=True, changed=False)
        self.assertIn("deleted", self._msg_text(result))

    def test_ccc_version_too_old_fails(self):
        """Running the module against a Catalyst Center version older than 2.3.7.6 fails."""
        self.run_dnac_exec.side_effect = []
        cfg = _migrate_with_mapping_cfg(
            {"ip_address": _SRC_IP}, {"ip_address": _DEST_IP}
        )
        args = dict(_BASE_ARGS, config=[cfg])
        args["dnac_version"] = "2.3.5.3"
        set_module_args(args)
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "does not support the SDA Port Assignment Migration",
            self._msg_text(result),
        )

    def test_invalid_destination_device_missing_identifier(self):
        """Mirror of scenario 5 but for destination_device - both fields missing."""
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"ip_address": _SRC_IP},
            "destination_device": {},
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "must provide at least one of 'ip_address' or 'hostname'",
            self._msg_text(result),
        )

    def test_invalid_destination_device_bad_ipv4(self):
        """Mirror of scenario 6 but for destination_device.ip_address."""
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"ip_address": _SRC_IP},
            "destination_device": {"ip_address": "999.bad.ipv4"},
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn("is not a valid IPv4 address", self._msg_text(result))

    def test_invalid_same_hostname_source_and_destination(self):
        """
        Scenario 7 variant: same hostname on source and destination. Exercises the
        hostname branch of _validate_source_destination_not_same.
        """
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"hostname": _SRC_HOSTNAME},
            "destination_device": {"hostname": _SRC_HOSTNAME},
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "cannot reference the same device",
            self._msg_text(result),
        )

    def test_invalid_mapping_entry_non_dict(self):
        """interface_mapping entry that is not a dict must fail validation.

        The DnacBase.validate_list_of_dicts helper rejects this before our
        own per-entry check gets a chance to run, so the error message is
        "is not of the same datatype as expected which is dict".
        """
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"ip_address": _SRC_IP},
            "destination_device": {"ip_address": _DEST_IP},
            "interface_mapping": ["not a dict"],
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        text = self._msg_text(result)
        self.assertTrue(
            "must be a dictionary" in text
            or "is not of the same datatype" in text,
            "Unexpected failure message: {0}".format(text),
        )

    def test_invalid_mapping_missing_source_interface(self):
        """interface_mapping entry with no source_interface must fail."""
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"ip_address": _SRC_IP},
            "destination_device": {"ip_address": _DEST_IP},
            "interface_mapping": [
                {"destination_interface": "GigabitEthernet2/0/5"},
            ],
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "missing or empty 'source_interface'",
            self._msg_text(result),
        )

    def test_invalid_mapping_missing_destination_interface(self):
        """interface_mapping entry with no destination_interface must fail."""
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"ip_address": _SRC_IP},
            "destination_device": {"ip_address": _DEST_IP},
            "interface_mapping": [
                {"source_interface": "GigabitEthernet1/0/5"},
            ],
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "missing or empty 'destination_interface'",
            self._msg_text(result),
        )

    def test_invalid_mapping_bad_source_interface_name(self):
        """interface_mapping entry with a non-Cisco-format source_interface must fail."""
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"ip_address": _SRC_IP},
            "destination_device": {"ip_address": _DEST_IP},
            "interface_mapping": [
                {"source_interface": "not an interface",
                 "destination_interface": "GigabitEthernet2/0/5"},
            ],
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "does not look like a valid Cisco interface name",
            self._msg_text(result),
        )

    def test_invalid_mapping_is_not_a_list(self):
        """interface_mapping provided as a dict (not a list) must fail."""
        self.run_dnac_exec.side_effect = []
        cfg = {
            "fabric_site_name_hierarchy": _FABRIC,
            "source_device": {"ip_address": _SRC_IP},
            "destination_device": {"ip_address": _DEST_IP},
            "interface_mapping": {"GigabitEthernet1/0/5": "GigabitEthernet2/0/5"},
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        # argspec's type=list first catches this; accept either wording.
        self.assertTrue(
            "list" in self._msg_text(result).lower(),
            "Unexpected failure message: {0}".format(self._msg_text(result)),
        )

    # ---------------------------------------------------------------------
    # Synthetic fixture tests
    #
    # These use fabricated Catalyst Center API responses so we can drive the
    # module through code paths the integration testbed can't produce - update
    # flows for port assignments and port channels, add port channels, combined
    # operations, no-mapping identity migration, and all of the API-backed
    # sad-path branches that need specific API response shapes.
    # ---------------------------------------------------------------------

    # --- Positive paths ---

    def test_synth_update_port_assignments_changes_vlan(self):
        """
        Destination already has the same interface with a different VLAN.
        Classification should route it into the update bucket, the module should
        call update_port_assignments, and changed should be True.
        """
        src_pa = [
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/1",
                                   vlan="VLAN_NEW"),
        ]
        dest_pa = [
            _Synth.port_assignment(_Synth.DEST_DEVICE_ID, "GigabitEthernet1/0/1",
                                   vlan="VLAN_OLD"),
        ]
        prelude = _Synth.prelude(src_pa, dest_pa, [], [])
        self._synth_side_effect = (
            prelude
            # task_chain MUST use num_polls=1: the poll loop breaks as soon as
            # it sees an endTime, so a second task_detail would be left over
            # and the *next* _exec call (verify's get_port_assignments) would
            # consume it - corrupting the list with its dict keys.
            + _Synth.task_chain("task-update-pa", num_polls=1)
            + _Synth.verify_epilogue(
                [_Synth.port_assignment(_Synth.DEST_DEVICE_ID,
                                        "GigabitEthernet1/0/1", vlan="VLAN_NEW")],
                [],
            )
        )
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[{
            "source_interface": "GigabitEthernet1/0/1",
            "destination_interface": "GigabitEthernet1/0/1",
        }])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(changed=True, failed=False)
        msg = result.get("msg") or {}
        self.assertIsInstance(msg, dict)
        self.assertIn(
            "Update Port Assignment(s) Task Succeeded for following interface(s)",
            msg,
        )

    def test_synth_add_port_channels_only(self):
        """
        Source has one port channel (no assignments), destination has nothing.
        The module should add the port channel and report changed=True.
        """
        src_pc = [
            _Synth.port_channel(
                _Synth.SRC_DEVICE_ID, "Port-channel1",
                ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"],
                protocol="LACP",
                connected="TRUNK",
            ),
        ]
        # Need at least one source port assignment (to avoid the "nothing to
        # migrate" guard). Actually the guard allows just channels. Let's
        # keep assignments empty to exercise the channels-only path.
        src_pa = []
        # Destination has no existing port-channels / assignments, so
        # collect_interfaces would yield an empty dest_interfaces set and the
        # mapping validation would reject TenGi1/0/1. Declare the interfaces
        # explicitly so the dest get_interfaces fixture reports them as
        # physically present.
        prelude = _Synth.prelude(
            src_pa, [], src_pc, [],
            dest_interfaces={"TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"},
        )
        self._synth_side_effect = (
            prelude
            + _Synth.task_chain("task-add-pc", num_polls=1)
            + _Synth.verify_epilogue(
                [],
                [_Synth.port_channel(
                    _Synth.DEST_DEVICE_ID, "Port-channel1",
                    ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"],
                    protocol="LACP", connected="TRUNK",
                )],
            )
        )
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
            {"source_interface": "TenGigabitEthernet1/0/2",
             "destination_interface": "TenGigabitEthernet1/0/2"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(changed=True, failed=False)
        msg = result.get("msg") or {}
        self.assertIsInstance(msg, dict)
        self.assertIn(
            "Add Port Channel(s) Task Succeeded for following port channel(s)",
            msg,
        )

    def test_synth_update_port_channels_description_change(self):
        """
        Source and destination have matching port channel members, but different
        descriptions. Classification should route to update; the module should
        invoke update_port_channels and report changed=True.
        """
        members = ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"]
        src_pc = [
            _Synth.port_channel(
                _Synth.SRC_DEVICE_ID, "Port-channel1", members,
                protocol="LACP", connected="TRUNK",
                description="new-description",
            ),
        ]
        dest_pc = [
            _Synth.port_channel(
                _Synth.DEST_DEVICE_ID, "Port-channel1", members,
                protocol="LACP", connected="TRUNK",
                description="old-description",
            ),
        ]
        src_pa = []
        prelude = _Synth.prelude(src_pa, [], src_pc, dest_pc)
        self._synth_side_effect = (
            prelude
            + _Synth.task_chain("task-update-pc", num_polls=1)
            + _Synth.verify_epilogue([], dest_pc)
        )
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
            {"source_interface": "TenGigabitEthernet1/0/2",
             "destination_interface": "TenGigabitEthernet1/0/2"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(changed=True, failed=False)
        msg = result.get("msg") or {}
        self.assertIn(
            "Update Port Channel(s) Task Succeeded for following port channel(s)",
            msg,
        )

    def test_synth_no_update_port_channels_path(self):
        """
        Source and destination port channels already match exactly. Changed=False,
        the result should include the no-update port channel bucket.
        """
        members = ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"]
        src_pc = [
            _Synth.port_channel(
                _Synth.SRC_DEVICE_ID, "Port-channel1", members,
                protocol="LACP", connected="TRUNK",
            ),
        ]
        dest_pc = [
            _Synth.port_channel(
                _Synth.DEST_DEVICE_ID, "Port-channel1", members,
                protocol="LACP", connected="TRUNK",
            ),
        ]
        prelude = _Synth.prelude([], [], src_pc, dest_pc)
        self._synth_side_effect = prelude + _Synth.verify_epilogue([], dest_pc)
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
            {"source_interface": "TenGigabitEthernet1/0/2",
             "destination_interface": "TenGigabitEthernet1/0/2"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(changed=False, failed=False)
        msg = result.get("msg") or {}
        self.assertIn(
            "Port channel does not needs any update for following port channel(s)",
            msg,
        )

    def test_synth_combined_add_update_operations(self):
        """
        Source has two interfaces: Gi1/0/1 (new on destination) and Gi1/0/2
        (existing on destination with a different VLAN). Exercise both the add
        and update branches in the same run, plus a matching unchanged one.
        """
        src_pa = [
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/1",
                                   vlan="VLAN_NEW"),
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/2",
                                   vlan="VLAN_NEW"),
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/3",
                                   vlan="VLAN_KEEP"),
        ]
        dest_pa = [
            # Gi1/0/1 is absent on destination -> add path
            _Synth.port_assignment(_Synth.DEST_DEVICE_ID, "GigabitEthernet1/0/2",
                                   vlan="VLAN_OLD"),  # update path
            _Synth.port_assignment(_Synth.DEST_DEVICE_ID, "GigabitEthernet1/0/3",
                                   vlan="VLAN_KEEP"),  # no-update path
        ]
        # Destination inventory must physically include Gi1/0/1 (which is not
        # in dest_pa yet). Declare all three interface names so the dest
        # get_interfaces fixture reports them.
        prelude = _Synth.prelude(
            src_pa, dest_pa, [], [],
            dest_interfaces={
                "GigabitEthernet1/0/1",
                "GigabitEthernet1/0/2",
                "GigabitEthernet1/0/3",
            },
        )
        # Two tasks: add then update, each polled once.
        self._synth_side_effect = (
            prelude
            + _Synth.task_chain("task-add", num_polls=1)
            + _Synth.task_chain("task-upd", num_polls=1)
            + _Synth.verify_epilogue(
                [_Synth.port_assignment(_Synth.DEST_DEVICE_ID,
                                        "GigabitEthernet1/0/1", vlan="VLAN_NEW"),
                 _Synth.port_assignment(_Synth.DEST_DEVICE_ID,
                                        "GigabitEthernet1/0/2", vlan="VLAN_NEW"),
                 _Synth.port_assignment(_Synth.DEST_DEVICE_ID,
                                        "GigabitEthernet1/0/3", vlan="VLAN_KEEP")],
                [],
            )
        )
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
            {"source_interface": "GigabitEthernet1/0/2",
             "destination_interface": "GigabitEthernet1/0/2"},
            {"source_interface": "GigabitEthernet1/0/3",
             "destination_interface": "GigabitEthernet1/0/3"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(changed=True, failed=False)
        msg = result.get("msg") or {}
        self.assertIsInstance(msg, dict)
        self.assertIn(
            "Add Port Assignment(s) Task Succeeded for following interface(s)", msg)
        self.assertIn(
            "Update Port Assignment(s) Task Succeeded for following interface(s)", msg)
        self.assertIn(
            "Port assignment does not needs any update for following interface(s)",
            msg,
        )

    def test_synth_no_mapping_identity_migration(self):
        """
        No interface_mapping supplied -> identity mapping used. Destination has
        the same interface names available. This exercises Rule C in
        _validate_interface_mapping_against_devices and the identity-mapping
        branch of _build_interface_mapping_lookup.
        """
        src_pa = [
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/1"),
        ]
        prelude = _Synth.prelude(
            src_pa, [], [], [],
            # Destination has the interface available to receive the assignment.
            dest_interfaces={"GigabitEthernet1/0/1"},
        )
        self._synth_side_effect = (
            prelude
            + _Synth.task_chain("task-add-identity", num_polls=1)
            + _Synth.verify_epilogue(
                [_Synth.port_assignment(_Synth.DEST_DEVICE_ID,
                                        "GigabitEthernet1/0/1")],
                [],
            )
        )
        cfg = {
            "fabric_site_name_hierarchy": _Synth.SITE_HIERARCHY,
            "source_device": {"ip_address": _Synth.SRC_IP},
            "destination_device": {"ip_address": _Synth.DEST_IP},
            # No interface_mapping key -> identity mapping path.
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(changed=True, failed=False)
        msg = result.get("msg") or {}
        self.assertIn(
            "Add Port Assignment(s) Task Succeeded for following interface(s)", msg)

    # --- API-backed negative paths ---

    def test_synth_fail_source_device_unreachable(self):
        """Source device has reachabilityStatus != 'Reachable'."""
        self._synth_side_effect = [
            _Synth.get_sites(),
            _Synth.get_fabric_sites(),
            _Synth.get_device(
                _Synth.SRC_DEVICE_ID, _Synth.SRC_IP, _Synth.SRC_HOSTNAME,
                reachable="Unreachable",
            ),
        ]
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn("is not reachable from Catalyst Center", self._msg_text(result))

    def test_synth_fail_source_device_unmanaged(self):
        """Source device has collectionStatus not in {Managed, In Progress}."""
        self._synth_side_effect = [
            _Synth.get_sites(),
            _Synth.get_fabric_sites(),
            _Synth.get_device(
                _Synth.SRC_DEVICE_ID, _Synth.SRC_IP, _Synth.SRC_HOSTNAME,
                collection="Partial Collection Failure",
            ),
        ]
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "not in a manageable collection state", self._msg_text(result))

    def test_synth_fail_source_device_is_unified_ap(self):
        """Source device has family 'Unified AP' - unsupported."""
        self._synth_side_effect = [
            _Synth.get_sites(),
            _Synth.get_fabric_sites(),
            _Synth.get_device(
                _Synth.SRC_DEVICE_ID, _Synth.SRC_IP, _Synth.SRC_HOSTNAME,
                family="Unified AP",
            ),
        ]
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn("is a Unified AP", self._msg_text(result))

    def test_synth_fail_source_device_missing_ids(self):
        """
        Catalyst Center returns a device record missing id or managementIpAddress.
        This is a malformed-inventory scenario and must be caught explicitly.
        """
        self._synth_side_effect = [
            _Synth.get_sites(),
            _Synth.get_fabric_sites(),
            {
                "response": [{
                    # id deliberately missing
                    "hostname": _Synth.SRC_HOSTNAME,
                    "family": "Switches and Hubs",
                    "reachabilityStatus": "Reachable",
                    "collectionStatus": "Managed",
                }],
                "version": "1.0",
            },
        ]
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn("missing 'id' or 'managementIpAddress'", self._msg_text(result))

    def test_synth_fail_hostname_matches_multiple_devices(self):
        """Hostname filter returns multiple devices -> ambiguous match."""
        dup_records = [
            {
                "id": "dev-a",
                "managementIpAddress": "10.0.0.1",
                "hostname": _Synth.SRC_HOSTNAME,
                "family": "Switches and Hubs",
                "reachabilityStatus": "Reachable",
                "collectionStatus": "Managed",
            },
            {
                "id": "dev-b",
                "managementIpAddress": "10.0.0.2",
                "hostname": _Synth.SRC_HOSTNAME,
                "family": "Switches and Hubs",
                "reachabilityStatus": "Reachable",
                "collectionStatus": "Managed",
            },
        ]
        self._synth_side_effect = [
            _Synth.get_sites(),
            _Synth.get_fabric_sites(),
            _Synth.multiple_devices(dup_records),
        ]
        cfg = {
            "fabric_site_name_hierarchy": _Synth.SITE_HIERARCHY,
            # Hostname path to exercise the ambiguity branch.
            "source_device": {"hostname": _Synth.SRC_HOSTNAME},
            "destination_device": {"ip_address": _Synth.DEST_IP},
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "matched multiple devices in Catalyst Center inventory",
            self._msg_text(result),
        )

    def test_synth_fail_destination_not_provisioned_in_fabric(self):
        """Destination device exists in inventory but is not in the fabric."""
        self._synth_side_effect = [
            _Synth.get_sites(),
            _Synth.get_fabric_sites(),
            _Synth.get_device(_Synth.SRC_DEVICE_ID, _Synth.SRC_IP,
                              _Synth.SRC_HOSTNAME),
            _Synth.get_device(_Synth.DEST_DEVICE_ID, _Synth.DEST_IP,
                              _Synth.DEST_HOSTNAME),
            _Synth.get_fabric_devices(_Synth.SRC_DEVICE_ID),
            _Synth.empty_fabric_devices(),  # destination NOT provisioned
        ]
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn("is not provisioned in fabric site", self._msg_text(result))

    def test_synth_fail_source_has_nothing_to_migrate(self):
        """Source has no port assignments and no port channels - abort."""
        prelude = _Synth.prelude([], [], [], [])
        self._synth_side_effect = prelude
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "has no port assignments and no port channels",
            self._msg_text(result),
        )

    def test_synth_fail_port_channel_protocol_change(self):
        """
        Source + destination have matching port channel members, but the
        destination uses protocol 'ON' and the source uses 'LACP'. Catalyst
        Center does not allow protocol to change on an existing channel.
        """
        members = ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"]
        src_pc = [_Synth.port_channel(
            _Synth.SRC_DEVICE_ID, "Port-channel1", members,
            protocol="LACP", connected="TRUNK",
        )]
        dest_pc = [_Synth.port_channel(
            _Synth.DEST_DEVICE_ID, "Port-channel1", members,
            protocol="ON", connected="TRUNK",
        )]
        prelude = _Synth.prelude([], [], src_pc, dest_pc)
        self._synth_side_effect = prelude
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
            {"source_interface": "TenGigabitEthernet1/0/2",
             "destination_interface": "TenGigabitEthernet1/0/2"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "does not allow the protocol of a port channel to be updated",
            self._msg_text(result),
        )

    def test_synth_fail_port_channel_trunk_to_extended_without_pagp(self):
        """
        Destination port channel is TRUNK with protocol 'LACP'; source wants to
        transition it to EXTENDED_NODE. That transition requires existing
        protocol 'PAGP', so the migration must fail.
        """
        members = ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"]
        src_pc = [_Synth.port_channel(
            _Synth.SRC_DEVICE_ID, "Port-channel1", members,
            protocol="LACP", connected="EXTENDED_NODE",
        )]
        dest_pc = [_Synth.port_channel(
            _Synth.DEST_DEVICE_ID, "Port-channel1", members,
            protocol="LACP", connected="TRUNK",
        )]
        prelude = _Synth.prelude([], [], src_pc, dest_pc)
        self._synth_side_effect = prelude
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
            {"source_interface": "TenGigabitEthernet1/0/2",
             "destination_interface": "TenGigabitEthernet1/0/2"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "transitioning 'connectedDeviceType' from TRUNK to EXTENDED_NODE",
            self._msg_text(result),
        )

    def test_synth_fail_port_channel_overlap_with_different_channel(self):
        """
        Source port channel's translated members overlap with a *different*
        destination port channel (but don't equal its full member set). That's
        a cross-channel membership conflict.
        """
        src_members = ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"]
        dest_members = ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/3"]
        src_pc = [_Synth.port_channel(
            _Synth.SRC_DEVICE_ID, "Port-channel1", src_members,
            protocol="LACP",
        )]
        dest_pc = [_Synth.port_channel(
            _Synth.DEST_DEVICE_ID, "Port-channel2", dest_members,
            protocol="LACP",
        )]
        prelude = _Synth.prelude([], [], src_pc, dest_pc,
                                 dest_interfaces=set(src_members) | set(dest_members))
        self._synth_side_effect = prelude
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
            {"source_interface": "TenGigabitEthernet1/0/2",
             "destination_interface": "TenGigabitEthernet1/0/2"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "overlaps with an existing port channel on destination",
            self._msg_text(result),
        )

    def test_synth_fail_port_channel_partial_mapping(self):
        """
        Rule B: an explicit interface_mapping that omits some port channel members.
        A source port channel has two members, but the mapping only covers one.
        """
        src_pc = [_Synth.port_channel(
            _Synth.SRC_DEVICE_ID, "Port-channel1",
            ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"],
            protocol="LACP",
        )]
        # Declare the mapped destination interface physically so we clear Rule
        # A's "exists on destination" check and reach the Rule B partial
        # mapping check.
        prelude = _Synth.prelude(
            [], [], src_pc, [],
            dest_interfaces={"TenGigabitEthernet1/0/1"},
        )
        self._synth_side_effect = prelude
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            # Only one of two members is mapped.
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "Partial port channel mapping is not supported",
            self._msg_text(result),
        )

    def test_synth_fail_mapping_source_interface_has_no_data(self):
        """
        Rule A (third check): interface_mapping entry references an interface
        that exists on the source device but has no port assignment and is not
        a member of any port channel.
        """
        src_pa = [
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/1"),
        ]
        # Extra bare source interface Gi1/0/99 with nothing assigned to it.
        prelude = _Synth.prelude(
            src_pa, [], [], [],
            src_interfaces={"GigabitEthernet1/0/1", "GigabitEthernet1/0/99"},
            dest_interfaces={"GigabitEthernet1/0/1", "GigabitEthernet1/0/99"},
        )
        self._synth_side_effect = prelude
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/99",
             "destination_interface": "GigabitEthernet1/0/99"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "has no port assignment and is not a member of any port channel",
            self._msg_text(result),
        )

    def test_synth_fail_no_mapping_source_interface_not_on_destination(self):
        """
        Rule C: no interface_mapping supplied; the source device has an interface
        that does not exist on the destination device.
        """
        src_pa = [
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID,
                                   "GigabitEthernet1/0/42"),
        ]
        prelude = _Synth.prelude(
            src_pa, [], [], [],
            # Destination has no Gi1/0/42 (only a completely different interface).
            dest_interfaces={"GigabitEthernet1/0/1"},
        )
        self._synth_side_effect = prelude
        cfg = {
            "fabric_site_name_hierarchy": _Synth.SITE_HIERARCHY,
            "source_device": {"ip_address": _Synth.SRC_IP},
            "destination_device": {"ip_address": _Synth.DEST_IP},
            # No interface_mapping.
        }
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "does not exist on the destination device",
            self._msg_text(result),
        )

    def test_synth_fail_task_status_returns_failure(self):
        """
        POST add_port_assignments returns a taskId, but the task poll returns
        FAILURE. The module should surface the task failure.
        """
        src_pa = [
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/1"),
        ]
        prelude = _Synth.prelude(src_pa, [], [], [])
        self._synth_side_effect = (
            prelude
            + [_Synth.post_task_response("task-will-fail")]
            + [_Synth.task_detail("task-will-fail", status="FAILURE")]
            # task failure may trigger a failure-reason fetch; return empty to
            # be safe against any trailing _exec call. Extra items at the end
            # of side_effect are ignored if unused.
            + [{"response": []} for unused_idx in range(10)]
        )
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        # DnacBase surfaces task failures with a status/FAILURE reference; we
        # only need to confirm the module did not succeed.
        self.assertTrue(result.get("failed"))

    def test_synth_fail_add_port_channels_no_task_id(self):
        """
        POST add_port_channels returns a response but no taskId. The module
        must fail with a clear message.
        """
        members = ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/2"]
        src_pc = [_Synth.port_channel(
            _Synth.SRC_DEVICE_ID, "Port-channel1", members,
            protocol="LACP",
        )]
        # Declare the mapped destination interfaces physically so we clear the
        # mapping validation and reach the port-channels POST.
        prelude = _Synth.prelude(
            [], [], src_pc, [],
            dest_interfaces=set(members),
        )
        # POST returns a response with NO taskId.
        no_task_post = {"response": {"url": "/no-task-here"}, "version": "1.0"}
        self._synth_side_effect = prelude + [no_task_post]
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "TenGigabitEthernet1/0/1",
             "destination_interface": "TenGigabitEthernet1/0/1"},
            {"source_interface": "TenGigabitEthernet1/0/2",
             "destination_interface": "TenGigabitEthernet1/0/2"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        text = self._msg_text(result)
        # Either the module's own "did not return a task id" message or any
        # upstream task-id failure reason from DnacBase is acceptable.
        self.assertTrue(
            "did not return a task id" in text
            or "task id" in text.lower(),
            "Unexpected failure message: {0}".format(text),
        )

    def test_synth_fail_site_returns_empty_fabric(self):
        """
        Site exists but is not an SDA fabric site. get_fabric_sites returns an
        empty response -> "not configured as an SDA fabric site" error.
        """
        self._synth_side_effect = [
            _Synth.get_sites(),
            # empty fabric_sites list
            {"response": [], "version": "1.0"},
        ]
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(failed=True, changed=False)
        self.assertIn(
            "not configured as an SDA fabric site",
            self._msg_text(result),
        )

    def test_synth_verify_warns_on_missing_destination_assignment(self):
        """
        verify_diff_merged path: after a successful migration, the post-run
        fetch returns an empty destination. Verification logs warnings but
        does NOT flip the result to failed.
        """
        src_pa = [
            _Synth.port_assignment(_Synth.SRC_DEVICE_ID, "GigabitEthernet1/0/1"),
        ]
        # Destination has no PA yet (add path) but the interface must exist
        # physically for the mapping validation to pass.
        prelude = _Synth.prelude(
            src_pa, [], [], [],
            dest_interfaces={"GigabitEthernet1/0/1"},
        )
        self._synth_side_effect = (
            prelude
            + _Synth.task_chain("task-add-then-verify-miss", num_polls=1)
            # Verify epilogue returns EMPTY destination assignments - should
            # trigger the "requested port assignment ... is missing" warning.
            + [
                _Synth.get_port_assignments([]),
                _Synth.get_port_channels([]),
            ]
        )
        cfg = dict(_SYNTH_BASE_CFG, interface_mapping=[
            {"source_interface": "GigabitEthernet1/0/1",
             "destination_interface": "GigabitEthernet1/0/1"},
        ])
        set_module_args(dict(_BASE_ARGS, config=[cfg]))
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Add Port Assignment(s) Task Succeeded",
            str(result.get("msg") or {}),
        )

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _msg_text(result):
        """
        Collapse result['msg'] (sometimes a string, sometimes a dict) into a plain
        string for substring assertions. DnacBase writes the failure reason into
        result['msg'] directly; we also fold in result.get('response') because set_
        operation_result sometimes places detail there.
        """
        parts = []
        msg = result.get("msg")
        if msg is not None:
            parts.append(str(msg))
        resp = result.get("response")
        if resp is not None:
            parts.append(str(resp))
        return " ".join(parts)
