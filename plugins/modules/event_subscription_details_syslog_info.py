#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_subscription_details_syslog_info
short_description: Information module for Event Subscription
  Details Syslog
description:
  - Get all Event Subscription Details Syslog.
  - Gets the list of subscription details for specified
    connectorType.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  name:
    description:
      - Name query parameter. Name of the specific configuration.
    type: str
  instanceId:
    description:
      - InstanceId query parameter. Instance Id of the
        specific configuration.
    type: str
  offset:
    description:
      - >
        Offset query parameter. The number of Syslog
        Subscription detail's to offset in the resultset
        whose default value 0.
    type: float
  limit:
    description:
      - >
        Limit query parameter. The number of Syslog
        Subscription detail's to limit in the resultset
        whose default value 10.
    type: float
  sortBy:
    description:
      - SortBy query parameter. SortBy field name.
    type: str
  order:
    description:
      - Order query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      GetSyslogSubscriptionDetails
    description: Complete reference of the GetSyslogSubscriptionDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-syslog-subscription-details
notes:
  - SDK Method used are
    event_management.EventManagement.get_syslog_subscription_details,
  - Paths used are
    get /dna/intent/api/v1/event/subscription-details/syslog,
"""

EXAMPLES = r"""
---
- name: Get all Event Subscription Details Syslog
  cisco.dnac.event_subscription_details_syslog_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    name: string
    instanceId: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "instanceId": "string",
        "name": "string",
        "description": "string",
        "connectorType": "string",
        "syslogConfig": {
          "configId": "string",
          "name": "string",
          "description": "string",
          "host": "string",
          "port": "string",
          "protocol": "string"
        }
      }
    ]
"""
