#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_dhcp_settings_info
short_description: Information module for Sites Dhcp
  Settings
description:
  - Get all Sites Dhcp Settings. - > Retrieve DHCP settings
    for a site; `null` values indicate that the setting
    will be inherited from the parent site; empty objects
    `{}` indicate that the setting is unset at a site.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Site Id.
    type: str
  _inherited:
    description:
      - >
        _inherited query parameter. Include settings
        explicitly set for this site and settings inherited
        from sites higher in the site hierarchy; when
        `false`, `null` values indicate that the site
        inherits that setting from the parent site or
        a site higher in the site hierarchy.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings RetrieveDHCPSettingsForASite
    description: Complete reference of the RetrieveDHCPSettingsForASite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-dhcp-settings-for-a-site
notes:
  - SDK Method used are
    network_settings.NetworkSettings.retrieve_d_h_c_p_settings_for_a_site,
  - Paths used are
    get /dna/intent/api/v1/sites/{id}/dhcpSettings,
"""

EXAMPLES = r"""
---
- name: Get all Sites Dhcp Settings
  cisco.dnac.sites_dhcp_settings_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    _inherited: true
    id: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "dhcp": {
          "servers": [
            "string"
          ],
          "inheritedSiteId": "string",
          "inheritedSiteName": "string"
        }
      },
      "version": "string"
    }
"""
