#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Abhishek Maheshwari, Madhan Sankaranarayanan")

DOCUMENTATION = r"""
---
module: events_and_notifications_workflow_manager
short_description: Resource module for Network Device
description:
- Manage operations create, update and delete of the resource Network Device.
- Adds the device with given credential.
- Deletes the network device for the given Id.
- Sync the devices provided as input.
version_added: '6.8.0'
extends_documentation_fragment:
  - cisco.dnac.intent_params
author: Abhishek Maheshwari (@abmahesh)
        Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center config after applying the playbook config.
    type: bool
    default: False
  state:
    description: The state of Cisco Catalyst Center after module completion.
    type: str
    choices: [ merged, deleted ]
    default: merged
  config:
    description: List containing the subscription configuration for events, notification on site through one or more channels.
    type: list
    elements: dict
    required: True
    suboptions:
      syslog_destination:
        description: Dictionary containing the details for configuring/updating syslog destination in Cisco Catalyst Center.
        type: dict
        suboptions:
          name:
            description: Name of the syslog destination.
            type: str
          description:
            description: Description of the syslog destination.
            type: str
          host:
            description: Hostname or IP address of the syslog server.
            type: str
          protocol:
            description: Protocol used for sending syslog messages (e.g., UDP, TCP).
                Transmission Control Protocol (TCP) - It is a connection-oriented protocol used for reliable and ordered communication
                    between devices on a network. It provides error-checking, retransmission of lost packets, and ensures that data is
                    delivered in the correct order.
                User Datagram Protocol (UDP) - It is a connectionless protocol used for sending datagrams between devices on a network.
                    It provides a lightweight, best-effort delivery mechanism without guaranteeing delivery or ordering of packets. UDP
                    is commonly used for real-time applications such as streaming media, online gaming, and VoIP.
            type: str
          port:
            description: Port number on which the syslog server is listening. It must be in the range of 1-65536.
            type: int
      snmp_destination:
        description: Dictionary containing the details for configuring/updating SNMP destination in Cisco Catalyst Center.
        type: dict
        suboptions:
          name:
            description: Name of the SNMP destination.
            type: str
          description:
            description: Description of the SNMP destination.
            type: str
          ip_address:
            description: IP address of the SNMP server.
            type: str
          port:
            description: Port number on which the SNMP server is listening.
            type: str
          snmp_version:
            description: SNMP version used for communication (e.g., SNMPv1, SNMPv2c, SNMPv3).
                v2 - In this communication between the SNMP manager (such as Cisco Catalyst) and the managed devices
                    (such as routers, switches, or access points) is based on community strings.Community strings serve
                    as form of authentication and they are transmitted in clear text, providing no encryption.
                v3 - It is the most secure version of SNMP, providing authentication, integrity, and encryption features.
                    It allows for the use of usernames, authentication passwords, and encryption keys, providing stronger
                    security compared to v2.
            type: str
          community:
            description: SNMP community string for authentication (Required only if snmpVersion is V2C).
            type: str
          username:
            description: Username for SNMP authentication (Required only if snmpVersion is V3).
            type: str
          snmp_mode:
            description: AUTH_PRIVACY, AUTH_NO_PRIVACY, NO_AUTH_NO_PRIVACY). If snmpVersion is V3 it is required and cannot be NONE.
                NO_AUTH_NO_PRIVACY - This mode provides no authentication or encryption for SNMP messages. It means that devices communicating using SNMPv1 do
                    not require any authentication (username/password) or encryption (data confidentiality). This makes it the least secure option.
                AUTH_NO_PRIVACY - This mode provides authentication but no encryption for SNMP messages. Authentication involves validating the source of the
                    SNMP messages using a community string (similar to a password). However, the data transmitted between devices is not encrypted,
                    so it's susceptible to eavesdropping.
                AUTH_PRIVACY - This mode provides both authentication and encryption for SNMP messages. It offers the highest level of security among the three
                    options. Authentication ensures that the source of the messages is genuine, and encryption ensures that the data exchanged between
                    devices is confidential and cannot be intercepted by unauthorized parties.
            type: str
          snmp_auth_type:
            description: SNMP authentication type (e.g., MD5, SHA).
                SHA (Secure Hash Algorithm) - It represents a family of cryptographic hash functions designed by the National Security Agency (NSA)
                    to ensure stronger security.
                MD5 (Message Digest Algorithm 5) - is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value.
                    In the context of SNMPv3, it is used to authenticate the integrity and authenticity of the messages.
            type: str
          auth_password:
            description: Password for SNMP authentication.
            type: str
          snmp_privacy_type:
            description: SNMP privacy type (e.g., AES128).
            type: str
          privacy_password:
            description: Privacy password for snmp authentication.
            type: str
      rest_webhook_destination:
        description: Dictionary containing the details for configuring/updating Rest Webhook destination in Cisco Catalyst Center.
        type: dict
        suboptions:
          name:
            description: The name of the webhook destination. It identifies the webhook within the system.
            type: str
          description:
            description: A brief explanation of what the webhook destination is used for.
            type: str
          url:
            description: The URL to which the webhook will send the request. It should be a fully qualified URL(e.g., https://ciscocatalyst.com).
            type: str
          method:
            description: The HTTP method used by the webhook when sending requests (e.g., POST, PUT).
            type: str
          trust_cert:
            description: A boolean indicating whether the SSL/TLS certificate of the URL should be verified. Set to true to bypass certificate verification.
            type: bool
          headers:
            description: A list of HTTP headers to be included in the webhook request. Each header is represented as a dictionary.
            type: list
            elements: dict
            suboptions:
              name:
                description: The name of the HTTP header.
                type: str
              value:
                description: The value assigned to the HTTP header.
                type: str
              default_value:
                description: A default value for the HTTP header that can be used if no specific value is provided.
                type: str
              encrypt:
                description: Indicates whether the value of the header should be encrypted. Useful for sensitive data.
                type: bool
          is_proxy_route:
            description: A boolean that determines whether the request should be routed through a proxy. True if routing through a proxy; otherwise, false."
            type: bool
      email_destination:
        description: List containing the subscription configuration for events, notification on site through one or more channels. Also we can create or
                configure email destination in Cisco Catalyst Center only once then later we can just modify it.
        type: dict
        suboptions:
          primary_smtp_config:
            description: Add the primary configuration for smtp while creating/updating email destination.
            type: dict
            suboptions:
              hostname:
                description: Name of the host used for configuring smtp while creating/updating email destination.
                type: str
              port:
                description: Name of the port used for configuring smtp while creating/updating email destination.
                type: str
              smtp_type:
                description: The type of SMTP server connection. Options include(DEFAULT,TLS, SSL).
                    DEFAULT - This one is selected for basic SMTP connection without encryption.
                    TLS - This one is selected for secure SMTP communication that begins unencrypted and then upgrades to encrypted using TLS if possible.
                    SSL - This one is selected for secure SMTP communication that starts encrypted using SSL."
                type: str
              username:
                description: Name of the username used for configuring smtp while creating/updating email destination.
                type: str
              password:
                description: Password used for configuring smtp while creating/updating email destination.
                type: str
          secondary_smtp_config:
            description: Add the secondary configuration for smtp while creating/updating email destination.
            type: dict
            suboptions:
              hostname:
                description: Name of the host used for configuring smtp while creating/updating email destination.
                type: str
              port:
                description: Name of the port used for configuring smtp while creating/updating email destination.
                type: str
              smtp_type:
                description: The type of SMTP server connection. Options include(DEFAULT,TLS, SSL).
                    DEFAULT - This one is selected for basic SMTP connection without encryption.
                    TLS - This one is selected for secure SMTP communication that begins unencrypted and then upgrades to encrypted using TLS if possible.
                    SSL - This one is selected for secure SMTP communication that starts encrypted using SSL."
                type: str
              username:
                description: Name of the username used for configuring smtp while creating/updating email destination.
                type: str
              password:
                description: Password used for configuring smtp while creating/updating email destination.
                type: str
          from_email:
            description: Email address from which mail to be sent while creating/updating email destination.
            type: str
          to_email:
            description: Email address which receives mail while creating/updating email destination.
            type: str
          subject:
            description: Subject of the email used for sending mail while creating/updating email destination.
            type: str
      itsm_setting:
        description: Dictionary containing the configuration details necessary for integrating with an IT Service Management (ITSM) system.
        type: dict
        suboptions:
          name:
            description: The name of the ITSM configuration. This helps in identifying the integration within the system. Also while deleting
                the ITSM Intergration setting from Cisco Catalyst Center.
            type: str
          description:
            description: A brief description of the ITSM settings, outlining its purpose or usage within the organization.
            type: str
          connection_settings:
            description: A dictionary of settings required to establish a connection with the ITSM system.
            type: dict
            suboptions:
              url:
                description: The URL of the ITSM system API endpoint. This is the base URL used for ITSM service requests.
                type: str
              username:
                description: The username used for authentication with the ITSM system. This is required for accessing the API.
                type: str
              password:
                description: The password associated with the username for API authentication. It is recommended to handle this data securely.
                type: str


requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5

notes:
  - SDK Method used are
    events.Events.get_syslog_destination,
    events.Events.create_syslog_destination,
    events.Events.update_syslog_destination,
    events.Events.get_snmp_destination,
    events.Events.create_snmp_destination,
    events.Events.update_snmp_destination,
    events.Events.get_webhook_destination,
    events.Events.create_webhook_destination,
    events.Events.update_webhook_destination,

"""

EXAMPLES = r"""
- name: Create Syslog destination with given name.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - syslog_destination:
          name: Syslog test
          description: "Adding syslog destination"
          host: "10.30.0.90"
          protocol: "TCP"
          port: 6553

- name: Update Syslog destination with given name.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - syslog_destination:
          name: Syslog test
          description: "Updating syslog destination."

- name: Create SNMP destination with given name.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - snmp_destination:
          name: Snmp test
          description: "Adding snmp destination for testing."
          ip_address: "10.30.0.90"
          port: "25"
          snmp_version: "V3"
          username: cisco
          snmp_mode: AUTH_PRIVACY
          snmp_auth_type: SHA
          auth_password: authpass123
          snmp_privacy_type: AES128
          privacy_password: privacy123

- name: Update SNMP destination with given name.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - snmp_destination:
          name: Snmp test
          description: "Updating snmp destination with snmp version v2."
          ip_address: "10.30.0.90"
          port: "25"
          snmp_version: "V2C"
          community: "public123"

- name: Configuring the email destination in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - email_destination:
          from_email: "test@cisco.com"
          to_email: "demo@cisco.com"
          subject: "Ansible testing"
          primary_smtp_config:
            hostname: "outbound.cisco.com"
            port: "25"
            smtp_type: "DEFAULT"

- name: Updating the email destination in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - email_destination:
          from_email: "test@cisco.com"
          to_email: "demo123@cisco.com"
          subject: "Ansible updated email config testing"

- name: Create Rest Webhook destination with given name.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - rest_webhook_destination:
          name: "webhook test"
          description: "creating webhook for testing"
          url: "https://10.195.227.14/dna"
          method: "GET"
          trust_cert: False

- name: Updating Rest Webhook destination with given name.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - rest_webhook_destination:
          name: "webhook test"
          description: "updating webhook for testing"

- name: Create ITSM Integration Setting with given name in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - itsm_setting:
          name: "ITSM test"
          description: "ITSM description for testing"
          connection_settings:
            url: "http/catalystcenter.com"
            username: "catalyst"
            password: "catalyst@123"

- name: Updating ITSM Integration Setting with given name in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: merged
    config:
      - itsm_setting:
          name: "ITSM test"
          connection_settings:
            url: "http/catalystcenterupdate.com"
            password: "catalyst@123"

- name: Deleting ITSM Integration Setting with given name from the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: False
    state: deleted
    config:
      - itsm_setting:
          name: "ITSM test"

"""

RETURN = r"""

dnac_response:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
import re


class Events(DnacBase):
    """Class containing member attributes for inventory workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
            will contain the validated configuration. If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
        """

        temp_spec = {
            'syslog_destination': {
                'type': 'dict',
                'name': {'type': 'str'},
                'description': {'type': 'str'},
                'host': {'type': 'str'},
                'protocol': {'type': 'str'},
                'port': {'type': 'int'},
            },
            'snmp_destination': {
                'type': 'dict',
                'name': {'type': 'str'},
                'description': {'type': 'str'},
                'ip_address': {'type': 'str'},
                'port': {'type': 'str'},
                'snmp_version': {'type': 'str'},
                'community': {'type': 'str'},
                'username': {'type': 'str'},
                'snmp_mode': {'type': 'str'},
                'snmp_auth_type': {'type': 'str'},
                'auth_password': {'type': 'str'},
                'snmp_privacy_type': {'type': 'str'},
                'privacy_password': {'type': 'str'},
            },
            'email_destination': {
                'type': 'dict',
                'primary_smtp_config': {
                    'type': 'dict',
                    'hostname': {'type': 'str'},
                    'port': {'type': 'str'},
                    'smtp_type': {'type': 'str'},
                    'username': {'type': 'str'},
                    'password': {'type': 'str'},
                },
                'secondary_smtp_config': {
                    'type': 'dict',
                    'hostname': {'type': 'str'},
                    'port': {'type': 'str'},
                    'smtp_type': {'type': 'str'},
                    'username': {'type': 'str'},
                    'password': {'type': 'str'},
                },
                'from_email': {'type': 'str'},
                'to_email': {'type': 'str'},
                'subject': {'type': 'str'},
            },
            'rest_webhook_destination': {
                'type': 'dict',
                'name': {'type': 'str'},
                'description': {'type': 'str'},
                'url': {'type': 'str'},
                'method': {'type': 'str'},
                'trust_cert': {'type': 'bool'},
                'headers': {
                    'type': 'list',
                    'elements': 'dict',
                    'name': {'type': 'str'},
                    'value': {'type': 'str'},
                    'default_value': {'type': 'str'},
                    'encrypt': {'type': 'bool'},
                },
                'is_proxy_route': {'type': 'bool'}
            },
            'itsm_setting': {
                'type': 'dict',
                'name': {'type': 'str'},
                'description': {'type': 'str'},
                'connection_settings': {
                    'type': 'dict',
                    'url': {'type': 'str'},
                    'auth_username': {'type': 'str'},
                    'auth_password': {'type': 'str'},
                },
            },
        }

        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, temp_spec
        )

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(str(valid_temp))
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def get_have(self, config):
        """
        Retrieve and check destinations information present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration details of destinations to be checked.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center having destination details.
                - syslog_destinations (list): A list of syslog destinations existing in Cisco Catalyst Center.
                - snmp_destinations (list): A list of SNMP destinations existing in Cisco Catalyst Center.
                - webhook_destinations (list): A list of webhook destinations existing in Cisco Catalyst Center.
                - email_destination (list): A list of email destinations existing in Cisco Catalyst Center.
                - itsm_setting (list): A list of ITSM settings existing in Cisco Catalyst Center.
        Description:
            This function checks the specified destinations in the playbook against the destinations existing in Cisco Catalyst Center.
            It retrieves information about various types of destinations (syslog, SNMP, webhook, email, ITSM) and returns a dictionary
            with keys representing each type of destination and corresponding lists of existing destinations in Cisco Catalyst Center.
        """

        have = {}

        if config.get('syslog_destination'):
            if self.get_syslog_destination_in_ccc():
                have['syslog_destinations'] = self.get_syslog_destination_in_ccc()

        if config.get('snmp_destination'):
            if self.get_snmp_destination_in_ccc():
                have['snmp_destinations'] = self.get_snmp_destination_in_ccc()

        if config.get('rest_webhook_destination'):
            if self.get_rest_webhook_destination_in_ccc():
                have['webhook_destinations'] = self.get_rest_webhook_destination_in_ccc()

        if config.get('email_destination'):
            if self.get_email_destination_in_ccc():
                have['email_destination'] = self.get_email_destination_in_ccc()

        if config.get('itsm_setting'):
            if self.get_itsm_settings_in_ccc():
                have['itsm_setting'] = self.get_itsm_settings_in_ccc()

        self.have = have
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")

        return self

    def get_want(self, config):
        """
        Retrieve the desired configuration parameters specified in the playbook.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the desired configuration details specified in the playbook.
        Returns:
            self (object): An instance of the class with the desired configuration parameters collected from the playbook.
        Description:
            This function retrieves the desired configuration parameters specified in the playbook and organizes them into a dictionary.
            It collects details related to various types of destinations (syslog, SNMP, webhook, email, ITSM) based on the playbook configuration
            and stores them in the 'want' attribute of the class instance.
        """

        want = {}
        if config.get('syslog_destination'):
            want['syslog_details'] = config.get('syslog_destination')
        if config.get('snmp_destination'):
            want['snmp_details'] = config.get('snmp_destination')
        if config.get('rest_webhook_destination'):
            want['webhook_details'] = config.get('rest_webhook_destination')
        if config.get('email_destination'):
            want['email_details'] = config.get('email_destination')
        if config.get('itsm_setting'):
            want['itsm_details'] = config.get('itsm_setting')

        self.want = want
        self.msg = "Successfully collected all parameters from the playbook "
        self.status = "success"
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_syslog_destination_in_ccc(self):
        """
        Retrieve the details of syslog destinations present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            str: A string containing the details of syslog destinations present in Cisco Catalyst Center.
        Description:
            This function queries Cisco Catalyst Center to retrieve the details of syslog destinations.
            The response contains the status message indicating the syslog destinations present in Cisco Catalyst Center.
            If no syslog destinations are found, it returns an empty string.
            In case of any errors during the API call, an exception is raised with an error message.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_syslog_destination'
            )
            self.log("Received API response from 'get_syslog_destination': {0}".format(str(response)), "DEBUG")
            response = response.get('statusMessage')

            if not response:
                self.log("There is no Syslog destination present in Cisco Catalyst Center", "INFO")
                return response

            return response

        except Exception as e:
            error_message = "Error while getting the details of Syslog destination present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def get_syslog_destination_with_name(self, name):
        """
        Retrieve the details of a syslog destination with a specific name from Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the syslog destination to retrieve details for.
        Returns:
            dict: A dictionary containing the details of the syslog destination with the specified name.
        Description:
            This function queries Cisco Catalyst Center to retrieve the details of a syslog destination with a specific name.
            The response contains the status message indicating the syslog destination details.
            If no syslog destination is found with the specified name, it returns None.
            In case of any errors during the API call, an exception is raised with an error message.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_syslog_destination',
                op_modifies=True,
                params={"name": name}
            )
            self.log("Received API response from 'get_syslog_destination': {0}".format(str(response)), "DEBUG")
            response = response.get('statusMessage')

            if not response:
                self.log("There is no Syslog destination added with the name '{0}' in Cisco Catalyst Center".format(name), "INFO")
                return response
            syslog_details = response[0]

            return syslog_details

        except Exception as e:
            error_message = "Error while getting the details of Syslog destination with the name '{0}' from Cisco Catalyst Center: {1}".format(name, str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def syslog_dest_needs_update(self, syslog_details, syslog_details_in_ccc):
        """
        Check if the syslog destination needs an update based on a comparison between desired and current details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            syslog_details (dict): A dictionary containing the desired syslog destination details.
            syslog_details_in_ccc (dict): A dictionary containing the current syslog destination details in Cisco Catalyst Center.
        Returns:
            bool: A boolean indicating whether an update is needed for the syslog destination.
        Description:
            This function compares the desired syslog destination details with the current details retrieved from Cisco Catalyst Center.
            It iterates through each key-value pair in the desired syslog details and checks if the corresponding value in the current
            details matches or if the desired value is empty. If any discrepancy is found, indicating a difference between desired and
            current details, the function sets the 'update_needed' flag to True, indicating that an update is needed.
            If no discrepancies are found, the function returns False, indicating that no update is needed.
        """

        update_needed = False
        for key, value in syslog_details.items():
            if str(syslog_details_in_ccc[key]) == value or value == "":
                continue
            else:
                update_needed = True

        return update_needed

    def add_syslog_destination(self, syslog_details):
        """
        Add a syslog destination to Cisco Catalyst Center based on the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            syslog_details (dict): A dictionary containing the details of the syslog destination to be added.
        Returns:
            self (object): An instance of the class with the result of the operation.
                - If successful, 'status' is set to 'success', 'result['changed']' is True, and 'msg' contains a success message.
                - If unsuccessful, 'status' is set to 'failed', 'result['changed']' is False, and 'msg' contains an error message.
        Description:
            This function adds a syslog destination to Cisco Catalyst Center using the provided details.
            It validates the input parameters, including the protocol, and constructs the necessary parameters for the API call.
            If the operation is successful, the function sets the appropriate status, logs a success message, and returns the result.
            If the operation fails, the function sets the status to 'failed', logs an error message, and returns the result with
            details of the failure.
        """

        try:
            name = syslog_details.get('name')
            description = syslog_details.get('description')
            host = syslog_details.get('host')
            protocol = syslog_details.get('protocol')
            port = syslog_details.get('port', 514)

            if not protocol:
                self.status = "failed"
                self.msg = "Protocol is needed while configuring the syslog destionation with name '{0}' in Cisco Catalyst Center".format(name)
                self.log(self.msg, "ERROR")
                return self

            protocol = protocol.upper()
            if protocol not in ["TCP", "UDP"]:
                self.status = "failed"
                self.msg = """Invalid protocol name '{0}' for creating/updating syslog destination in Cisco Catalyst Center.
                            Select one of the following protocol 'TCP/UDP'.""".format(protocol)
                self.log(self.msg, "ERROR")
                return self

            add_syslog_params = {
                'name': name,
                'description': description,
                'host': host,
                'protocol': protocol,
                'port': int(port)
            }

            response = self.dnac._exec(
                family="event_management",
                function='create_syslog_destination',
                op_modifies=True,
                params=add_syslog_params
            )
            self.log("Received API response from 'create_syslog_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('apiStatus')

            if status == 'SUCCESS':
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Syslog Destination with name '{0}' added successfully in Cisco Catalyst Center".format(name)
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to Add syslog destination with name '{0}' in Cisco Catalyst Center".format(name)

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while Adding the Syslog destination with the name '{0}' in Cisco Catalyst Center: {1}".format(name, str(e))
            self.log(self.msg, "ERROR")

        return self

    def update_syslog_destination(self, syslog_details, syslog_details_in_ccc):
        """
        Update an existing syslog destination in Cisco Catalyst Center with the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            syslog_details (dict): A dictionary containing the desired syslog destination details to update.
            syslog_details_in_ccc (dict): A dictionary containing the current syslog destination details in Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with the result of the operation.
                - If successful, 'status' is set to 'success', 'result['changed']' is True, and 'msg' contains a success message.
                - If unsuccessful, 'status' is set to 'failed', 'result['changed']' is False, and 'msg' contains an error message.
        Description:
            This function updates an existing syslog destination in Cisco Catalyst Center with the provided details.
            It constructs the parameters required for the API call by merging the desired syslog details with the current details.
            If the operation is successful, the function sets the appropriate status, logs a success message, and returns the result.
            If the operation fails, the function sets the status to 'failed', logs an error message, returns the result with failure details.
        """

        try:
            update_syslog_params = {}
            update_syslog_params['name'] = syslog_details.get('name') or syslog_details_in_ccc.get('name')
            update_syslog_params['description'] = syslog_details.get('description') or syslog_details_in_ccc.get('description')
            update_syslog_params['host'] = syslog_details.get('host') or syslog_details_in_ccc.get('host')
            update_syslog_params['protocol'] = syslog_details.get('protocol') or syslog_details_in_ccc.get('protocol')
            update_syslog_params['port'] = int(syslog_details.get('port') or syslog_details_in_ccc.get('port'))
            update_syslog_params['configId'] = syslog_details_in_ccc.get('configId')
            name = update_syslog_params.get('name')

            response = self.dnac._exec(
                family="event_management",
                function='update_syslog_destination',
                op_modifies=True,
                params=update_syslog_params
            )
            self.log("Received API response from 'update_syslog_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('apiStatus')

            if status == 'SUCCESS':
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Syslog Destination with name '{0}' updated successfully in Cisco Catalyst Center".format(name)
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to update syslog destination with name '{0}' in Cisco Catalyst Center".format(name)

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while Updating the Syslog destination with the name '{0}' in Cisco Catalyst Center: {1}".format(name, str(e))
            self.log(self.msg, "ERROR")

        return self

    def get_snmp_destination_in_ccc(self):
        """
        Retrieve the details of SNMP destinations present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            dict: A dictionary containing the details of SNMP destinations present in Cisco Catalyst Center.
        Description:
            This function queries Cisco Catalyst Center to retrieve the details of SNMP destinations.
            It utilizes the 'event_management' API endpoint with the 'get_snmp_destination' function.
            The response contains information about the SNMP destinations present in Cisco Catalyst Center.
            If no SNMP destinations are found, it returns an empty dictionary.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_snmp_destination'
            )
            self.log("Received API response from 'get_snmp_destination': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("There is no SNMP destination present in Cisco Catalyst Center", "INFO")
                return response

            return response

        except Exception as e:
            error_message = "Error while getting the details of SNMP destination present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def collect_snmp_playbook_params(self, snmp_details):
        """
        Collect the SNMP playbook parameters based on the provided SNMP details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            snmp_details (dict): A dictionary containing the SNMP destination details.
        Returns:
            dict: A dictionary containing the SNMP playbook parameters.
        Description:
            This function constructs the SNMP playbook parameters based on the provided SNMP destination details.
            It extracts relevant information such as name, description etc.
            The constructed playbook parameters are returned for further use in the playbook.
        """

        playbook_params = {
            'name': snmp_details.get('name'),
            'description': snmp_details.get('description'),
            'ipAddress': snmp_details.get('ip_address'),
            'port': snmp_details.get('port'),
            'snmpVersion': snmp_details.get('snmp_version')
        }

        if playbook_params['snmpVersion'] == "V2C":
            playbook_params['community'] = snmp_details.get('community')
        else:
            playbook_params['userName'] = snmp_details.get('username')
            playbook_params['snmpMode'] = snmp_details.get('snmp_mode')
            if playbook_params['snmpMode'] == "AUTH_PRIVACY":
                playbook_params['snmpAuthType'] = snmp_details.get('snmp_auth_type')
                playbook_params['authPassword'] = snmp_details.get('auth_password')
                playbook_params['snmpPrivacyType'] = snmp_details.get('snmp_privacy_type', 'AES128')
                playbook_params['privacyPassword'] = snmp_details.get('privacy_password')
            elif playbook_params['snmpMode'] == "AUTH_NO_PRIVACY":
                playbook_params['snmpAuthType'] = snmp_details.get('snmp_auth_type')
                playbook_params['authPassword'] = snmp_details.get('auth_password')

        return playbook_params

    def check_snmp_required_parameters(self, snmp_params):
        """
        Check if all the required parameters for adding an SNMP destination in Cisco Catalyst Center are present.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            snmp_params (dict): A dictionary containing the SNMP destination parameters.
        Returns:
            self (object): An instance of the class with the result of the parameter check.
                - If all required parameters are present, 'status' is set to 'success', and 'msg' contains a success message.
                - If any required parameter is missing, 'status' is set to 'failed', 'msg' contains an error message,
                and the missing parameters are logged.
        Description:
            This function validates whether all the required parameters for adding an SNMP destination in Cisco Catalyst Center
            are present in the provided SNMP destination parameters. If any required parameter is missing, it logs an error
            message with the missing parameters and sets the status to 'failed'.
            If all required parameters are present, it logs a success message and sets the status to 'success'.
        """

        missing_params_list = []
        required_parameter_list = ["name", "description", "ipAddress", "port", "snmpVersion"]

        if snmp_params['snmpVersion'] == "V2C":
            required_parameter_list.append("community")
        else:
            required_parameter_list.extend(["userName", "snmpMode"])
            if snmp_params['snmpMode'] == "AUTH_PRIVACY":
                required_parameter_list.extend(["snmpAuthType", "authPassword", "privacyPassword"])
            elif snmp_params['snmpMode'] == "AUTH_NO_PRIVACY":
                required_parameter_list.extend(["snmpAuthType", "authPassword"])

        for item in required_parameter_list:
            if snmp_params[item] is None:
                missing_params_list.append(item)

        if not missing_params_list:
            self.status = "success"
            self.msg = "All the required parameters for adding SNMP Destination in Cisco Catalyst Center is present."
            self.log(self.msg, "INFO")
            return self

        self.status = "failed"
        self.msg = "Required parameter '{0}' is missing for adding SNMP Destination in Cisco Catalyst Center".format(str(missing_params_list))
        self.log(self.msg, "ERROR")

        return self

    def add_snmp_destination(self, snmp_params):
        """
        Add the SNMP destination in Cisco Catalyst Center using the provided SNMP parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            snmp_params (dict): A dictionary containing the SNMP destination parameters.

        Returns:
            self (object): An instance of the class with the result of the SNMP destination addition.
                - If the SNMP destination is added successfully, 'status' is set to 'success',
                'changed' is set to True, 'msg' contains a success message, and 'response' contains the API response.
                - If the addition fails, 'status' is set to 'failed', 'msg' contains an error message,
                and 'response' contains the API error response.
        Description:
            This function adds an SNMP destination in Cisco Catalyst Center using the provided SNMP parameters.
            Upon receiving the API response, it checks the status to determine the success or failure of the operation.
            If the addition is successful, it sets the appropriate attributes and logs a success message.
            If the addition fails, it logs the error message from the API response.
        """

        try:
            response = self.dnac._exec(
                family="event_management",
                function='create_snmp_destination',
                op_modifies=True,
                params=snmp_params
            )
            self.log("Received API response from 'create_snmp_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('apiStatus')

            if status == 'SUCCESS':
                self.status = "success"
                self.result['changed'] = True
                self.msg = "SNMP Destination with name '{0}' added successfully in Cisco Catalyst Center".format(snmp_params.get('name'))
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to Add SNMP destination with name '{0}' in Cisco Catalyst Center".format(snmp_params.get('name'))

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

            return self

        except Exception as e:
            error_message = """Error while Adding the SNMP destination with the name '{0}' in Cisco Catalyst Center:
                    {1}""".format(snmp_params.get('name'), str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def snmp_dest_needs_update(self, snmp_params, snmp_dest_detail_in_ccc):
        """
        Determine if an update is needed for the SNMP destination in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            snmp_params (dict): A dictionary containing the updated SNMP destination parameters.
            snmp_dest_detail_in_ccc (dict): A dictionary containing the details of existing SNMP destination in Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with the result of the SNMP destination addition.
        Description:
            This function compares the provided SNMP destination parameters with the existing SNMP destination details
            in Cisco Catalyst Center to determine if an update is needed.
            If any value is different or empty in the updated parameters compared to the existing details,
            it sets 'update_needed' to True, indicating that an update is needed.
            Otherwise, if all values match or are empty, it sets 'update_needed' to False.
        """

        update_needed = False
        for key, value in snmp_params.items():
            if str(snmp_dest_detail_in_ccc[key]) == str(value) or value == "":
                continue
            else:
                update_needed = True

        return update_needed

    def update_snmp_destination(self, snmp_params, snmp_dest_detail_in_ccc):
        """
        Update an existing SNMP destination in Cisco Catalyst Center with the provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            snmp_params (dict): A dictionary containing the updated parameters for the SNMP destination.
            snmp_dest_detail_in_ccc (dict): A dictionary containing the details of the SNMP destination
                                            currently configured in Cisco Catalyst Center.
        Returns:
            self (object): An object representing the status of the operation, including whether it was successful or failed,
                    any error messages encountered during the operation, and whether changes were made to the system.
        Description:
            This function attempts to update an existing SNMP destination in Cisco Catalyst Center with the provided parameters.
            It compares the parameters specified in the playbook (`snmp_params`) with the current configuration of the SNMP destination
            in Cisco Catalyst Center (`snmp_dest_detail_in_ccc`). If any parameter differs between the playbook and the current
            configuration, the function sends a request to update the SNMP destination with the new parameters.
            If the operation is successful, it sets the status to "success" and logs a success message.
            If the operation fails, it sets the status to "failed" and logs an error message along with any error details
            received from the API response.
        """
        try:
            update_snmp_params = {}
            update_snmp_params['name'] = snmp_params.get('name') or snmp_dest_detail_in_ccc.get('name')
            update_snmp_params['description'] = snmp_params.get('description') or snmp_dest_detail_in_ccc.get('description')
            update_snmp_params['ipAddress'] = snmp_params.get('ipAddress') or snmp_dest_detail_in_ccc.get('ipAddress')
            update_snmp_params['port'] = snmp_params.get('port') or snmp_dest_detail_in_ccc.get('port')
            update_snmp_params['snmpVersion'] = snmp_params.get('snmpVersion') or snmp_dest_detail_in_ccc.get('snmpVersion')

            if update_snmp_params.get('port'):
                try:
                    port = int(snmp_params.get('port'))
                    if port not in range(1, 65536):
                        self.status = "failed"
                        self.msg = "Invalid Notification trap port '{0}' given in playbook. Select port from the number range(1, 65536)".format(port)
                        self.log(self.msg, "ERROR")
                        return self
                except Exception as e:
                    self.status = "failed"
                    self.msg = """Invalid datatype for the Notification trap port '{0}' given in playbook. Select port with correct datatype from the
                                number range(1, 65536).""".format(port)
                    self.log(self.msg, "ERROR")
                    return self

            if update_snmp_params['snmpVersion'] == "V2C":
                update_snmp_params['community'] = snmp_params.get('community') or snmp_dest_detail_in_ccc.get('community')
            else:
                update_snmp_params['userName'] = snmp_params.get('userName') or snmp_dest_detail_in_ccc.get('userName')
                update_snmp_params['snmpMode'] = snmp_params.get('snmpMode') or snmp_dest_detail_in_ccc.get('snmpMode')
                if update_snmp_params['snmpMode'] == "AUTH_PRIVACY":
                    update_snmp_params['snmpAuthType'] = snmp_params.get('snmpAuthType') or snmp_dest_detail_in_ccc.get('snmpAuthType')
                    update_snmp_params['authPassword'] = snmp_params.get('authPassword') or snmp_dest_detail_in_ccc.get('authPassword')
                    update_snmp_params['snmpPrivacyType'] = snmp_params.get('snmpPrivacyType', 'AES128')
                    update_snmp_params['privacyPassword'] = snmp_params.get('privacyPassword') or snmp_dest_detail_in_ccc.get('privacyPassword')
                elif update_snmp_params['snmpMode'] == "AUTH_NO_PRIVACY":
                    update_snmp_params['snmpAuthType'] = snmp_params.get('snmpAuthType') or snmp_dest_detail_in_ccc.get('snmpAuthType')
                    update_snmp_params['authPassword'] = snmp_params.get('authPassword') or snmp_dest_detail_in_ccc.get('authPassword')

            update_snmp_params['configId'] = snmp_dest_detail_in_ccc.get('configId')

            response = self.dnac._exec(
                family="event_management",
                function='update_snmp_destination',
                op_modifies=True,
                params=update_snmp_params
            )
            self.log("Received API response from 'update_snmp_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('apiStatus')

            if status == 'SUCCESS':
                self.status = "success"
                self.result['changed'] = True
                self.msg = "SNMP Destination with name '{0}' updated successfully in Cisco Catalyst Center".format(update_snmp_params.get('name'))
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to update SNMP destination with name '{0}' in Cisco Catalyst Center".format(update_snmp_params.get('name'))

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while Updating the SNMP destination with name '{0}' in Cisco Catalyst Center: {1}".format(update_snmp_params.get('name'), str(e))
            self.log(self.msg, "ERROR")

        return self

    def get_rest_webhook_destination_in_ccc(self):
        """
        Retrieve details of Rest Webhook destinations present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            dict: A dictionary containing details of Rest Webhook destinations present in Cisco Catalyst Center,
                or None if no Rest Webhook destinations are found.
        Description:
            This function retrieves the details of Rest Webhook destinations present in Cisco Catalyst Center
            using the 'event_management' API endpoint with the 'get_webhook_destination' function.
            If an error occurs during the retrieval process, it logs the error message and raises an Exception.
        """

        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_webhook_destination'
            )
            self.log("Received API response from 'get_webhook_destination': {0}".format(str(response)), "DEBUG")
            response = response.get('statusMessage')

            if not response:
                self.log("There is no Rest Webhook destination present in Cisco Catalyst Center", "INFO")
                return response

            return response

        except Exception as e:
            error_message = "Error while getting the details of Webhook destination(s) present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def collect_webhook_playbook_params(self, webhook_details):
        """
        Collect parameters for configuring a Rest Webhook destination from the playbook.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_details (dict): A dictionary containing the details of the Rest Webhook destination to be configured.
        Returns:
            dict: A dictionary containing the collected parameters for configuring the Rest Webhook destination.
        Description:
            This function collects parameters for configuring a Rest Webhook destination from the playbook.
        """

        playbook_params = {
            'name': webhook_details.get('name'),
            'description': webhook_details.get('description'),
            'url': webhook_details.get('url'),
            'method': webhook_details.get('method', 'POST').upper(),
            'trustCert': webhook_details.get('trust_cert', False),
            'isProxyRoute': webhook_details.get('is_proxy_route', True)
        }

        if webhook_details.get('headers'):
            headers_list = webhook_details['headers']
            playbook_params['headers'] = []
            for headers in headers_list:
                temp_dict = {
                    'name': headers.get('name'),
                    'value': headers.get('name'),
                    'defaultValue': headers.get('default_value'),
                    'encrypt': headers.get('encrypt')
                }
                playbook_params['headers'].append(temp_dict)

        return playbook_params

    def add_webhook_destination(self, webhook_params):
        """
        Add or configure REST webhook destination in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_params (dict): A dictionary containing the parameters for configuring the REST webhook destination.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                successful or failed, any error messages encountered during operation.
        Description:
            This function attempts to add a REST webhook destination in Cisco Catalyst Center using the provided parameters.
            It sends a request to create a webhook destination with the specified parameters.
            If the operation is successful, it sets the status to "success" and logs a success message.
            If the operation fails, it sets the status to "failed" and logs an error message along with any error details
            received from the API response.
        """

        try:
            response = self.dnac._exec(
                family="event_management",
                function='create_webhook_destination',
                op_modifies=True,
                params=webhook_params
            )
            self.log("Received API response from 'create_webhook_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('apiStatus')

            if status == 'SUCCESS':
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Webhook Destination with name '{0}' added successfully in Cisco Catalyst Center".format(webhook_params.get('name'))
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to Add Webhook destination with name '{0}' in Cisco Catalyst Center".format(webhook_params.get('name'))

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while Adding the Webhook destination with the name '{0}' in Cisco Catalyst Center: {1}".format(webhook_params.get('name'), str(e))
            self.log(self.msg, "ERROR")

        return self

    def webhook_dest_needs_update(self, webhook_params, webhook_dest_detail_in_ccc):
        """
        Check if updates are needed for a webhook destination in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_params (dict): A dictionary containing the updated parameters for the webhook destination.
            webhook_dest_detail_in_ccc (dict): A dictionary containing the details of the webhook destination
                                                currently configured in Cisco Catalyst Center.
        Returns:
            bool: A boolean value indicating whether updates are needed for the webhook destination.
        Description:
            This function compares the parameters specified in the playbook (`webhook_params`) with the current configuration
            of the webhook destination in Cisco Catalyst Center (`webhook_dest_detail_in_ccc`). If any parameter differs between
            the playbook and the current configuration, it returns True, indicating that updates are needed.
            If all parameters match or are None, it returns False, indicating that no updates are needed.
        """

        update_needed = False
        for key, value in webhook_params.items():
            if webhook_dest_detail_in_ccc[key] == value or value is None:
                continue
            else:
                update_needed = True

        return update_needed

    def remove_duplicates(self, headers_in_ccc):
        """
        Remove duplicate headers from a list of header dictionaries.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            headers_in_ccc (list): A list of dictionaries representing headers.
        Returns:
            list: A list of dictionaries with duplicate headers removed.
        Description:
            This function takes a list of header dictionaries (`headers_in_ccc`) as input and removes duplicate headers from it.
            It iterates through each dictionary in the list and converts it to a tuple of its items. This tuple representation
            is used to check if a similar tuple has been seen before. If not, the dictionary is added to the list of unique_dicts.
            Finally, it returns the list of dictionaries with duplicate headers removed.
        """

        seen_set = set()
        unique_dicts = []

        for header_dict in headers_in_ccc:
            # Convert the dictionary to a tuple of its items
            dict_tuple = tuple(sorted(header_dict.items()))

            # Check if the tuple representation of the dictionary has been seen before
            if dict_tuple not in seen_set:
                seen_set.add(dict_tuple)
                unique_dicts.append(header_dict)

        return unique_dicts

    def update_webhook_destination(self, webhook_details, webhook_dest_detail_in_ccc):
        """
        Update a webhook destination in Cisco Catalyst Center with the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_details (dict): A dictionary containing the details of the webhook destination to be updated.
            webhook_dest_detail_in_ccc (dict): A dictionary containing the details of the webhook destination in Cisco Catalyst Center.
        Returns:
             self (object): An instance of a class representing the status of the operation, including whether it was
                successful or failed, any error messages encountered during operation.
        Description:
            This function updates a webhook destination in Cisco Catalyst Center with the provided details.
            It constructs the parameters needed for the update based on the provided and existing details.
            Then, it sends an API request to update the webhook destination with the constructed parameters.
            If the update is successful, it sets the status to "success" and logs the success message.
            If the update fails, it sets the status to "failed" and logs the failure message.
        """

        try:
            update_webhook_params = {}
            update_webhook_params['name'] = webhook_details.get('name') or webhook_dest_detail_in_ccc.get('name')
            update_webhook_params['description'] = webhook_details.get('description') or webhook_dest_detail_in_ccc.get('description')
            update_webhook_params['url'] = webhook_details.get('url') or webhook_dest_detail_in_ccc.get('url')
            update_webhook_params['method'] = webhook_details.get('method') or webhook_dest_detail_in_ccc.get('method')
            update_webhook_params['trust_cert'] = webhook_details.get('trustCert') or webhook_dest_detail_in_ccc.get('trustCert')
            update_webhook_params['is_proxy_route'] = webhook_details.get('isProxyRoute') or webhook_dest_detail_in_ccc.get('isProxyRoute')
            playbook_headers = webhook_details.get('headers')
            headers_in_ccc = webhook_dest_detail_in_ccc.get('headers')

            final_headers_list = []
            if playbook_headers:
                if headers_in_ccc:
                    headers_in_ccc.extend(playbook_headers)
                    final_headers_list = self.remove_duplicates(headers_in_ccc)
                else:
                    final_headers_list.extend(playbook_headers)

            if not final_headers_list:
                final_headers_list = None

            update_webhook_params['headers'] = final_headers_list
            update_webhook_params['webhookId'] = webhook_dest_detail_in_ccc.get('webhookId')

            response = self.dnac._exec(
                family="event_management",
                function='update_webhook_destination',
                op_modifies=True,
                params=update_webhook_params
            )
            self.log("Received API response from 'update_webhook_destination': {0}".format(str(response)), "DEBUG")
            name = update_webhook_params.get('name')
            status = response.get('apiStatus')

            if status == 'SUCCESS':
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Rest Webhook Destination with name '{0}' updated successfully in Cisco Catalyst Center".format(name)
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to update rest webhook destination with name '{0}' in Cisco Catalyst Center".format(name)

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while Updating the Rest Webhook destination with the name '{0}' in Cisco Catalyst Center: {1}".format(name, str(e))
            self.log(self.msg, "ERROR")

        return self

    def get_email_destination_in_ccc(self):
        """
        Retrieve the details of the Email destination present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            dict or None: A dictionary containing the details of the Email destination if it exists,
                        otherwise returns None.
        Description:
            This function retrieves the details of the Email destination present in Cisco Catalyst Center.
            If the Email destination exists, it returns a dictionary containing its details.
            If no Email destination is found, it returns None.
        """

        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_email_destination'
            )
            self.log("Received API response from 'get_email_destination': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("There is no Email destination present in Cisco Catalyst Center", "INFO")
                return response

            return response[0]

        except Exception as e:
            error_message = "Error while getting the details of Email destination present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def collect_email_playbook_params(self, email_details):
        """
        Collects the parameters required for configuring Email destinations from the playbook.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_details (dict): A dictionary containing the Email destination details from the playbook.
        Returns:
            dict: A dictionary containing the collected parameters for configuring Email destinations.
        Description:
            This function collects the parameters required for configuring Email destinations from the playbook.
            It extracts parameters such as 'fromEmail', 'toEmail', 'subject', and SMTP configurations
            (primary and secondary) from the provided email_details dictionary.
        """

        playbook_params = {
            'fromEmail': email_details.get('from_email'),
            'toEmail': email_details.get('to_email'),
            'subject': email_details.get('subject')
        }

        if email_details.get('primary_smtp_config'):
            primary_smtp_details = email_details.get('primary_smtp_config')
            playbook_params['primarySMTPConfig'] = {}
            playbook_params['primarySMTPConfig']['hostName'] = primary_smtp_details.get('hostname')
            playbook_params['primarySMTPConfig']['port'] = primary_smtp_details.get('port', "25")
            playbook_params['primarySMTPConfig']['smtpType'] = primary_smtp_details.get('smtp_type', "DEFAULT")
            playbook_params['primarySMTPConfig']['userName'] = primary_smtp_details.get('username', '')
            playbook_params['primarySMTPConfig']['password'] = primary_smtp_details.get('password', '')

        if email_details.get('seconday_smtp_config'):
            secondary_smtp_details = email_details.get('secondary_smtp_config')
            playbook_params['secondarySMTPConfig'] = {}
            playbook_params['secondarySMTPConfig']['hostName'] = secondary_smtp_details.get('hostname')
            playbook_params['secondarySMTPConfig']['port'] = secondary_smtp_details.get('port')
            playbook_params['secondarySMTPConfig']['smtpType'] = secondary_smtp_details.get('smtp_type', "DEFAULT")
            playbook_params['secondarySMTPConfig']['userName'] = secondary_smtp_details.get('username', '')
            playbook_params['secondarySMTPConfig']['password'] = secondary_smtp_details.get('password', '')

        return playbook_params

    def add_email_destination(self, email_params):
        """
        Adds an Email destination in Cisco Catalyst Center using the provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_params (dict): A dictionary containing the parameters required for adding an Email destination.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                successful or failed, any error messages encountered during operation.
        Description:
            This function adds an Email destination in Cisco Catalyst Center using the provided parameters.
            After the API call, it checks the status of the execution using the 'get_status_api_for_events' API.
            If the status indicates success, it sets the status of the operation as 'success' and logs an informational message.
            If the status indicates failure, it sets the status of the operation as 'failed' and logs an error message.

        """

        try:
            response = self.dnac._exec(
                family="event_management",
                function='create_email_destination',
                op_modifies=True,
                params=email_params
            )
            self.log("Received API response from 'create_email_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]

            # Now we check the status of API Events for configuring Email destination
            status_response = self.dnac._exec(
                family="event_management",
                function='get_status_api_for_events',
                op_modifies=True,
                params={"execution_id": status_execution_id}
            )
            self.log("Received API response from 'get_status_api_for_events': {0}".format(str(status_response)), "DEBUG")

            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Email Destination added successfully in Cisco Catalyst Center"
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to Add Email destination in Cisco Catalyst Center"

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while Adding the Email destination in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")

        return self

    def email_dest_needs_update(self, email_params, email_dest_detail_in_ccc):
        """
        Checks if an update is needed for an Email destination based on the provided parameters and details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_params (dict): A dictionary containing the parameters for the Email destination to be updated.
            email_dest_detail_in_ccc (dict): A dictionary containing the current details of Email destination in Cisco Catalyst Center.
        Returns:
            bool: A boolean value indicating whether an update is needed for the Email destination.
        Description:
            This function compares the parameters of the Email destination specified in email_params
            with the current details of the Email destination in Cisco Catalyst Center specified in email_dest_detail_in_ccc.
            If any parameter value in email_params differs from the corresponding value in email_dest_detail_in_ccc,
            it indicates that an update is needed and returns True else it returns False indicating that no update is needed.
        """

        update_needed = False

        for key, value in email_params.items():
            if isinstance(value, dict):
                self.email_dest_needs_update(value, email_dest_detail_in_ccc[key])
            elif email_dest_detail_in_ccc[key] == value or value == "":
                continue
            else:
                update_needed = True

        return update_needed

    def update_email_destination(self, email_details, email_dest_detail_in_ccc):
        """
        Updates an Email destination based on the provided parameters and current details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_details (dict): A dictionary containing the updated parameters for the Email destination.
            email_dest_detail_in_ccc (dict): A dictionary containing the current details of the Email
                destination in Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class representing the result of the update operation.
        Description:
            This function updates the Email destination in Cisco Catalyst Center based on the provided email_details
            and the current details of the Email destination specified in email_dest_detail_in_ccc.
            It constructs the update_email_params dictionary with the updated parameters.
            If the update is successful, it sets the status to 'success' and logs a success message.
            If the update fails, it sets the status to 'failed' and logs an error message.
            Finally, it returns the result object containing the status and response message.
        """

        try:
            update_email_params = {}
            update_email_params['primarySMTPConfig'] = email_details.get('primarySMTPConfig') or email_dest_detail_in_ccc.get('primarySMTPConfig')
            update_email_params['secondarySMTPConfig'] = email_details.get('secondarySMTPConfig') or email_dest_detail_in_ccc.get('secondarySMTPConfig', 'None')
            update_email_params['fromEmail'] = email_details.get('fromEmail') or email_dest_detail_in_ccc.get('fromEmail')
            update_email_params['toEmail'] = email_details.get('toEmail') or email_dest_detail_in_ccc.get('toEmail')
            update_email_params['subject'] = email_details.get('subject') or email_dest_detail_in_ccc.get('subject')
            update_email_params['emailConfigId'] = email_dest_detail_in_ccc.get('emailConfigId')

            response = self.dnac._exec(
                family="event_management",
                function='update_email_destination',
                op_modifies=True,
                params=update_email_params
            )
            self.log("Received API response from 'update_email_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]

            # Now we check the status of API Events for configuring Email destination
            status_response = self.dnac._exec(
                family="event_management",
                function='get_status_api_for_events',
                op_modifies=True,
                params={"execution_id": status_execution_id}
            )
            self.log("Received API response from 'get_status_api_for_events': {0}".format(str(status_response)), "DEBUG")

            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Email Destination updated successfully in Cisco Catalyst Center"
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to update Email destination in Cisco Catalyst Center"

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while Updating the Email destination in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")

        return self

    def get_itsm_settings_in_ccc(self):
        """
        Retrieves the ITSM Integration Settings present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            dict: A dictionary containing the list of details of ITSM Integration Settings.
        Description:
            This function retrieves the ITSM Integration Settings present in Cisco Catalyst Center
            by executing the 'get_all_itsm_integration_settings' API call.
            It logs the API response and extracts the data.
            If there are no ITSM Integration Settings, it logs an INFO message.
            If an error occurs during the process, it logs an ERROR message and raises an Exception.
        """

        try:
            response = self.dnac._exec(
                family="itsm_integration",
                function='get_all_itsm_integration_settings'
            )
            self.log("Received API response from 'get_all_itsm_integration_settings': {0}".format(str(response)), "DEBUG")
            response = response.get('data')
            if not response:
                self.log("There is no ISTM Integration settings present in Cisco Catalyst Center", "INFO")

            return response

        except Exception as e:
            error_message = "Error while getting the details of ITSM Integration Settings present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def get_itsm_settings_by_id(self, itsm_id):
        """
        Retrieves the ITSM Integration Settings with the specified ID from Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            itsm_id (str): The ID of the ITSM Integration Setting to retrieve.
        Returns:
            dict: A dictionary containing the ITSM Integration Setting information for the given itsm id.
        Description:
            This function retrieves the ITSM Integration Setting with the specified ID from Cisco Catalyst Center.
            It logs the API response and returns the data if it exists.
            If there is no ITSM Integration Setting with the given ID, it logs an INFO message.
            If an error occurs during the process, it logs an ERROR message and raises an Exception.
        """

        try:
            response = self.dnac._exec(
                family="itsm_integration",
                function='get_itsm_integration_setting_by_id',
                op_modifies=True,
                params={"instance_id": itsm_id}
            )
            self.log("Received API response from 'get_itsm_integration_setting_by_id': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("There is no ISTM Integration settings with given ID present in Cisco Catalyst Center", "INFO")

            return response

        except Exception as e:
            error_message = "Error while getting the details of ITSM Integration Setting by id present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def collect_itsm_playbook_params(self, itsm_details):
        """
        Constructs the ITSM playbook parameters from the provided ITSM details.
        Args:
            self (object): An instance of a class used for ITSM playbook operations.
            itsm_details (dict): A dictionary containing details about an ITSM integration.
        Returns:
            dict: A dictionary structured as required by the ITSM playbook for interaction.
        Description:
            This function takes a dictionary containing ITSM integration details, and constructs
            a set of parameters formatted to meet the requirements of an ITSM playbook. These parameters can then be used to
            configure ITSM connections through playbook executions.
        """

        playbook_params = {
            'name': itsm_details.get('name'),
            'description': itsm_details.get('description'),
            'dypName': 'ServiceNowConnection'
        }
        playbook_params['data'] = {}

        if itsm_details.get('connection_settings'):
            connection_details = itsm_details.get('connection_settings')
            playbook_params['data']['ConnectionSettings'] = {}
            playbook_params['data']['ConnectionSettings']['Url'] = connection_details.get('url')
            playbook_params['data']['ConnectionSettings']['Auth_UserName'] = connection_details.get('auth_username')
            playbook_params['data']['ConnectionSettings']['Auth_Password'] = connection_details.get('auth_password')

        return playbook_params

    def check_required_itsm_param(self, itsm_params, invalid_itsm_params):
        """
        Recursively checks for required ITSM parameters and collects any that are missing.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            itsm_params (dict): A dictionary of ITSM parameters that need validation.
            invalid_itsm_params (list): A list to accumulate the keys of missing parameters.
        Returns:
            list: A list containing the keys of parameters that are found to be missing or None.
        Description:
            This method iteratively and recursively examines a dictionary of ITSM parameters
            to ensure that all necessary parameters except 'description' are present and not None.
            If a parameter is found to be missing or explicitly set to None, its key is added to the
            'invalid_itsm_params' list. This function is particularly useful for validating nested
            parameter structures commonly found in configurations for ITSM systems.
        """

        for key, value in itsm_params.items():
            if isinstance(value, dict):
                self.check_required_itsm_param(value, invalid_itsm_params)
            elif key == "description":
                continue
            elif itsm_params.get(key) is None:
                invalid_itsm_params.append(key)

        return invalid_itsm_params

    def create_itsm_integration_setting(self, itsm_params):
        """
        Creates a new ITSM integration setting in the Cisco Catalyst Center using provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            itsm_params (dict): A dictionary containing the parameters necessary to create an ITSM integration setting.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                successful or failed, any error messages encountered during operation.
        Description:
            This method sends a request to the Cisco Catalyst Center to create an ITSM integration setting based on the
            parameters provided in 'itsm_params'.
            It then makes an API call and logs the response. If the creation is successful, indicated by the presence
            of a 'createdDate' in the response, it logs a success message, sets the internal state to 'success', and
            marks the operation as having changed the system state. If the creation fails, it attempts to log any errors
            returned by the API or logs a generic failure message if no specific error is provided.
        """

        try:
            instance_name = itsm_params.get('name')
            response = self.dnac._exec(
                family="itsm_integration",
                function='create_itsm_integration_setting',
                op_modifies=True,
                params=itsm_params
            )
            self.log("Received API response from 'create_itsm_integration_setting': {0}".format(str(response)), "DEBUG")
            created_date = response.get('createdDate')

            if created_date:
                self.status = "success"
                self.result['changed'] = True
                self.msg = "ITSM Integration Settings with name '{0}' has been created successfully in Cisco Catalyst Center".format(instance_name)
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errors')
            except Exception as e:
                failure_msg = "Unable to create ITSM Integration Settings with name '{0}' in Cisco Catalyst Center".format(instance_name)

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while creating the ITSM Integration Settings with name '{0}' in Cisco Catalyst Center: {1}".format(instance_name, str(e))
            self.log(self.msg, "ERROR")

        return self

    def itsm_needs_update(self, itsm_params, itsm_in_ccc):
        """
        Checks if the ITSM settings in Cisco Catalyst Center need to be updated based on provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            itsm_params (dict): A dictionary containing the new ITSM settings parameters.
            itsm_in_ccc (dict): A dictionary containing the existing ITSM settings in the Cisco Catalyst Center.
        Returns:
            bool: True if an update is required based on the differences between the provided parameters and the existing settings, False otherwise.
        Description:
            This method compares provided ITSM integration parameters against the current settings stored in the Cisco Catalyst Center
            to determine if an update is necessary.
            If any of the checked fields or connection settings differ between the provided parameters and the existing settings, the method
            will return True indicating an update is required. Otherwise, it returns False.
        """

        itsm_require_update = False
        required_params = ["name", "description"]
        for key in required_params:
            if key == "description" and itsm_params[key]:
                if itsm_params[key] != itsm_in_ccc[key]:
                    itsm_require_update = True
                    return itsm_require_update
            elif itsm_params[key] != itsm_in_ccc[key]:
                itsm_require_update = True
                return itsm_require_update

        if itsm_params.get('data') is None or itsm_params.get('data').get('ConnectionSettings') is None:
            self.log("ITSM Connection settings parameters are not given in the input playbook so no update required.", "INFO")
            return itsm_require_update

        url = itsm_params.get('data').get('ConnectionSettings').get('Url')
        username = itsm_params.get('data').get('ConnectionSettings').get('Auth_UserName')

        if url and url != itsm_in_ccc.get('data').get('ConnectionSettings').get('Url'):
            itsm_require_update = True
        if username and username != itsm_in_ccc.get('data').get('ConnectionSettings').get('Auth_UserName'):
            itsm_require_update = True

        return itsm_require_update

    def update_itsm_integration_setting(self, itsm_params, itsm_in_ccc):
        """
        Updates the ITSM integration settings in the Cisco Catalyst Center based on the provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            itsm_params (dict): A dictionary containing the new ITSM settings parameters.
            itsm_in_ccc (dict): A dictionary containing the existing ITSM settings in the Cisco Catalyst Center.
        Returns:
            self (object): The instance itself with updated status and message properties reflecting the result of the operation.
        Description:
            This method updates existing ITSM integration settings in the Cisco Catalyst Center using the provided new parameters.
            The method performs several checks:
            - It verifies that the 'Auth_Password' is provided when updating the connection settings. If not, it sets the status
            to 'failed' and logs an informational message.
            - It validates that the provided URL starts with 'https://'. If the URL is invalid, it sets the status to 'failed' and
            logs an informational message.
            Upon successful update, the method logs the success and returns the instance with a 'success' status. If the update
            fails for any reason (such as an invalid URL or API errors), it logs the failure and returns the instance with a 'failed'
            status.
        """

        try:
            update_itsm_params = {}
            update_itsm_params['name'] = itsm_params.get('name') or itsm_in_ccc.get('name')
            update_itsm_params['description'] = itsm_params.get('description') or itsm_in_ccc.get('description')
            update_itsm_params['dypName'] = 'ServiceNowConnection'

            update_itsm_params['data'] = {}
            update_itsm_params['data']['ConnectionSettings'] = {}
            if itsm_params.get('data') is None or itsm_params.get('data').get('ConnectionSettings') is None:
                update_itsm_params['data']['ConnectionSettings']['Url'] = itsm_in_ccc.get('data').get('ConnectionSettings').get('Url')
                update_itsm_params['data']['ConnectionSettings']['Auth_UserName'] = itsm_in_ccc.get('data').get('ConnectionSettings').get('Auth_UserName')
            else:
                connection_params = itsm_params.get('data').get('ConnectionSettings')
                update_itsm_params['data']['ConnectionSettings']['Url'] = connection_params.get('Url')
                update_itsm_params['data']['ConnectionSettings']['Auth_UserName'] = connection_params.get('Auth_UserName')

                if not connection_params.get('Auth_Password'):
                    self.status = "failed"
                    self.msg = """Unable to update ITSM setting '{0}' as 'Auth Password' is the required parameter for updating
                            ITSM Intergartion setting.""".format(update_itsm_params.get('name'))
                    self.log(self.msg, "INFO")
                    return self

                update_itsm_params['data']['ConnectionSettings']['Auth_Password'] = connection_params.get('Auth_Password')

            # Check whether the given url is valid or not
            url = update_itsm_params.get('data').get('ConnectionSettings').get('Url')
            regex_pattern = r'https://\S+'

            if not re.match(regex_pattern, url):
                self.status = "failed"
                self.msg = "Given url '{0}' is invalid url for ITSM Intergartion setting.It must starts with 'https://'".format(url)
                self.log(self.msg, "INFO")
                return self

            itsm_param_dict = {
                'payload': update_itsm_params,
                'instance_id': itsm_in_ccc.get('id')
            }

            response = self.dnac._exec(
                family="itsm_integration",
                function='update_itsm_integration_setting',
                op_modifies=True,
                params=itsm_param_dict,
            )
            self.log("Received API response from 'update_itsm_integration_setting': {0}".format(str(response)), "DEBUG")

            updated_date = response.get('updatedDate')

            if updated_date:
                self.status = "success"
                self.result['changed'] = True
                self.msg = """ITSM Integration Settings with name '{0}' has been updated successfully in Cisco Catalyst
                        Center.""".format(update_itsm_params.get('name'))
                self.log(self.msg, "INFO")
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            try:
                failure_msg = response.get('errors')
            except Exception as e:
                failure_msg = "Unable to update ITSM Integration Settings with name '{0}' in Cisco Catalyst Center".format(update_itsm_params.get('name'))

            self.log(failure_msg, "ERROR")
            self.result['response'] = failure_msg

        except Exception as e:
            self.status = "failed"
            self.msg = """Error while Updating the ITSM Integration Settings with name '{0}' in Cisco Catalyst Center due to:
                    {1}""".format(update_itsm_params.get('name'), str(e))
            self.log(self.msg, "ERROR")

        return self

    def delete_itsm_integration_setting(self, itsm_name, itsm_id):
        """
        Deletes a specified ITSM integration setting from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            itsm_name (str): The name of the ITSM integration setting to be deleted.
            itsm_id (str): The unique identifier of the ITSM integration setting to be deleted.
        Returns:
            self (object): The instance itself with updated status and message properties reflecting the result of the operation.
        Description:
            This method attempts to delete an ITSM integration setting based on the provided name and ID.
            If the deletion is not successful, the method logs an error message and sets the 'status' attribute to 'failed'.
            This could occur if the ITSM integration setting does not exist or due to a failure in the API call.
            Exceptions caught during the API call are handled by logging an error message detailing the issue and setting the 'status'
            attribute to 'failed'.
        """

        try:
            response = self.dnac._exec(
                family="itsm_integration",
                function='delete_itsm_integration_setting',
                op_modifies=True,
                params={"instance_id": itsm_id}
            )
            self.log("Received API response from 'delete_itsm_integration_setting': {0}".format(str(response)), "DEBUG")

            if "successfully" in response:
                self.msg = "ISTM Integration settings instance with name '{0}' deleted successfully from Cisco Catalyst Center".format(itsm_name)
                self.status = "success"
                self.log(self.msg, "INFO")
                self.result['changed'] = True
                self.result['response'] = self.msg
                return self

            self.status = "failed"
            self.msg = "Cannot delete ISTM Integration settings instance with name '{0}' from Cisco Catalyst Center".format(itsm_name)
            self.log(self.msg, "ERROR")

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while deleting ITSM Integration Setting with name '{0}' from Cisco Catalyst Center due to: {1}".format(itsm_name, str(e))
            self.log(self.msg, "ERROR")

        return self

    def get_diff_merged(self, config):
        """
        Processes the configuration difference and merges them into Cisco Catalyst Center.
        This method updates Cisco Catalyst Center configurations based on the differences detected
        between the desired state (`want`) and the current state (`have`). It handles different
        types of configurations such as syslog, SNMP, REST webhook, email, and ITSM settings.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing various destination settings that may include
                        syslog destination, SNMP destination, REST webhook destination,
                        email destination, and ITSM settings. Each key should point to a dictionary
                        that defines specific configuration for that setting type.
        Return:
            self (object): Returns the instance itself after potentially modifying internal state to reflect
                the status of operation, messages to log, and response details.
        Description:
            This method acts as a controller that delegates specific tasks such as adding or updating
            configurations for syslog, SNMP, REST webhook, email, and ITSM settings in the Cisco Catalyst
            Center. It ensures required parameters are present, validates them, and calls the appropriate
            methods to add or update the configurations. Error handling is included to manage any exceptions
            or invalid configurations, updating the internal state to reflect these errors.
        """

        # Create/Update Syslog destination in Cisco Catalyst Center
        if config.get('syslog_destination'):
            syslog_details = self.want.get('syslog_details')
            name = syslog_details.get('name')
            port = syslog_details.get('port')

            if not name:
                self.status = "failed"
                self.msg = "Name is required parameter for adding/updating syslog destination for creating/updating the event."
                self.log(self.msg, "ERROR")
                return self

            if not port.isdigit() or (isinstance(port, int) and port not in range(1, 65536)):
                self.status = "failed"
                self.msg = "Invalid Syslog destination port '{0}' given in playbook. Select port from the number range(1, 65536)".format(port)
                self.log(self.msg, "ERROR")
                return self

            syslog_details_in_ccc = self.get_syslog_destination_with_name(name)

            if not syslog_details_in_ccc:
                # We need to Add the Syslog Destination in the Catalyst Center
                self.add_syslog_destination(syslog_details).check_return_status()
            else:
                # Check destination needs update and if yes then update Syslog Destination
                syslog_need_update = self.syslog_dest_needs_update(syslog_details, syslog_details_in_ccc)
                if not syslog_need_update:
                    self.msg = "Syslog Destination with name '{0}' needs no update in Cisco Catalyst Center".format(name)
                    self.log(self.msg, "INFO")
                    self.result['changed'] = False
                    self.result['response'] = self.msg
                else:
                    # Update the syslog destination with given
                    self.update_syslog_destination(syslog_details, syslog_details_in_ccc).check_return_status()

        # Create/Update snmp destination in Cisco Catalyst Center
        if config.get('snmp_destination'):
            snmp_details = self.want.get('snmp_details')
            destination_name = snmp_details.get('name')
            if not destination_name:
                self.status = "failed"
                self.msg = "Name is required parameter for adding/updating SNMP destination for creating/updating the event."
                self.log(self.msg, "ERROR")
                return self

            is_destination_exist = False
            for snmp_dict in self.have.get('snmp_destinations'):
                if snmp_dict['name'] == destination_name:
                    snmp_dest_detail_in_ccc = snmp_dict
                    is_destination_exist = True
                    break

            snmp_params = self.collect_snmp_playbook_params(snmp_details)
            if snmp_params.get('port'):
                try:
                    port = int(snmp_params.get('port'))
                    if port not in range(1, 65536):
                        self.status = "failed"
                        self.msg = "Invalid Notification trap port '{0}' given in playbook. Select port from the number range(1, 65536)".format(port)
                        self.log(self.msg, "ERROR")
                        return self
                except Exception as e:
                    self.status = "failed"
                    self.msg = "Invalid Notification trap port '{0}' given in playbook. Select port from the number range(1, 65536)".format(port)
                    self.log(self.msg, "ERROR")
                    return self

            if not is_destination_exist:
                # Need to Add snmp destination in Cisco Catalyst Center with given playbook params
                self.check_snmp_required_parameters(snmp_params).check_return_status()
                self.log("""Required parameter validated successfully for adding SNMP Destination with name '{0}' in Cisco
                            Catalyst Center.""".format(destination_name), "INFO")
                self.add_snmp_destination(snmp_params).check_return_status()
            else:
                # Check destination needs update and if yes then update SNMP Destination
                snmp_need_update = self.snmp_dest_needs_update(snmp_params, snmp_dest_detail_in_ccc)
                if not snmp_need_update:
                    self.msg = "SNMP Destination with name '{0}' needs no update in Cisco Catalyst Center".format(destination_name)
                    self.log(self.msg, "INFO")
                    self.result['changed'] = False
                    self.result['response'] = self.msg
                else:
                    # Update the email destination with given details in the playbook
                    self.update_snmp_destination(snmp_params, snmp_dest_detail_in_ccc).check_return_status()

        # Create/Update Rest Webhook destination in Cisco Catalyst Center
        if config.get('rest_webhook_destination'):
            webhook_details = self.want.get('webhook_details')
            destination_name = webhook_details.get('name')

            if not destination_name:
                self.status = "failed"
                self.msg = "Name is required parameter for adding/updating Webhook destination for creating/updating the event."
                self.log(self.msg, "ERROR")
                return self

            is_destination_exist = False
            for webhook_dict in self.have.get('webhook_destinations'):
                if webhook_dict['name'] == destination_name:
                    webhook_dest_detail_in_ccc = webhook_dict
                    is_destination_exist = True
                    break
            webhook_params = self.collect_webhook_playbook_params(webhook_details)

            if webhook_params.get('method') not in ["POST", "PUT"]:
                self.status = "failed"
                self.msg = """Invalid Webhook method name '{0}' for creating/updating Webhook destination in Cisco Catalyst Center.
                            Select one of the following method 'POST/PUT'.""".format(webhook_params.get('method'))
                self.log(self.msg, "ERROR")
                return self

            if not is_destination_exist:
                # Need to Add snmp destination in Cisco Catalyst Center with given playbook params
                if not webhook_params['url']:
                    self.status = "failed"
                    self.msg = "Url is required parameter for creating Webhook destination for creating/updating the event in Cisco Catalyst Center."
                    self.log(self.msg, "ERROR")
                    return self

                self.add_webhook_destination(webhook_params).check_return_status()
            else:
                # Check destination needs update and if yes then update SNMP Destination
                webhook_need_update = self.webhook_dest_needs_update(webhook_params, webhook_dest_detail_in_ccc)

                if not webhook_need_update:
                    self.msg = "Webhook Destination with name '{0}' needs no update in Cisco Catalyst Center".format(destination_name)
                    self.log(self.msg, "INFO")
                    self.result['changed'] = False
                    self.result['response'] = self.msg
                else:
                    # Update the syslog destination with given
                    self.update_webhook_destination(webhook_details, webhook_dest_detail_in_ccc).check_return_status()

        # Create/Update Email destination in Cisco Catalyst Center
        if config.get('email_destination'):
            email_details = self.want.get('email_details')
            email_params = self.collect_email_playbook_params(email_details)

            if not self.have.get('email_destination'):
                # Need to Add snmp destination in Cisco Catalyst Center with given playbook params
                required_params = ['fromEmail', 'toEmail', 'subject']
                invalid_email_params = []
                for item in required_params:
                    if not email_params[item]:
                        invalid_email_params.append(item)
                if not email_params.get('primarySMTPConfig').get('hostName'):
                    invalid_email_params.append('hostName')

                if invalid_email_params:
                    self.status = "failed"
                    self.msg = """Required parameter '{0}' for configuring Email Destination in Cisco Catalyst Center
                            is missing.""".format(str(invalid_email_params))
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self
                self.log("Required parameter validated successfully for adding Email Destination in Cisco Catalyst Center.", "INFO")
                self.add_email_destination(email_params).check_return_status()
            else:
                # Check destination needs update and if yes then update Email Destination
                email_dest_detail_in_ccc = self.have.get('email_destination')
                email_need_update = self.email_dest_needs_update(email_params, email_dest_detail_in_ccc)

                if not email_need_update:
                    self.msg = "Email Destination needs no update in Cisco Catalyst Center"
                    self.log(self.msg, "INFO")
                    self.result['changed'] = False
                    self.result['response'] = self.msg
                else:
                    # Update the email destination with given details in the playbook
                    self.update_email_destination(email_params, email_dest_detail_in_ccc).check_return_status()

        # Create/Update ITSM Integration Settings in Cisco Catalyst Center
        if config.get('itsm_setting'):
            itsm_details = self.want.get('itsm_details')
            itsm_name = itsm_details.get('name')
            if not itsm_name:
                self.status = "failed"
                self.msg = "Instance name is required parameter for adding/updating ITSM integration setting in Cisco Catalyst Center."
                self.log(self.msg, "ERROR")
                return self

            itsm_params = self.collect_itsm_playbook_params(itsm_details)

            is_itsm_exist = False
            itsm_detail_in_ccc = self.have.get('itsm_setting')
            if not itsm_detail_in_ccc:
                self.log("There is no ITSM Intergartion setting present in Cisco Catalyst Center", "INFO")
            else:
                # Check whether the given itsm integration present in Cisco Catalyst Center or not.
                for itsm in itsm_detail_in_ccc:
                    if itsm['name'] == itsm_name:
                        itsm_id = itsm['id']
                        is_itsm_exist = True
                        break

            if not is_itsm_exist:
                # Need to Add snmp destination in Cisco Catalyst Center with given playbook params
                invalid_itsm_params = []
                invalid_itsm_params = self.check_required_itsm_param(itsm_params, invalid_itsm_params)

                # Check whether the url is valid or not
                url = itsm_params.get('data').get('ConnectionSettings').get('Url')
                regex_pattern = r'https://\S+'

                if not re.match(regex_pattern, url):
                    self.status = "failed"
                    self.msg = "Given url '{0}' is invalid url for ITSM Intergartion setting.It must starts with 'https://'".format(url)
                    self.log(self.msg, "INFO")
                    return self

                if invalid_itsm_params:
                    self.status = "failed"
                    self.msg = """Required parameter '{0}' for configuring ITSM Intergartion setting in Cisco Catalyst
                            Center is missing.""".format(str(invalid_itsm_params))
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self

                self.log("Required parameter validated successfully for configuring ITSM Intergartion setting in Cisco Catalyst Center.", "INFO")
                self.create_itsm_integration_setting(itsm_params).check_return_status()
            else:
                itsm_in_ccc = self.get_itsm_settings_by_id(itsm_id)
                if not itsm_in_ccc:
                    self.status = "failed"
                    self.msg = "Unable to update as there is no ITSM Integration setting with name '{0}' present in Cisco Catalyst Center".format(itsm_name)
                    self.log(self.msg, "ERROR")
                    return self

                # Check destination needs update and if yes then update Email Destination
                itsm_need_update = self.itsm_needs_update(itsm_params, itsm_in_ccc)

                if not itsm_need_update:
                    self.msg = "ITSM Intergartion setting with name '{0}' needs no update in Cisco Catalyst Center".format(itsm_name)
                    self.log(self.msg, "INFO")
                    self.result['changed'] = False
                    self.result['response'] = self.msg
                else:
                    # Update the email destination with given details in the playbook
                    self.update_itsm_integration_setting(itsm_params, itsm_in_ccc).check_return_status()

        return self

    def get_diff_deleted(self, config):
        """
        Handles the deletion of ITSM integration settings in Cisco Catalyst Center based on the configuration provided.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the 'itsm_setting' key with details about the ITSM integration to be deleted.
        Returns:
            self (object): The instance of the class with updated status, results, and message based on the deletion operation.
        Description:
            This function is responsible for deleting an ITSM setting from Cisco Catalyst Center if it exists.
            It checks whether the specified ITSM setting exists in the current Catalyst Center configuration. If it exists,
            the function proceeds to delete it. If it does not exist or is already deleted, the function updates the instance
            status and results to reflect that no change was needed.
        """

        if config.get('itsm_setting'):
            itsm_details = self.want.get('itsm_details')
            itsm_name = itsm_details.get('name')
            itsm_detail_in_ccc = self.have.get('itsm_setting')
            if not itsm_detail_in_ccc:
                self.status = "success"
                self.result['changed'] = False
                self.msg = """There is no ITSM Intergartion setting present in Cisco Catalyst Center so cannot delete
                            the ITSM Integartion setting with name '{0}'""".format(itsm_name)
                self.log(self.name, "INFO")
                return self

            # Check whether the given itsm integration present in Catalyst Center or not
            itsm_exist = False
            for itsm in itsm_detail_in_ccc:
                if itsm['name'] == itsm_name:
                    itsm_id = itsm.get('id')
                    itsm_exist = True
                    break
            if itsm_exist:
                self.delete_itsm_integration_setting(itsm_name, itsm_id).check_return_status()
            else:
                self.msg = "Unable to delete ITSM Integartion setting with name '{0}' as it is not present in Cisco Catalyst Center".format(itsm_name)
                self.log(self.msg, "INFO")
                self.result['changed'] = False
                self.result['response'] = self.msg

        return self

    def verify_diff_merged(self, config):
        """
        Verify the addition/update status of configurations in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies whether the specified configurations have been successfully added/updated
            in Cisco Catalyst Center as desired.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        if config.get('syslog_destination'):
            syslog_details = self.want.get('syslog_details')
            syslog_name = syslog_details.get('name')
            syslog_details_in_ccc = self.get_syslog_destination_with_name(syslog_name)

            if syslog_details_in_ccc:
                self.status = "success"
                msg = """Requested Syslog Destination '{0}' have been successfully added/updated to the Cisco Catalyst Center and their
                    addition/updation has been verified.""".format(syslog_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that the Syslog destination with name
                        '{0}' addition/updation task may not have executed successfully.""".format(syslog_name), "INFO")

        if config.get('snmp_destination'):
            snmp_details = self.want.get('snmp_details')
            snmp_dest_name = snmp_details.get('name')
            is_snmp_dest_exist = False

            for snmp_dict in self.have.get('snmp_destinations'):
                if snmp_dict['name'] == snmp_dest_name:
                    is_snmp_dest_exist = True
                    break

            if is_snmp_dest_exist:
                self.status = "success"
                msg = """Requested SNMP Destination '{0}' have been successfully added/updated to the Cisco Catalyst Center and their
                    addition/updation has been verified.""".format(snmp_dest_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that the SNMP destination with name
                        '{0}' addition/updation task may not have executed successfully.""".format(snmp_dest_name), "INFO")

        if config.get('rest_webhook_destination'):
            webhook_details = self.want.get('webhook_details')
            webhook_name = webhook_details.get('name')

            is_webhook_dest_exist = False
            for webhook_dict in self.have.get('webhook_destinations'):
                if webhook_dict['name'] == webhook_name:
                    is_webhook_dest_exist = True
                    break
            if is_webhook_dest_exist:
                self.status = "success"
                msg = """Requested Rest Webhook Destination '{0}' have been successfully added/updated to the Cisco Catalyst Center and their
                    addition/updation has been verified.""".format(webhook_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Rest Webhook destination with name
                        '{0}' addition/updation task may not have executed successfully.""".format(webhook_name), "INFO")

        if config.get('email_destination'):

            if self.have.get('email_destination'):
                self.status = "success"
                msg = """Requested Email Destination have been successfully configured to the Cisco Catalyst Center and their
                    configuration has been verified."""
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Email destination configuration
                         task may not have executed successfully.""", "INFO")

        if config.get('itsm_setting'):
            itsm_details = self.want.get('itsm_details')
            itsm_name = itsm_details.get('name')
            is_itsm_exist = False
            itsm_detail_in_ccc = self.have.get('itsm_setting')

            if not itsm_detail_in_ccc:
                self.log("There is no ITSM Intergartion setting present in Cisco Catalyst Center", "INFO")
            else:
                # Check whether the given itsm integration present in Cisco Catalyst Center or not.
                for itsm in itsm_detail_in_ccc:
                    if itsm['name'] == itsm_name:
                        is_itsm_exist = True
                        break

            if is_itsm_exist:
                self.status = "success"
                msg = """Requested ITSM Integration setting '{0}' have been successfully added/updated to the Cisco Catalyst Center
                    and their addition/updation has been verified.""".format(itsm_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that ITSM Integration setting with
                        name '{0}' addition/updation task may not have executed successfully.""".format(itsm_name), "INFO")

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of ITSM Integration Setting in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified ITSM Integration setting deleted from Cisco Catalyst Center.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        if config.get('itsm_setting'):
            itsm_details = self.want.get('itsm_details')
            itsm_name = itsm_details.get('name')
            itsm_detail_in_ccc = self.have.get('itsm_setting')
            itsm_deleted = True

            # Check whether the given itsm integration present in Catalyst Center or not
            if not itsm_detail_in_ccc:
                itsm_deleted = True
            else:
                for itsm in itsm_detail_in_ccc:
                    if itsm['name'] == itsm_name:
                        itsm_deleted = False
                        break

            if itsm_deleted:
                self.status = "success"
                msg = """Requested ITSM Integration setting '{0}' have been successfully deleted from the Cisco Catalyst Center
                    and their deletion has been verified.""".format(itsm_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that ITSM Integration setting with
                        name '{0}' deletion task may not have executed successfully.""".format(itsm_name), "INFO")

        return self


def main():
    """ main entry point for module execution
    """

    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin', 'aliases': ['user']},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'config_verify': {'type': 'bool', "default": False},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                    }

    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=False)

    ccc_events = Events(module)
    state = ccc_events.params.get("state")

    if state not in ccc_events.supported_states:
        ccc_events.status = "invalid"
        ccc_events.msg = "State {0} is invalid".format(state)
        ccc_events.check_return_status()

    ccc_events.validate_input().check_return_status()
    config_verify = ccc_events.params.get("config_verify")

    for config in ccc_events.validated_config:
        ccc_events.reset_values()
        ccc_events.get_want(config).check_return_status()
        ccc_events.get_have(config).check_return_status()
        ccc_events.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_events.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_events.result)


if __name__ == '__main__':
    main()
