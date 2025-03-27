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
short_description: Configure various types of destinations to deliver event notifications
  from Cisco Catalyst Center Platform.
description:
  - Configure various types of destinations to deliver event notifications from Cisco
    Catalyst Center Platform.
  - Configuring/Updating the Webhook destination details in Cisco Catalyst Center.
  - Configuring/Updating the Email destination details in Cisco Catalyst Center.
  - Configuring/Updating the Syslog destination details in Cisco Catalyst Center.
  - Configuring/Updating the SNMP destination details in Cisco Catalyst Center.
  - Configuring/Updating the ITSM Integration Settings in Cisco Catalyst Center.
  - Deletes the ITSM Integration Settings from Cisco Catalyst Center.
  - Create/Update Notification using the above destination in Cisco Catalyst Center.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Abhishek Maheshwari (@abmahesh) Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center config after applying
      the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description: List containing the subscription configuration for events, notification
      on site through one or more channels.
    type: list
    elements: dict
    required: true
    suboptions:
      webhook_destination:
        description: Dictionary containing the details for configuring/updating the
          REST Endpoint to receive Audit logs and Events from Cisco Catalyst Center
          Platform.
        type: dict
        suboptions:
          name:
            description: Name of the webhook destination. A unique identifier for
              the webhook destination within the system.
            type: str
            required: true
          description:
            description: A brief explanation of what the webhook destination is used
              for.
            type: str
          url:
            description: Fully qualified URL to which the webhook will send requests
              (e.g., "https://ciscocatalyst.com").
            type: str
            required: true
          method:
            description: The HTTP method used by the webhook when sending requests
              (e.g., POST, PUT). POST - It is typically used to create a new webhook
              destination. When you set up a new webhook in Cisco Catalyst Center,
              you would use the POST method to send the necessary configuration details
              (like URL, headers, payload format, etc.) to the server. PUT - It is
              used to update an existing webhook destination. If a webhook destination
              is already configured and you need to change any of its settings—such
              as modifying the URL, adjusting headers, or changing the payload format.
            type: str
          trust_cert:
            description: A boolean that indicates whether to verify the SSL/TLS certificate
              of the URL, setting this to true will bypass certificate verification.
              By default, it is set to false.
            type: bool
          headers:
            description: A list of HTTP headers to be included in the webhook request.
              Each header is represented as a dictionary. While giving the headers
              details we can categorize them into - "Basic, Token and No Auth". Basic
              Authentication - It  is used to ensure that the receiving server can
              validate the identity of the requesting server by checking the credentials
              against its store. This method is straightforward but less secure compared
              to others since credentials are sent encoded but not encrypted. Token
              Authentication - It involves security tokens which are typically generated
              by the server. A client must send this token in the HTTP header to access
              resources. It is more secure than Basic Authentication as it allows
              the server to issue tokens that can have a limited lifetime, be revoked,
              and carry specific permissions without exposing user credentials. No
              Auth - It implies that no authentication method is required to access
              the webhook destination. This setting can be used in environments where
              security is either handled by other means (such as network isolation)
              or where the data being transmitted is not sensitive.
            type: list
            elements: dict
            suboptions:
              name:
                description: Name of the HTTP header.
                type: str
              value:
                description: Value assigned to the HTTP header.
                type: str
              default_value:
                description: Default value for the HTTP header that can be used if
                  no specific value is provided.
                type: str
              encrypt:
                description: Indicates whether the value of the header should be encrypted.
                  Useful for sensitive data.
                type: bool
          is_proxy_route:
            description: A boolean value indicating if the request should use a proxy
              server. It will set to true for proxy routing, and false for direct
              connection. By default, it is set to True.
            type: bool
      email_destination:
        description: Configure settings to send out emails from Cisco Catalyst Center.
          Also we can create or configure email destination in Cisco Catalyst Center
          only once then later we can just modify it. This one is just used to configure
          the Primary and Secondary SMTP server while configuring the email destination.
          It's not related to email event subscription notification.
        type: dict
        suboptions:
          primary_smtp_config:
            description: Add the primary configuration for smtp while creating/updating
              email destination.
            type: dict
            suboptions:
              server_address:
                description: Hostname or IP address of the primary SMTP server. Supports
                  both IPv4 and IPv6.
                type: str
                required: true
              smtp_type:
                description: The type of connection used for the SMTP server, with
                  options being DEFAULT, TLS, or SSL. By default, it is set to DEFAULT.
                  DEFAULT - Chooses a standard SMTP connection without encryption.
                  If it's selected then port will be 25 only. TLS - Initiates an unencrypted
                  SMTP connection and upgrades to TLS encryption when available. If
                  it's selected then port will be either 465 or 587. SSL - Begins
                  with an encrypted SMTP connection using SSL from the start. If it's
                  selected then port will be either 465 or 587.
                type: str
                required: true
              port:
                description: Port number used for configuring Primary SMTP Server.
                  Also there is a mapping of smtype and port if snmp_type is DEFAULT
                  then port is 25 and for smtp_type TLS or SSL we can choose either
                  465 or 587 as port number.
                type: str
              username:
                description: Username for Authenticating Primary SMTP Server.
                type: str
              password:
                description: Password for Authenticating Primary SMTP Server.
                type: str
          secondary_smtp_config:
            description: Include an optional secondary SMTP configuration when creating
              or updating an email destination.
            type: dict
            suboptions:
              server_address:
                description: Hostname or IP address of the secondary SMTP server.
                  Supports both IPv4 and IPv6.
                type: str
              smtp_type:
                description: The type of connection used for the SMTP server, with
                  options being DEFAULT, TLS, or SSL. By default, it is set to DEFAULT.
                  DEFAULT - Chooses a standard SMTP connection without encryption.
                  If it's selected then port will be 25 only. TLS - Initiates an unencrypted
                  SMTP connection and upgrades to TLS encryption when available. If
                  it's selected then port will be either 465 or 587. SSL - Begins
                  with an encrypted SMTP connection using SSL from the start. If it's
                  selected then port will be either 465 or 587.
                type: str
              port:
                description: Port number used for configuring Secondary SMTP Server.
                  Also there is a mapping of smtype and port if snmp_type is DEFAULT
                  then port is 25 and for smtp_type TLS or SSL we can choose either
                  465 or 587 as port number.
                type: str
              username:
                description: Username for Authenticating Secondary SMTP Server.
                type: str
              password:
                description: Password for Authenticating Secondary SMTP Server.
                type: str
          sender_email:
            description: Sender's email address used when setting up or modifying
              an email destination.
            type: str
            required: true
          recipient_email:
            description: Recipient's email address that will receive emails when an
              email destination is created or updated.
            type: str
            required: true
          subject:
            description: Subject line of the email to be used when sending emails
              from the specified email destination.
            type: str
            required: true
      syslog_destination:
        description: Dictionary containing the details for configuring/updating the
          Syslog Server to collect Audit logs and Events from the Cisco Catalyst Center.
        type: dict
        suboptions:
          name:
            description: Name of the syslog destination.
            type: str
            required: true
          description:
            description: A brief explanation detailing the purpose of the syslog destination.
            type: str
            required: true
          server_address:
            description: Hostname or IP address of the Syslog server.
            type: str
            required: true
          protocol:
            description: Protocol used for sending syslog messages (e.g., UDP, TCP).
              Transmission Control Protocol (TCP) - It is a connection-oriented protocol
              used for reliable and ordered communication between devices on a network.
              It provides error-checking, retransmission of lost packets, and ensures
              that data is delivered in the correct order. User Datagram Protocol
              (UDP) - It is a connectionless protocol used for sending datagrams between
              devices on a network. It provides a lightweight, best-effort delivery
              mechanism without guaranteeing delivery or ordering of packets. UDP
              is commonly used for real-time applications such as streaming media,
              online gaming, and VoIP.
            type: str
            required: true
          port:
            description: Port number on which the syslog server is listening. It must
              be in the range of 1-65535. If not given any port then we will use 514
              as default port.
            type: int
            required: true
      snmp_destination:
        description: Dictionary containing the details for configuring/updating the
          SNMP Trap Server to receive Audit logs and Events from Cisco Catalyst Center.
        type: dict
        suboptions:
          name:
            description: Name of the SNMP destination.
            type: str
            required: true
          description:
            description: Description of the SNMP destination.
            type: str
            required: true
          server_address:
            description: IP address of the SNMP server.
            type: str
            required: true
          port:
            description: Port number on which the SNMP server is listening.
            type: str
            required: true
          snmp_version:
            description: The SNMP protocol version used for network management and
              monitoring, selectable between SNMPv2c and SNMPv3. V2C - Utilizes community
              strings for the authentication between the SNMP manager (like Cisco
              Catalyst) and managed network devices (routers, switches, access points),
              without encryption, as strings are sent in plain text. V3 - Offers enhanced
              security features over V2C, including authentication, integrity, and
              encryption, using usernames, passwords, and encryption keys for secure
              communications.
            type: str
          community:
            description: SNMP community string used for authentication, necessary
              only when the snmp_version is set to V2C.
            type: str
          username:
            description: Username required for SNMP authentication, applicable exclusively
              when the snmp_version is configured to V3.
            type: str
          mode:
            description: The security mode for SNMP communication (options - AUTH_PRIVACY,
              AUTH_NO_PRIVACY, NO_AUTH_NO_PRIVACY). Mandatory for snmp_version V3
              and must not be set to NONE. AUTH_PRIVACY - The most secure mode, providing
              both verification of the message source through authentication and protection
              of message contents with encryption. If this option is selected, must
              need to provide auth_type, auth_password, privacy_type, privacy_password
              parameter in the playbook. AUTH_NO_PRIVACY - This mode ensures the authenticity
              of SNMP messages via a community string for validation but does not
              encrypt the data, leaving it vulnerable to interception. If this option
              is selected, must need to provide auth_type, auth_password parameter
              in the playbook. NO_AUTH_NO_PRIVACY - In this mode, SNMP messages are
              neither authenticated nor encrypted, making it the least secure as it
              requires no credentials or data protection. If this option is selected,
              not need to provide auth_type, auth_password, privacy_type, privacy_password
              parameter in the playbook.
            type: str
          auth_type:
            description: Type of SNMP authentication protocol to use, such as MD5
              or SHA. SHA - Stands for Secure Hash Algorithm, a suite of cryptographic
              hash functions developed by the National Security Agency (NSA) offering
              enhanced security. MD5 - Refers to Message Digest Algorithm 5, a well-established
              cryptographic hash function generating a 128-bit hash value, employed
              in SNMPv3 for message authenticity and integrity verification.
            type: str
          auth_password:
            description: Password used for SNMP authentication.
            type: str
          privacy_type:
            description: Encryption algorithm used for SNMP privacy, such as AES128.
            type: str
          privacy_password:
            description: Password used for encryption in SNMP privacy.
            type: str
      itsm_setting:
        description: Dictionary containing the configuration details to configure
          the ServiceNow/BMCRemedy settings to automatically create incidents/problems/RFC's
          from Cisco Catalyst Center.
        type: dict
        suboptions:
          instance_name:
            description: The name of the ITSM configuration. This helps in identifying
              the integration within the system. Also while deleting the ITSM Intergration
              setting from Cisco Catalyst Center.
            type: str
            required: true
          description:
            description: A brief description of the ITSM settings, outlining its purpose
              or usage within the organization.
            type: str
          connection_settings:
            description: A dictionary of settings required to establish a connection
              with the ITSM system.
            type: dict
            suboptions:
              url:
                description: The URL of the ITSM system API endpoint. This is the
                  base URL used for ITSM service requests.
                type: str
                required: true
              username:
                description: The username used for authentication with the ITSM system.
                  This is required for accessing the API.
                type: str
                required: true
              password:
                description: The password associated with the username for API authentication.
                  It is recommended to handle this data securely.
                type: str
                required: true
      webhook_event_notification:
        description: Dictionary containing the details for creating/updating the Webhook
          Event subscription notification in Cisco Catalyst Center.
        type: dict
        suboptions:
          name:
            description: Name of the Webhook event subscription notification.
            type: str
            required: true
          description:
            description: A brief explanation detailing the purpose of the email events
              subscription notification.
            type: str
            required: true
          version:
            description: Version label for the event subscription, helping track updates
              or changes.
            type: str
          destination:
            description: The name of the destination for sending event notifications
              via webhook.
            type: str
            required: true
          events:
            description: List of event names to be subscribed to for notification
              configurations (e.g., ["AP Flap", "AP Reboot Crash"]).
            type: list
            elements: str
            required: true
          domain:
            description: The main category or domain under which events fall (e.g.,
              Know Your Network, Connectivity, etc.).
            type: str
          subdomains:
            description: More specific categories within the main domain to further
              classify events (e.g., ["Wireless", "Applications"]).
            type: list
            elements: str
          event_types:
            description: Types of events that trigger the notifications, defining
              the nature of the event (e.g., ["APP", "NETWORK"]).
            type: list
            elements: str
          event_categories:
            description: List of event categories to be included in the subscription
              for notifications (e.g., WARN, INFO, ERROR, ALERT, TASK_COMPLETE, TASK_FAILURE).
            type: list
            elements: str
          event_severities:
            description: List of event severities to be included in the subscription
              for notifications (e.g., ["1", "2", "3"]).
            type: list
            elements: str
          event_sources:
            description: List of event sources to be included in the subscription
              for notifications.
            type: list
            elements: str
          sites:
            description: List of site names where events are included in the notification
              subscription(e.g., ["Global/India", "Global/USA"]).
            type: list
            elements: str
      email_event_notification:
        description: Configuration for setting up or modifying an Email Event Subscription
          in Cisco Catalyst Center. This includes parameters for the email notification
          itself as well as details for the associated email instance.
        type: dict
        suboptions:
          name:
            description: Name of the Email event subscription notification.
            type: str
            required: true
          description:
            description: A brief explanation detailing the purpose of the Email events
              subscription notification.
            type: str
            required: true
          version:
            description: Version label for the event subscription, helping track updates
              or changes.
            type: str
          events:
            description: List of event names to be subscribed to for notification
              configurations (e.g., ["AP Flap", "AP Reboot Crash"]).
            type: list
            elements: str
            required: true
          sender_email:
            description: Originating email address for sending out the notifications.
            type: str
            required: true
          recipient_emails:
            description: Recipient email addresses that will receive the notifications.
            type: list
            elements: str
            required: true
          subject:
            description: The Subject line for the email notification, briefly indicating
              the notification content.
            type: str
            required: true
          instance:
            description: Name assigned to the specific email instance used for sending
              the notification.
            type: str
            required: true
          instance_description:
            description: Detailed explanation of the email instance's purpose and
              how it relates to the notifications.
            type: str
            required: true
          domain:
            description: The main category or domain under which events fall (e.g.,
              Know Your Network, Connectivity, etc.).
            type: str
          subdomains:
            description: More specific categories within the main domain to further
              classify events (e.g., ["Wireless", "Applications"]).
            type: list
            elements: str
          event_types:
            description: Types of events that trigger the notifications, defining
              the nature of the event (e.g., ["APP", "NETWORK"]).
            type: list
            elements: str
          event_categories:
            description: List of event categories to be included in the subscription
              for notifications (e.g., WARN, INFO, ERROR, ALERT, TASK_COMPLETE, TASK_FAILURE).
            type: list
            elements: str
          event_severities:
            description: List of event severities to be included in the subscription
              for notifications (e.g., ["1", "2", "3"]).
            type: list
            elements: str
          event_sources:
            description: List of event sources to be included in the subscription
              for notifications.
            type: list
            elements: str
          sites:
            description: List of site names where events are included in the notification
              subscription(e.g., ["Global/India", "Global/USA"]).
            type: list
            elements: str
      syslog_event_notification:
        description: Configuration for establishing or revising a Syslog Event Subscription
          in the Cisco Catalyst Center. This allows for the specification of Syslog
          event notification parameters and destination settings.
        type: dict
        suboptions:
          name:
            description: Name of the Syslog event subscription notification.
            type: str
            required: true
          description:
            description: A brief explanation detailing the purpose of the syslog events
              subscription notification.
            type: str
            required: true
          version:
            description: Version label for the event subscription, helping track updates
              or changes.
            type: str
          destination:
            description: The name of the destination for sending event notifications
              via syslog.
            type: str
            required: true
          events:
            description: List of event names to be subscribed to for notification
              configurations (e.g., ["AP Flap", "AP Reboot Crash"]).
            type: list
            elements: str
            required: true
          domain:
            description: The main category or domain under which events fall (e.g.,
              Know Your Network, Connectivity, etc.).
            type: str
          subdomains:
            description: More specific categories within the main domain to further
              classify events (e.g., ["Wireless", "Applications"]).
            type: list
            elements: str
          event_types:
            description: Types of events that trigger the notifications, defining
              the nature of the event (e.g., ["APP", "NETWORK"]).
            type: list
            elements: str
          event_categories:
            description: List of event categories to be included in the subscription
              for notifications (e.g., WARN, INFO, ERROR, ALERT, TASK_COMPLETE, TASK_FAILURE).
            type: list
            elements: str
          event_severities:
            description: List of event severities to be included in the subscription
              for notifications (e.g., ["1", "2", "3"]).
            type: list
            elements: str
          event_sources:
            description: List of event sources to be included in the subscription
              for notifications.
            type: list
            elements: str
          sites:
            description: List of site names where events are included in the notification
              subscription(e.g., ["Global/India", "Global/USA"]).
            type: list
            elements: str
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.5
notes:
  - To ensure the module operates correctly with scaled sets—such as creating or updating
    multiple destinations and handling event subscription notifications—please ensure
    that valid input is provided in the playbook. If any failure occurs, the module
    will halt execution and will not proceed to subsequent operations.
  - Configuring the webhook destination with headers now supports starting from dnacentersdk
    version 2.9.1 onwards. This enhancement is in alignment with Catalyst Center Release
    2.3.7.5.
  - Configuring the SNMP destination now supports starting from dnacentersdk version
    2.9.1 onwards. This enhancement is in alignment with Catalyst Center Release 2.3.7.5.
  - SDK Method used are events.Events.get_syslog_destination, events.Events.create_syslog_destination,
    events.Events.update_syslog_destination, events.Events.get_snmp_destination, events.Events.create_snmp_destination,
    events.Events.update_snmp_destination, events.Events.get_webhook_destination,
    events.Events.create_webhook_destination, events.Events.update_webhook_destination,
    events.Events.get_email_destination, events.Events.create_email_destination, events.Events.get_status_api_for_events,
    events.Events.get_all_itsm_integration_settings, events.Events.get_itsm_integration_setting_by_id,
    events.Events.create_itsm_integration_setting, events.Events.update_itsm_integration_setting,
    events.Events.delete_itsm_integration_setting, events.Events.get_eventartifacts,
    events.Events.get_site, events.Events.get_syslog_event_subscriptions, events.Events.get_syslog_subscription_details,
    events.Events.create_syslog_event_subscription, events.Events.update_syslog_event_subscription,
    events.Events.get_rest_webhook_event_subscriptions, events.Events.get_rest_webhook_subscription_details,
    events.Events.create_rest_webhook_event_subscription, events.Events.update_rest_webhook_event_subscription,
    events.Events.get_email_event_subscriptions, events.Events.get_email_subscription_details,
    events.Events.create_email_event_subscription, events.Events.update_email_event_subscription,
    events.Events.delete_event_subscriptions
"""
EXAMPLES = r"""
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
    dnac_log: false
    state: merged
    config:
      - webhook_destination:
          name: "webhook test"
          description: "creating webhook for testing"
          url: "https://10.195.227.14/dna"
          method: "POST"
          trust_cert: false
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
    dnac_log: false
    state: merged
    config:
      - webhook_destination:
          name: "webhook test"
          description: "updating webhook for testing"
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
    dnac_log: false
    state: merged
    config:
      - email_destination:
          sender_email: "test@cisco.com"
          recipient_email: "demo@cisco.com"
          subject: "Ansible testing"
          primary_smtp_config:
            server_address: "outbound.cisco.com"
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
    dnac_log: false
    state: merged
    config:
      - email_destination:
          sender_email: "test@cisco.com"
          recipient_email: "demo123@cisco.com"
          subject: "Ansible updated email config testing"
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
    dnac_log: false
    state: merged
    config:
      - syslog_destination:
          name: Syslog test
          description: "Adding syslog destination"
          server_address: "10.30.0.90"
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
    dnac_log: false
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
    dnac_log: false
    state: merged
    config:
      - snmp_destination:
          name: Snmp test
          description: "Adding snmp destination for testing."
          server_address: "10.30.0.90"
          port: "25"
          snmp_version: "V3"
          username: cisco
          mode: AUTH_PRIVACY
          auth_type: SHA
          auth_password: authpass123
          privacy_type: AES128
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
    dnac_log: false
    state: merged
    config:
      - snmp_destination:
          name: Snmp test
          description: "Updating snmp destination with snmp version v2."
          server_address: "10.30.0.23"
          port: "25"
          snmp_version: "V2C"
          community: "public123"
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
    dnac_log: false
    state: merged
    config:
      - itsm_setting:
          instance_name: "ITSM test"
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
    dnac_log: false
    state: merged
    config:
      - itsm_setting:
          instance_name: "ITSM test"
          connection_settings:
            url: "http/catalystcenterupdate.com"
            password: "catalyst@123"
- name: Creating Webhook Notification with the list of names of subscribed events
    in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - webhook_event_notification:
          name: "Webhook Notification."
          description: "Notification for webhook events subscription"
          sites: ["Global/India", "Global/USA"]
          events: ["AP Flap", "AP Reboot Crash", "Device Updation"]
          destination: "Webhook Demo"
- name: Updating Webhook Notification with the list of names of subscribed events
    in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - webhook_event_notification:
          name: "Webhook Notification."
          description: "Updated notification for webhook events subscription"
          sites: ["Global/India", "Global/USA", "Global/China"]
          destination: "Webhook Demo"
- name: Creating Email Notification with the list of names of subscribed events
    in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - email_event_notification:
          name: "Email Notification"
          description: "Notification description for email subscription creation"
          sites: ["Global/India", "Global/USA"]
          events: ["AP Flap", "AP Reboot Crash"]
          sender_email: "catalyst@cisco.com"
          recipient_emails: ["test@cisco.com", "demo@cisco.com"]
          subject: "Mail test"
          instance: Email Instance test
- name: Updating Email Notification with the list of names of subscribed events
    in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - email_event_notification:
          name: "Email Notification"
          description: "Notification description for email subscription updation"
          sites: ["Global/India", "Global/USA"]
          events: ["AP Flap", "AP Reboot Crash"]
          sender_email: "catalyst@cisco.com"
          recipient_emails: ["test@cisco.com", "demo@cisco.com", "update@cisco.com"]
          subject: "Mail test for updation"
          instance: Email Instance test
- name: Creating Syslog Notification with the list of names of subscribed events
    in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - syslog_event_notification:
          name: "Syslog Notification."
          description: "Notification for syslog events subscription"
          sites: ["Global/India", "Global/USA"]
          events: ["AP Flap", "AP Reboot Crash"]
          destination: "Syslog Demo"
- name: Updating Syslog Notification with the list of names of subscribed events
    in the system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - syslog_event_notification:
          name: "Syslog Notification."
          description: "Updated notification for syslog events subscription"
          sites: ["Global/India", "Global/USA", "Global/China"]
          events: ["AP Flap", "AP Reboot Crash"]
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
    dnac_log: false
    state: deleted
    config:
      - itsm_setting:
          instance_name: "ITSM test"
- name: Deleting Webhook Events Subscription Notification with given name from the
    system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - webhook_event_notification:
          name: "Webhook Notification"
- name: Deleting Email Events Subscription Notification with given name from the
    system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - email_event_notification:
          name: "Email Notification"
- name: Deleting Syslog Events Subscription Notification with given name from the
    system.
  cisco.dnac.events_and_notifications_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - syslog_event_notification:
          name: "Syslog Notification"
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
import time
class Events(DnacBase):
    """Class containing member attributes for inventory workflow manager module"""
    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.create_dest, self.update_dest, self.no_update_dest = [], [], []
        self.create_notification, self.update_notification, self.no_update_notification = [], [], []
        self.delete_dest, self.delete_notification, self.absent_dest, self.absent_notification = [], [], [], []
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
            'webhook_destination': {
                'type': 'dict',
                'name': {'type': 'str'},
                'description': {'type': 'str'},
                'url': {'type': 'str'},
                'method': {'type': 'str', 'default': 'POST'},
                'trust_cert': {'type': 'bool', 'default': False},
                'headers': {
                    'type': 'dict',
                    'name': {'type': 'str'},
                    'value': {'type': 'str'},
                    'default_value': {'type': 'str'},
                    'encrypt': {'type': 'bool'},
                },
                'is_proxy_route': {'type': 'bool', 'default': True}
            },
            'email_destination': {
                'type': 'dict',
                'primary_smtp_config': {
                    'type': 'dict',
                    'server_address': {'type': 'str'},
                    'smtp_type': {'type': 'str', 'default': 'DEFAULT'},
                    'port': {'type': 'str', 'default': '25'},
                    'username': {'type': 'str'},
                    'password': {'type': 'str'},
                },
                'secondary_smtp_config': {
                    'type': 'dict',
                    'server_address': {'type': 'str'},
                    'smtp_type': {'type': 'str'},
                    'port': {'type': 'str'},
                    'username': {'type': 'str'},
                    'password': {'type': 'str'},
                },
                'sender_email': {'type': 'str'},
                'recipient_email': {'type': 'str'},
                'subject': {'type': 'str'},
            },
            'syslog_destination': {
                'type': 'dict',
                'name': {'type': 'str'},
                'description': {'type': 'str'},
                'server_address': {'type': 'str'},
                'protocol': {'type': 'str'},
                'port': {'type': 'int', 'default': 514},
            },
            'snmp_destination': {
                'type': 'dict',
                'name': {'type': 'str'},
                'description': {'type': 'str'},
                'server_address': {'type': 'str'},
                'port': {'type': 'str'},
                'snmp_version': {'type': 'str'},
                'community': {'type': 'str'},
                'username': {'type': 'str'},
                'mode': {'type': 'str'},
                'auth_type': {'type': 'str'},
                'auth_password': {'type': 'str'},
                'privacy_type': {'type': 'str'},
                'privacy_password': {'type': 'str'},
            },
            'itsm_setting': {
                'type': 'dict',
                'instance_name': {'type': 'str'},
                'description': {'type': 'str'},
                'connection_settings': {
                    'type': 'dict',
                    'url': {'type': 'str'},
                    'username': {'type': 'str'},
                    'password': {'type': 'str'},
                },
            },
            'webhook_event_notification': {
                'type': 'dict',
                'name': {'type': 'str'},
                'version': {'type': 'str'},
                'description': {'type': 'str'},
                'sites': {'type': 'list', 'elements': 'str'},
                'events': {'type': 'list', 'elements': 'str'},
                'destination': {'type': 'str'},
                'domain': {'type': 'str'},
                'subdomains': {'type': 'list', 'elements': 'str'},
                'event_types': {'type': 'list', 'elements': 'str'},
                'event_categories': {'type': 'list', 'elements': 'str'},
                'event_severities': {'type': 'list', 'elements': 'str'},
                'event_sources': {'type': 'list', 'elements': 'str'},
            },
            'email_event_notification': {
                'type': 'dict',
                'name': {'type': 'str'},
                'version': {'type': 'str'},
                'description': {'type': 'str'},
                'sites': {'type': 'list', 'elements': 'str'},
                'events': {'type': 'list', 'elements': 'str'},
                'sender_email': {'type': 'str'},
                'recipient_emails': {'type': 'list', 'elements': 'str'},
                'subject': {'type': 'str'},
                'instance': {'type': 'str'},
                'instance_description': {'type': 'str'},
                'domain': {'type': 'str'},
                'subdomains': {'type': 'list', 'elements': 'str'},
                'event_types': {'type': 'list', 'elements': 'str'},
                'event_categories': {'type': 'list', 'elements': 'str'},
                'event_severities': {'type': 'list', 'elements': 'str'},
                'event_sources': {'type': 'list', 'elements': 'str'},
            },
            'syslog_event_notification': {
                'type': 'dict',
                'name': {'type': 'str'},
                'version': {'type': 'str'},
                'description': {'type': 'str'},
                'sites': {'type': 'list', 'elements': 'str'},
                'events': {'type': 'list', 'elements': 'str'},
                'destination': {'type': 'str'},
                'domain': {'type': 'str'},
                'subdomains': {'type': 'list', 'elements': 'str'},
                'event_types': {'type': 'list', 'elements': 'str'},
                'event_categories': {'type': 'list', 'elements': 'str'},
                'event_severities': {'type': 'list', 'elements': 'str'},
                'event_sources': {'type': 'list', 'elements': 'str'},
            },
        }
        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, temp_spec
        )
        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(invalid_params)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            self.result['response'] = self.msg
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
        if config.get("syslog_destination"):
            name = config.get("syslog_destination").get("name")
            syslog_destination = self.get_syslog_destination_in_ccc(name)
            if syslog_destination:
                have["syslog_destinations"] = syslog_destination[0]
        if config.get("snmp_destination"):
            name = config.get("snmp_destination").get("name")
            snmp_destinations = self.get_snmp_destination_in_ccc(name)
            if snmp_destinations:
                have["snmp_destinations"] = snmp_destinations
        if config.get("webhook_destination"):
            name = config.get("webhook_destination").get("name")
            webhook_destinations = self.get_webhook_destination_in_ccc(name)
            if webhook_destinations:
                have["webhook_destinations"] = webhook_destinations
        if config.get("email_destination"):
            email_destination = self.get_email_destination_in_ccc()
            if email_destination:
                have["email_destination"] = email_destination
        if config.get("itsm_setting"):
            name = config.get("itsm_setting").get("instance_name")
            itsm_setting = self.get_itsm_settings_in_ccc(name)
            if itsm_setting:
                have["itsm_setting"] = itsm_setting
        if config.get("syslog_event_notification"):
            name = config.get("syslog_event_notification").get("name")
            syslog_subscription_notifications = self.get_syslog_notification_details(name)
            if syslog_subscription_notifications:
                have["syslog_subscription_notifications"] = syslog_subscription_notifications
        if config.get("webhook_event_notification"):
            name = config.get("webhook_event_notification").get("name")
            webhook_subscription_notifications = self.get_webhook_notification_details(name)
            if webhook_subscription_notifications:
                have["webhook_subscription_notifications"] = webhook_subscription_notifications
        if config.get("email_event_notification"):
            name = config.get("email_event_notification").get("name")
            email_subscription_notifications = self.get_email_notification_details(name)
            if email_subscription_notifications:
                have["email_subscription_notifications"] = email_subscription_notifications
        self.have = have
        self.log("Current State (have): {0}".format(str(have)), "INFO")
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
        if config.get('webhook_destination'):
            want['webhook_details'] = config.get('webhook_destination')
        if config.get('email_destination'):
            want['email_details'] = config.get('email_destination')
        if config.get('itsm_setting'):
            want['itsm_details'] = config.get('itsm_setting')
        if config.get('webhook_event_notification'):
            want['webhook_event_notification'] = config.get('webhook_event_notification')
        if config.get('email_event_notification'):
            want['email_event_notification'] = config.get('email_event_notification')
        if config.get('syslog_event_notification'):
            want['syslog_event_notification'] = config.get('syslog_event_notification')
        self.want = want
        self.msg = "Successfully collected all parameters from the playbook "
        self.status = "success"
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
        return self
    def get_syslog_destination_in_ccc(self, name):
        """
        Retrieve the details of syslog destinations present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the syslog destination to retrieve details for.
        Returns:
            dict or None: A dictionary containing the details of syslog destination present in Cisco Catalyst Center.
                If not present then it just return the None.
        Description:
            This function queries Cisco Catalyst Center to retrieve the details of syslog destinations.
            The response contains the status message indicating the syslog destinations present in Cisco Catalyst Center.
            If no syslog destinations are found, it returns an empty string.
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
                self.log("There is no Syslog destination '{0}' present in Cisco Catalyst Center".format(name), "INFO")
                return response
            return response
        except Exception as e:
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Syslog destination with the name '{0}'. "
                        "It was not found in Cisco Catalyst Center.".format(name), "WARNING"
                    )
                    return None
            self.status = "failed"
            self.msg = "Error while getting the details of Syslog destination present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
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
            if key == "server_address":
                if syslog_details_in_ccc["host"] != value:
                    update_needed = True
                    break
            elif str(syslog_details_in_ccc[key]) == str(value) or value == "":
                continue
            else:
                update_needed = True
                break
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
            server_address = syslog_details.get('server_address')
            protocol = syslog_details.get('protocol')
            if not protocol:
                self.status = "failed"
                self.msg = "Protocol is needed while configuring the syslog destionation with name '{0}' in Cisco Catalyst Center".format(name)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            protocol = protocol.upper()
            if protocol not in ["TCP", "UDP"]:
                self.status = "failed"
                self.msg = """Invalid protocol name '{0}' for creating syslog destination in Cisco Catalyst Center.
                            Select one of the following protocol 'TCP/UDP'.""".format(protocol)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            port = syslog_details.get('port', 514)
            add_syslog_params = {
                'name': name,
                'description': description,
                'host': server_address,
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
                self.create_dest.append(name)
                return self
            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to add syslog destination with name '{0}' in Cisco Catalyst Center".format(name)
            self.msg = failure_msg
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while adding the Syslog destination with the name '{0}' in Cisco Catalyst Center: {1}".format(name, str(e))
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
            update_syslog_params['host'] = syslog_details.get('server_address') or syslog_details_in_ccc.get('host')
            update_syslog_params['protocol'] = syslog_details.get('protocol') or syslog_details_in_ccc.get('protocol')
            update_syslog_params['port'] = int(syslog_details.get('port') or syslog_details_in_ccc.get('port'))
            update_syslog_params['configId'] = syslog_details_in_ccc.get('configId')
            name = update_syslog_params.get('name')
            if update_syslog_params.get('protocol').upper() not in ["TCP", "UDP"]:
                self.status = "failed"
                self.msg = """Invalid protocol name '{0}' for updating syslog destination in Cisco Catalyst Center.
                            Select one of the following protocol 'TCP/UDP'.""".format(update_syslog_params.get('protocol'))
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
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
                self.update_dest.append(name)
                return self
            self.status = "failed"
            try:
                failure_msg = response.get('errorMessage').get('errors')
            except Exception as e:
                failure_msg = "Unable to update syslog destination with name '{0}' in Cisco Catalyst Center".format(name)
            self.msg = failure_msg
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while updating the Syslog destination with the name '{0}' in Cisco Catalyst Center: {1}".format(name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def get_snmp_destination_in_ccc(self, name):
        """
        Retrieve the details of SNMP destinations present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the syslog destination to retrieve details for.
        Returns:
            dict or None: A dictionary containing the details of SNMP destination present in Cisco Catalyst Center.
                If not present then it just return the None.
        Description:
            This function queries Cisco Catalyst Center to retrieve the details of SNMP destinations.
            It utilizes the 'event_management' API endpoint with the 'get_snmp_destination' function.
            The response contains information about the SNMP destinations present in Cisco Catalyst Center.
            If no SNMP destinations are found, it returns an empty dictionary.
        """
        try:
            offset = 0
            limit = 10
            while True:
                try:
                    response = self.dnac._exec(
                        family="event_management",
                        function='get_snmp_destination',
                        params={
                            "offset": offset * limit,
                            "limit": limit
                        }
                    )
                    offset = offset + 1
                    self.log("Received API response from 'get_snmp_destination': {0}".format(str(response)), "DEBUG")
                    if not response:
                        self.log("There is no SNMP destination with name '{0}' present in Cisco Catalyst Center".format(name), "INFO")
                        return response
                    for destination in response:
                        if destination.get("name") == name:
                            self.log("SNMP Destination '{0}' present in Cisco Catalyst Center".format(name), "INFO")
                            return destination
                    time.sleep(1)
                except Exception as e:
                    expected_exception_msgs = [
                        "Expecting value: line 1 column 1",
                        "not iterable",
                        "has no attribute"
                    ]
                    for msg in expected_exception_msgs:
                        if msg in str(e):
                            self.log(
                                "An exception occurred while checking for the SNMP destination with the name '{0}'. "
                                "It was not found in Cisco Catalyst Center.".format(name), "WARNING"
                            )
                            return None
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while getting the details of SNMP destination present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
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
            'ipAddress': snmp_details.get('server_address'),
            'port': snmp_details.get('port'),
            'snmpVersion': snmp_details.get('snmp_version')
        }
        server_address = snmp_details.get('server_address')
        snmp_version = playbook_params.get("snmpVersion")
        if snmp_version and snmp_version not in ["V2C", "V3"]:
            self.status = "failed"
            self.msg = "Invalid SNMP version '{0}' given in the playbook for configuring SNMP destination".format(snmp_version)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        if server_address and not self.is_valid_server_address(server_address):
            self.status = "failed"
            self.msg = "Invalid server address '{0}' given in the playbook for configuring SNMP destination".format(server_address)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        if snmp_version == "V2C":
            playbook_params['community'] = snmp_details.get('community')
        elif snmp_version == "V3":
            playbook_params['userName'] = snmp_details.get('username')
            playbook_params['snmpMode'] = snmp_details.get('mode')
            mode = playbook_params['snmpMode']
            auth_type = snmp_details.get('auth_type')
            if not mode or (mode not in ["AUTH_PRIVACY", "AUTH_NO_PRIVACY", "NO_AUTH_NO_PRIVACY"]):
                self.status = "failed"
                self.msg = """Invalid SNMP Mode '{0}' given in the playbook for configuring SNMP destination. Please select one of
                        the mode - AUTH_PRIVACY, AUTH_NO_PRIVACY, NO_AUTH_NO_PRIVACY in the playbook""".format(mode)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            if auth_type and auth_type not in ["SHA", "MD5"]:
                self.status = "failed"
                self.msg = """Invalid SNMP Authentication Type '{0}' given in the playbook for configuring SNMP destination. Please
                        select either SHA or MD5 as authentication type in the playbook""".format(auth_type)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            if playbook_params.get("snmpMode") == "AUTH_PRIVACY":
                playbook_params['snmpAuthType'] = auth_type
                playbook_params['authPassword'] = snmp_details.get('auth_password')
                playbook_params['snmpPrivacyType'] = snmp_details.get('privacy_type', 'AES128')
                playbook_params['privacyPassword'] = snmp_details.get('privacy_password')
            elif playbook_params.get("snmpMode") == "AUTH_NO_PRIVACY":
                playbook_params['snmpAuthType'] = auth_type
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
        self.result['response'] = self.msg
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
                self.create_dest.append(snmp_params.get('name'))
                return self
            self.status = "failed"
            error_messages = response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to add SNMP destination with name '{0}' in Cisco Catalyst Center".format(snmp_params.get('name'))
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            return self
        except Exception as e:
            self.status = "failed"
            self.msg = """Error while adding the SNMP destination with the name '{0}' in Cisco Catalyst Center:
                    {1}""".format(snmp_params.get('name'), str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
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
                    port = int(update_snmp_params.get('port'))
                    if port not in range(1, 65536):
                        self.status = "failed"
                        self.msg = "Invalid Notification trap port '{0}' given in playbook. Select port from the number range(1, 65535)".format(port)
                        self.log(self.msg, "ERROR")
                        self.result['response'] = self.msg
                        return self
                except Exception as e:
                    self.status = "failed"
                    self.msg = """Invalid datatype for the Notification trap port '{0}' given in playbook. Select port with correct datatype from the
                                number range(1, 65535).""".format(update_snmp_params.get('port'))
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
                self.update_dest.append(update_snmp_params.get('name'))
                return self
            self.status = "failed"
            error_messages = response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to update SNMP destination with name '{0}' in Cisco Catalyst Center".format(update_snmp_params.get('name'))
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while updating the SNMP destination with name '{0}' in Cisco Catalyst Center: {1}".format(update_snmp_params.get('name'), str(e))
            self.log(self.msg, "ERROR")
        return self
    def get_webhook_destination_in_ccc(self, name):
        """
        Retrieve details of Rest Webhook destinations present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the syslog destination to retrieve details for.
        Returns:
            dict: A dictionary containing details of Rest Webhook destination present in Cisco Catalyst Center,
                or None if no Rest Webhook destinations are found.
        Description:
            This function retrieves the details of Rest Webhook destinations present in Cisco Catalyst Center
            using the 'event_management' API endpoint with the 'get_webhook_destination' function.
            If an error occurs during the retrieval process, it logs the error message and raises an Exception.
        """
        try:
            offset = 0
            limit = 10
            while True:
                try:
                    response = self.dnac._exec(
                        family="event_management",
                        function='get_webhook_destination',
                        params={
                            "offset": offset * limit,
                            "limit": limit
                        }
                    )
                    offset = offset + 1
                    self.log("Received API response from 'get_webhook_destination': {0}".format(str(response)), "DEBUG")
                    response = response.get('statusMessage')
                    if not response:
                        self.log("There is no Rest Webhook destination present in Cisco Catalyst Center", "INFO")
                        return response
                    for destination in response:
                        if destination.get("name") == name:
                            self.log("Webhook Destination '{0}' present in Cisco Catalyst Center".format(name), "INFO")
                            return destination
                    time.sleep(1)
                except Exception as e:
                    expected_exception_msgs = [
                        "Expecting value: line 1 column 1",
                        "not iterable",
                        "has no attribute"
                    ]
                    for msg in expected_exception_msgs:
                        if msg in str(e):
                            self.log(
                                "An exception occurred while checking for the Webhook destination with the name '{0}'. "
                                "It was not found in Cisco Catalyst Center.".format(name), "WARNING"
                            )
                            return None
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while getting the details of Webhook destination(s) present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
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
            'method': (webhook_details.get('method', "POST") or "POST").upper(),
            'trustCert': webhook_details.get('trust_cert'),
            'isProxyRoute': webhook_details.get('is_proxy_route')
        }
        if webhook_details.get("headers") == []:
            playbook_params['headers'] = []
        elif webhook_details.get('headers'):
            custom_header = webhook_details['headers']
            playbook_params['headers'] = []
            for header in custom_header:
                playbook_params['headers'].append(header)
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
            if webhook_params.get("trustCert") is None:
                webhook_params["trustCert"] = False
            if webhook_params.get("isProxyRoute") is None:
                webhook_params["isProxyRoute"] = True
            self.log("Requested payload for creating webhook destination - {0}".format(str(webhook_params)), "INFO")
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
                self.create_dest.append(webhook_params.get('name'))
                return self
            self.status = "failed"
            error_messages = response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to add Webhook destination with name '{0}' in Cisco Catalyst Center".format(webhook_params.get('name'))
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while adding the Webhook destination with the name '{0}' in Cisco Catalyst Center: {1}".format(webhook_params.get('name'), str(e))
            self.log(self.msg, "ERROR")
        return self
    def webhook_header_needs_update(self, playbook_header, ccc_header):
        """
        Determines if an update is needed by comparing two lists of dictionaries based on the 'name' and 'value' keys.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            playbook_header (list of dict): The first list of dictionaries for headers given in the playbook. Each dictionary
                should contain 'name' and 'value' keys.
            ccc_header (list of dict): The second list of dictionaries for headers present in the Cisco Catalyst Center.
                Each dictionary should contain 'name' and 'value' keys, and may contain additional keys.
        Returns:
            bool: True if an update is needed, False otherwise.
        Description:
            This function checks whether an update is required by comparing two lists of dictionaries.
            It first checks for simple cases where one list is empty and the other is not.
            If neither of these cases applies, it converts both lists into dictionaries
            with the 'name' keys as dictionary keys and 'value' keys as dictionary values.
            It then compares these dictionaries to determine if they are identical.
            If they are not identical, it sets the update_needed flag to True.
        """
        if len(playbook_header) == 0 and ccc_header:
            return True
        if playbook_header and not ccc_header:
            return True
        playbook_dict = {item['name']: item['value'] for item in playbook_header}
        ccc_dict = {item['name']: item['value'] for item in ccc_header}
        return playbook_dict != ccc_dict
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
            if isinstance(value, list):
                update_needed = self.webhook_header_needs_update(value, webhook_dest_detail_in_ccc[key])
                if update_needed:
                    break
            elif webhook_dest_detail_in_ccc[key] == value or value is None:
                continue
            else:
                update_needed = True
                break
        return update_needed
    def update_webhook_destination(self, webhook_params, webhook_dest_detail_in_ccc):
        """
        Update a webhook destination in Cisco Catalyst Center with the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_params (dict): A dictionary containing the details of the webhook destination to be updated.
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
            update_webhook_params['name'] = webhook_params.get('name') or webhook_dest_detail_in_ccc.get('name')
            update_webhook_params['description'] = webhook_params.get('description') or webhook_dest_detail_in_ccc.get('description')
            update_webhook_params['url'] = webhook_params.get('url') or webhook_dest_detail_in_ccc.get('url')
            update_webhook_params['method'] = webhook_params.get('method') or webhook_dest_detail_in_ccc.get('method')
            update_webhook_params['trustCert'] = webhook_params.get('trustCert')
            update_webhook_params['isProxyRoute'] = webhook_params.get('isProxyRoute')
            update_webhook_params['headers'] = webhook_params.get('headers')
            update_webhook_params['webhookId'] = webhook_dest_detail_in_ccc.get('webhookId')
            name = update_webhook_params.get('name')
            if update_webhook_params.get("trustCert") is None:
                update_webhook_params["trustCert"] = webhook_dest_detail_in_ccc.get('trustCert')
            if update_webhook_params.get("isProxyRoute") is None:
                update_webhook_params["isProxyRoute"] = webhook_dest_detail_in_ccc.get('isProxyRoute')
            if update_webhook_params['headers'] != [] and not update_webhook_params['headers'] and webhook_dest_detail_in_ccc.get('headers'):
                update_webhook_params['headers'] = webhook_dest_detail_in_ccc.get('headers')
            response = self.dnac._exec(
                family="event_management",
                function='update_webhook_destination',
                op_modifies=True,
                params=update_webhook_params
            )
            self.log("Received API response from 'update_webhook_destination': {0}".format(str(response)), "DEBUG")
            status = response.get('apiStatus')
            if status == 'SUCCESS':
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Rest Webhook Destination with name '{0}' updated successfully in Cisco Catalyst Center".format(name)
                self.log(self.msg, "INFO")
                self.update_dest.append(name)
                return self
            self.status = "failed"
            error_messages = response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to update rest webhook destination with name '{0}' in Cisco Catalyst Center".format(name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while updating the Rest Webhook destination with the name '{0}' in Cisco Catalyst Center: {1}".format(name, str(e))
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
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Email destination. "
                        "It was not found in Cisco Catalyst Center.", "WARNING"
                    )
                    return None
            self.status = "failed"
            self.msg = "Error while getting the details of Email destination present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
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
            'fromEmail': email_details.get('sender_email'),
            'toEmail': email_details.get('recipient_email'),
            'subject': email_details.get('subject')
        }
        if email_details.get('primary_smtp_config'):
            primary_smtp_details = email_details.get('primary_smtp_config')
            primary_smtp_type = primary_smtp_details.get('smtp_type', "DEFAULT")
            if primary_smtp_type is None:
                primary_smtp_type = "DEFAULT"
            if primary_smtp_type not in ["DEFAULT", "TLS", "SSL"]:
                self.status = "failed"
                self.msg = """Invalid Primary SMTP Type '{0}' given in the playbook for configuring primary smtp server.
                    Please select one of the type - DEFAULT, TLS, SSL in the playbook""".format(primary_smtp_type)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            playbook_params['primarySMTPConfig'] = {}
            playbook_params['primarySMTPConfig']['hostName'] = primary_smtp_details.get('server_address')
            playbook_params['primarySMTPConfig']['smtpType'] = primary_smtp_type
            if primary_smtp_type == 'DEFAULT':
                playbook_params['primarySMTPConfig']['port'] = "25"
            else:
                playbook_params['primarySMTPConfig']['port'] = primary_smtp_details.get('port')
            playbook_params['primarySMTPConfig']['userName'] = primary_smtp_details.get('username', '')
            playbook_params['primarySMTPConfig']['password'] = primary_smtp_details.get('password', '')
        if email_details.get('secondary_smtp_config'):
            secondary_smtp_details = email_details.get('secondary_smtp_config')
            secondary_smtp_type = secondary_smtp_details.get('smtp_type', "DEFAULT")
            if secondary_smtp_type is None:
                secondary_smtp_type = "DEFAULT"
            if secondary_smtp_type and secondary_smtp_type not in ["DEFAULT", "TLS", "SSL"]:
                self.status = "failed"
                self.msg = """Invalid Secondary SMTP Type '{0}' given in the playbook for configuring secondary smtp server.
                    Please select one of the type - DEFAULT, TLS, SSL in the playbook""".format(secondary_smtp_type)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            playbook_params['secondarySMTPConfig'] = {}
            playbook_params['secondarySMTPConfig']['hostName'] = secondary_smtp_details.get('server_address')
            playbook_params['secondarySMTPConfig']['smtpType'] = secondary_smtp_type
            if playbook_params['secondarySMTPConfig']['smtpType'] == 'DEFAULT':
                playbook_params['secondarySMTPConfig']['port'] = "25"
            else:
                playbook_params['secondarySMTPConfig']['port'] = secondary_smtp_details.get('port')
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
            time.sleep(2)
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Email Destination added successfully in Cisco Catalyst Center"
                self.log(self.msg, "INFO")
                self.create_dest.append("Email destination")
                return self
            self.status = "failed"
            error_messages = response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to add Email destination in Cisco Catalyst Center."
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while adding the Email destination in Cisco Catalyst Center: {0}".format(str(e))
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
            if not value:
                continue
            if not email_dest_detail_in_ccc.get(key):
                update_needed = True
                break
            if isinstance(value, dict):
                # Recursive call should impact the update_needed flag
                update_needed = self.email_dest_needs_update(value, email_dest_detail_in_ccc[key])
                if update_needed:
                    break
            elif email_dest_detail_in_ccc.get(key) != value and value != "":
                update_needed = True
                break
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
            time.sleep(2)
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.msg = "Email Destination updated successfully in Cisco Catalyst Center"
                self.log(self.msg, "INFO")
                self.update_dest.append("Email destination")
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to update Email destination in Cisco Catalyst Center."
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while updating the Email destination in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
        return self
    def get_itsm_settings_in_ccc(self, name):
        """
        Retrieves the ITSM Integration Settings present in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The instance name of the ITSM Integration Setting to retrieve details for.
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
                function='get_all_itsm_integration_settings',
                op_modifies=True,
                params={"name": name}
            )
            self.log("Received API response from 'get_all_itsm_integration_settings': {0}".format(str(response)), "DEBUG")
            response = response.get('data')
            if not response:
                self.log("There is no ITSM Integration settings present in Cisco Catalyst Center", "INFO")
            return response
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while getting the details of ITSM Integration Settings present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
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
                self.log("There is no ITSM Integration settings with given ID present in Cisco Catalyst Center", "INFO")
            return response
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while getting the details of ITSM Integration Setting by id present in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
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
            'name': itsm_details.get('instance_name'),
            'description': itsm_details.get('description'),
            'dypName': 'ServiceNowConnection'
        }
        playbook_params['data'] = {}
        connection_details = itsm_details.get('connection_settings')
        if connection_details:
            playbook_params['data']['ConnectionSettings'] = {}
            playbook_params['data']['ConnectionSettings']['Url'] = connection_details.get('url')
            playbook_params['data']['ConnectionSettings']['Auth_UserName'] = connection_details.get('username')
            playbook_params['data']['ConnectionSettings']['Auth_Password'] = connection_details.get('password')
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
                self.create_dest.append(instance_name)
                return self
            self.status = "failed"
            failure_msg = response.get('errors')
            if not failure_msg:
                failure_msg = "Unable to create ITSM Integration Settings with name '{0}' in Cisco Catalyst Center".format(instance_name)
            self.msg = failure_msg
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
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
            - It verifies that the 'password' is provided when updating the connection settings. If not, it sets the status
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
            url_in_ccc = itsm_in_ccc.get('data').get('ConnectionSettings').get('Url')
            username_in_ccc = itsm_in_ccc.get('data').get('ConnectionSettings').get('Auth_UserName')
            if itsm_params.get('data') is None or itsm_params.get('data').get('ConnectionSettings') is None:
                update_itsm_params['data']['ConnectionSettings']['Url'] = url_in_ccc
                update_itsm_params['data']['ConnectionSettings']['Auth_UserName'] = username_in_ccc
            else:
                connection_params = itsm_params.get('data').get('ConnectionSettings')
                update_itsm_params['data']['ConnectionSettings']['Url'] = connection_params.get('Url') or url_in_ccc
                update_itsm_params['data']['ConnectionSettings']['Auth_UserName'] = connection_params.get('Auth_UserName') or username_in_ccc
                if not connection_params.get('Auth_Password'):
                    self.status = "failed"
                    self.msg = """Unable to update ITSM setting '{0}' as 'Auth Password' is the required parameter for updating
                            ITSM Intergartion setting.""".format(update_itsm_params.get('name'))
                    self.log(self.msg, "INFO")
                    self.result['response'] = self.msg
                    return self
                update_itsm_params['data']['ConnectionSettings']['Auth_Password'] = connection_params.get('Auth_Password')
            # Check whether the given url is valid or not
            url = update_itsm_params.get('data').get('ConnectionSettings').get('Url')
            regex_pattern = r'https://\S+'
            if not re.match(regex_pattern, url):
                self.status = "failed"
                self.msg = "Given url '{0}' is invalid url for ITSM Intergartion setting. It must start with 'https://'".format(url)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
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
                self.msg = (
                    "ITSM Integration Settings with name '{0}' has been updated successfully in Cisco Catalyst Center."
                ).format(update_itsm_params.get("name"))
                self.log(self.msg, "INFO")
                self.update_dest.append(update_itsm_params.get("name"))
                return self
            self.status = "failed"
            failure_msg = response.get('errors')
            if not failure_msg:
                failure_msg = "Unable to update ITSM Integration Settings with name '{0}' in Cisco Catalyst Center".format(update_itsm_params.get('name'))
            self.msg = failure_msg
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = """Error while updating the ITSM Integration Settings with name '{0}' in Cisco Catalyst Center due to:
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
                self.msg = "ITSM Integration settings instance with name '{0}' deleted successfully from Cisco Catalyst Center".format(itsm_name)
                self.status = "success"
                self.log(self.msg, "INFO")
                self.result['changed'] = True
                self.delete_dest.append(itsm_name)
                return self
            self.status = "failed"
            self.msg = "Cannot delete ITSM Integration settings instance with name '{0}' from Cisco Catalyst Center".format(itsm_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while deleting ITSM Integration Setting with name '{0}' from Cisco Catalyst Center due to: {1}".format(itsm_name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def get_syslog_notification_details(self, name):
        """
        Retrieves the details of a Syslog Event Notification subscription from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the Syslog Event Notification to retrieve details for.
        Returns:
            dict or None: A dictionary containing the details of the Syslog Event Notification subscription if found.
                        Returns None if no subscription is found or if an error occurs during the API call.
        Description:
            This function calls an API to fetch the details of a specified Syslog Event Notification subscription. If the
            subscription exists, it returns the response containing the subscription details. If no subscription is found
            or an error occurs, it logs the appropriate message and handles the exception accordingly.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_syslog_event_subscriptions',
                op_modifies=True,
                params={"name": name}
            )
            self.log("Received API response from 'get_syslog_event_subscriptions': {0}".format(str(response)), "DEBUG")
            if not response:
                self.log("There is no Syslog Event Notification with given name '{0}' present in Cisco Catalyst Center.".format(name), "INFO")
                return response
            return response
        except Exception as e:
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Syslog Event Notification with the name '{0}'. "
                        "It was not found in Cisco Catalyst Center.".format(name), "WARNING"
                    )
                    return None
            self.status = "failed"
            self.msg = (
                "An error occurred while retrieving Syslog Event subscription Notification details "
                "from Cisco Catalyst Center: {0}".format(repr(e))
            )
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
    def get_syslog_subscription_detail(self, destination):
        """
        Retrieves the details of a specific Syslog destination subscription from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            destination (str): The name of the Syslog destination for which details needs to be fetched.
        Returns:
            dict or list: A dictionary containing the details of the Syslog destination subscription if found.
                        Returns an empty list if no destination is found or if an error occurs during the API call.
        Description:
            This function calls an API to fetch the details of all Syslog destination from the Cisco Catalyst Center.
            It then searches for a subscription that matches the given `destination`. If a match is found, it returns
            details of the matching subscription. If no match is found or if an error occurs, it logs the appropriate message
            and handles the exception accordingly.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_syslog_subscription_details',
                op_modifies=True,
                params={"name": destination}
            )
            self.log("Received API response from 'get_syslog_subscription_details': {0}".format(str(response)), "DEBUG")
            if not response:
                self.log("Syslog destination with the name '{0}' not found in Cisco Catalyst Center.".format(destination), "INFO")
                return response
            return response[0]
        except Exception as e:
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Syslog destination with the name '{0}'. "
                        "It was not found in Cisco Catalyst Center.".format(destination), "WARNING"
                    )
                    return None
            self.status = "failed"
            self.msg = (
                "Error while getting the details of the Syslog Subscription with the given name '{0}'"
                " from Cisco Catalyst Center: {1}".format(destination, repr(e))
            )
            self.log(self.msg, "ERROR")
            self.check_return_status()
    def is_valid_event_types(self, event_types):
        """
        Validate the given event types against the defined types.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            event_types (list): A list of event types to be validated. Each event type should be a string.
        Returns:
            self (object): The instance of the class, with updated status and message if validation fails.
        Description:
            This function checks if the provided event types are valid based on a predefined list of acceptable event types.
            The defined types are: ["SECURITY", "APP", "NETWORK", "SYSTEM", "AUDIT_LOG", "INTEGRATIONS"].
            If `event_types` is not a list or contains invalid event types, it updates the instance status to "failed"
            and logs an error message. The function returns the instance itself to allow for method chaining.
        """
        defined_types = ["SECURITY", "APP", "NETWORK", "SYSTEM", "AUDIT_LOG", "INTEGRATIONS"]
        invalid_event_types = []
        if not isinstance(event_types, list):
            self.status = "failed"
            self.msg = "Given event types '{0}' should be a list of strings.".format(event_types)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            return self
        for e_type in event_types:
            if e_type.upper() not in defined_types:
                invalid_event_types.append(e_type)
        if invalid_event_types:
            self.status = "failed"
            self.msg = (
                "Invalid event type(s) {0} provided in the playbook. Unable to create or update "
                "event subscription notifications in Cisco Catalyst Center due to these unrecognized"
                " types.".format(invalid_event_types)
            )
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        return self
    def is_valid_event_categories(self, event_categories):
        """
        Validates the provided event categories against a predefined list of acceptable categories.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            event_categories (list of str): A list of event categories to be validated. Each category should be a string.
        Returns:
            self (object): The instance of the class, with updated status and message based on validation results.
        Description:
            This method checks if the provided event categories are valid by comparing them against a predefined list of acceptable categories:
            ["TASK_FAILURE", "TASK_COMPLETE", "WARN", "TASK_PROGRESS", "QUERY", "COMMAND", "ALERT", "INFO", "CONVERSATION", "ERROR"].
            If the input is not a list, or if any category in the list is invalid, the method updates the instance's status to "failed" and
            sets an appropriate error message. It also logs the error message.
        """
        categories = ["TASK_FAILURE", "TASK_COMPLETE", "WARN", "TASK_PROGRESS", "QUERY", "COMMAND", "ALERT", "INFO", "CONVERSATION", "ERROR"]
        invalid_event_categories = []
        if not isinstance(event_categories, list):
            self.status = "failed"
            self.msg = "Given event categories '{0}' should be a list of strings.".format(event_categories)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            return self
        for category in event_categories:
            if category.upper() not in categories:
                invalid_event_categories.append(category)
        if invalid_event_categories:
            self.status = "failed"
            self.msg = (
                "Invalid event catergory/categories {0} provided in the playbook. Unable to create or update "
                "event subscription notifications in Cisco Catalyst Center due to these unrecognized categories."
                .format(invalid_event_categories)
            )
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        return self
    def is_valid_event_severities(self, event_severities):
        """
        Validates the provided event severities to ensure they are within the acceptable range of 1 to 5.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            event_severities (list of str): A list of event severities to be validated. Each severity should be a string
                    representing a digit between 1 and 5.
        Returns:
            self (object): The instance of the class, with updated status and message based on validation results.
        Description:
            This method checks if the provided event severities are valid by ensuring they are strings representing digits between
            1 and 5. If the input is not a list, or if any severity in the list is invalid, the method updates the instance's status
            to "failed" and sets an appropriate error message. It also logs the error message.
        """
        invalid_event_severities = []
        if not isinstance(event_severities, list):
            self.status = "failed"
            self.msg = "Given event severities '{0}' should be a list of strings.".format(event_severities)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            return self
        for severity in event_severities:
            try:
                severity_int = int(severity)
                if severity_int not in range(1, 6):
                    invalid_event_severities.append(severity)
            except ValueError:
                invalid_event_severities.append(severity)
        if invalid_event_severities:
            self.status = "failed"
            self.msg = (
                "Invalid event severity/severities provided in the playbook: {0}. "
                "Unable to create or update event subscription notifications in Cisco Catalyst Center. "
                "Severity levels must be integers within the range 1 to 5.".format(invalid_event_severities)
            )
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        return self
    def get_event_ids(self, events):
        """
        Retrieves the event IDs for a given list of event names from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            events (list of str): A list of event names for which the event IDs need to be retrieved.
        Returns:
            list of str: A list of event IDs corresponding to the provided event names. If an event name is not
                    found, it is skipped.
        Description:
            This function iterates over a list of event names and calls an API to fetch the details of each event from
            the Cisco Catalyst Center. If the event is found, its event ID is extracted and added to the list of event IDs.
            The function logs messages for successfulAPI responses, missing events, and any errors encountered during the
            process. The final list of event IDs is returned.
        """
        event_ids = []
        for event_name in events:
            try:
                response = self.dnac._exec(
                    family="event_management",
                    function='get_eventartifacts',
                    op_modifies=True,
                    params={"search": event_name}
                )
                self.log("Received API response from 'get_eventartifacts': {0}".format(str(response)), "DEBUG")
                if not response:
                    self.log("There is no Event with name '{0}' present in Cisco Catalyst Center.".format(event_name), "INFO")
                    continue
                response = response[0]
                event_payload = response.get('eventPayload')
                if event_payload:
                    event_id = event_payload.get('eventId')
                    event_ids.append(event_id)
            except Exception as e:
                self.msg = """Error while getting the details of Event with given name '{0}' present in
                        Cisco Catalyst Center: {1}""".format(event_name, str(e))
                self.log(self.msg, "ERROR")
        return event_ids
    def get_site_ids(self, sites):
        """
        Retrieves the site IDs for a given list of site names from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            sites (list of str): A list of site names for which the site IDs need to be retrieved.
        Returns:
            list of str: A list of site IDs corresponding to the provided site names. If a site name is not
                    found, it is skipped and return empty list.
        Description:
            This function iterates over a list of site names and calls an API to fetch the details of each site
            from the Cisco Catalyst Center. If the site is found, its site ID is extracted and added to the list
            of site IDs. The function logs messages for successful API responses, missing sites, and any errors
            encountered during the process. The final list of site IDs is returned.
        """
        site_ids = []
        for site in sites:
            try:
                response = self.dnac._exec(
                    family="sites",
                    function='get_site',
                    op_modifies=True,
                    params={"name": site},
                )
                self.log("Received API response from 'get_site': {0}".format(str(response)), "DEBUG")
                response = response.get('response')
                if not response:
                    self.log("No site with the name '{0}' found in Cisco Catalyst Center.".format(site), "INFO")
                    continue
                site_id = response[0].get("id")
                if not site_id:
                    self.log("Site '{0}' found, but no ID available in the response.".format(site), "WARNING")
                    continue
                site_ids.append(site_id)
            except Exception as e:
                self.msg = """Error while getting the details of Site with given name '{0}' present in
                        Cisco Catalyst Center: {1}""".format(site, str(e))
                self.log(self.msg, "ERROR")
        return site_ids
    def collect_syslog_notification_playbook_params(self, syslog_notification_details):
        """
        Collects and prepares parameters for creating or updating a Syslog Event Notification.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            syslog_notification_details (dict): A dictionary containing the details required for creating or updating
                    the Syslog Event Notification.
        Returns:
            list of dict: A list containing a dictionary with the parameters for creating the Syslog Event Notification.
        Description:
            This function collects and structures the necessary parameters for creating or updating a Syslog Event Notification.
            It fetches additional details such as instance IDs and connector types from the Cisco Catalyst Center
            and prepares the subscription endpoints and filters. The function handles missing or incorrect details by logging
            appropriate messages and adjusting the status and returns a list containing required parameter.
        """
        syslog_notification_params = []
        name = syslog_notification_details.get('name')
        playbook_params = {
            'name': name,
            'description': syslog_notification_details.get('description'),
            'version': syslog_notification_details.get('version'),
            'subscriptionEndpoints': [],
            'filter': {}
        }
        # Collect the Instance ID of the syslog destination
        self.log("Collecting parameters for Syslog Event Notification named '{0}'.".format(name), "INFO")
        destination = syslog_notification_details.get('destination')
        if destination:
            subscription_details = self.get_syslog_subscription_detail(destination)
            if not subscription_details:
                self.status = "failed"
                self.msg = """Unable to create/update the syslog event notification '{0}' as syslog destination '{1}' is not configured or
                        present in Cisco Catalyst Center""".format(name, destination)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            instance_id = subscription_details.get('instanceId')
            connector_type = subscription_details.get('connectorType')
            temp_subscript_endpoint = {
                "instanceId": instance_id,
                "subscriptionDetails": {
                    "connectorType": connector_type
                }
            }
            playbook_params["subscriptionEndpoints"].append(temp_subscript_endpoint)
        events = syslog_notification_details.get('events')
        if events:
            events_ids = self.get_event_ids(events)
            if not events_ids:
                self.status = "failed"
                self.msg = (
                    "Unable to create/update Syslog event notification as the given event names '{0}' "
                    "are incorrect or could not be found."
                ).format(str(events))
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            playbook_params["filter"]["eventIds"] = events_ids
        domain = syslog_notification_details.get("domain")
        subdomains = syslog_notification_details.get("subdomains")
        if domain and subdomains:
            playbook_params["filter"]["domainsSubdomains"] = []
            domain_dict = {
                "domain": domain,
                "subDomains": subdomains
            }
            playbook_params["filter"]["domainsSubdomains"].append(domain_dict)
        # Add other filter parameters if present
        filter_keys = ["event_types", "event_categories", "event_severities", "event_sources"]
        filter_mapping = {
            "event_types": "types",
            "event_categories": "categories",
            "event_severities": "severities",
            "event_sources": "sources"
        }
        if syslog_notification_details.get("event_types"):
            self.is_valid_event_types(syslog_notification_details.get("event_types")).check_return_status()
        if syslog_notification_details.get("event_categories"):
            self.is_valid_event_categories(syslog_notification_details.get("event_categories")).check_return_status()
        if syslog_notification_details.get("event_severities"):
            self.is_valid_event_severities(syslog_notification_details.get("event_severities")).check_return_status()
        for key in filter_keys:
            value = syslog_notification_details.get(key)
            if value:
                playbook_params["filter"][filter_mapping[key]] = value
        sites = syslog_notification_details.get("sites")
        if sites:
            site_ids = self.get_site_ids(sites)
            if not site_ids:
                site_msg = (
                    "No Site IDs were found for the specified site(s) - '{0}' in the playbook input during the "
                    "Syslog event notification operation."
                ).format(sites)
                self.log(site_msg, "INFO")
            playbook_params["filter"]["siteIds"] = site_ids
        syslog_notification_params.append(playbook_params)
        self.log("Syslog notification playbook parameters collected successfully for '{0}': {1}".format(name, playbook_params), "INFO")
        return syslog_notification_params
    def mandatory_syslog_notification_parameter_check(self, syslog_notification_params):
        """
        Checks for the presence of mandatory parameters required for adding a Syslog Event Notification.
        Args:
            syslog_notification_params (list of dict): A list containing a single dictionary with the parameters
                for the Syslog Event Notification.
        Returns:
            self: The instance of the class with updated status and message if any required parameter is missing.
        Description:
            This function verifies the presence of required parameters for creating or updating a Syslog Event Notification.
            If any required parameter is absent, it logs an error message, updates the status to "failed",
            and sets the message attribute. It then returns the instance of the class with the updated status and message.
        """
        required_params_absent = []
        syslog_notification_params = syslog_notification_params[0]
        notification_name = syslog_notification_params.get("name")
        description = syslog_notification_params.get("description")
        if not notification_name:
            required_params_absent.append("name")
        if not description:
            required_params_absent.append("description")
        subs_endpoints = syslog_notification_params.get('subscriptionEndpoints')
        if not subs_endpoints:
            required_params_absent.append("destination")
        filters = syslog_notification_params.get("filter")
        if not filters.get("eventIds"):
            required_params_absent.append("events")
        if required_params_absent:
            self.status = "failed"
            self.msg = """Missing required parameter '{0}' for adding Syslog Event Notification with given
                    name {1}""".format(str(required_params_absent), notification_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        return self
    def create_syslog_notification(self, syslog_notification_params):
        """
        Creates a Syslog Event Notification subscription in Cisco Catalyst Center based on the provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            syslog_notification_params (list): A list containing a dictionary having the required parameter for creating
                    syslog event subscription notification.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                    successful or failed, any error messages encountered during operation.
        Description:
            This function makes an API call to create a Syslog Event Notification subscription in Cisco Catalyst Center.
            It takes the provided parameters as input and constructs the payload for the API call. After making the
            API call, it checks the status of the execution and updates the status and result attributes accordingly.
            If the creation is successful, it sets the status to "success" and updates the result attribute with the
            success message. If an error occurs during the process, it sets the status to "failed" and logs the
            appropriate error message.
        """
        try:
            notification_name = syslog_notification_params[0].get('name')
            self.log("Requested payload for create_syslog_event_subscription - {0}".format(str(syslog_notification_params)), "INFO")
            response = self.dnac._exec(
                family="event_management",
                function='create_syslog_event_subscription',
                op_modifies=True,
                params={'payload': syslog_notification_params}
            )
            time.sleep(1)
            self.log("Received API response from 'create_syslog_event_subscription': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Syslog Event Notification '{0}' created successfully in Cisco Catalyst Center".format(notification_name)
                self.log(self.msg, "INFO")
                self.create_notification.append(notification_name)
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to add Syslog Event Notification '{0}' in Cisco Catalyst Center.".format(notification_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = """Error while adding the Syslog Event Subscription Notification with name '{0}' in Cisco Catalyst Center:
                    {1}""".format(notification_name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def is_element_missing(self, playbook_list, ccc_list):
        """
        Checks if any element in the playbook list is missing in the CCC list.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            playbook_list (list): List of elements from the playbook.
            ccc_list (list): List of elements from the CCC.
        Returns:
            bool: True if any element from the playbook list is missing in the CCC list, False otherwise.
        Description:
            This function iterates through each element in the playbook list and checks if it is present in the CCC list.
            If any element from the playbook list is not found in the CCC list, it returns True indicating that an element
            is missing. If all elements are found, it returns False indicating that no element is missing.
        """
        for item in playbook_list:
            if item not in ccc_list:
                return True
        return False
    def compare_notification_filters(self, filters_in_playbook, filters_in_ccc):
        """
        Compares notification filters between the playbook and Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            filters_in_playbook (dict): Dictionary containing notification filters from the playbook.
            filters_in_ccc (dict): Dictionary containing notification filters from Cisco Catalyst Center.
        Returns:
            bool: True if notification filters need update, False otherwise.
        Description:
            This function compares notification filters between the playbook and Cisco Catalyst Center.
            It iterates through each key-value pair in the playbook filters and checks if they match with the
            corresponding key-value pair in the CCC filters.
            If any mismatch is found, it logs a message indicating the need for an update and returns True.
            If all filters match, it returns False indicating that no update is required.
        """
        for key, value in filters_in_playbook.items():
            if key == "domainsSubdomains":
                domain_subdomain_input = filters_in_playbook.get("domainsSubdomains")
                domain_subdomain_in_ccc = filters_in_ccc.get("domainsSubdomains")
                if domain_subdomain_input:  # Ensure that there is input for 'domainsSubdomains'
                    domain_input = domain_subdomain_input[0].get("domain")
                    subdomains_input = domain_subdomain_input[0].get("subDomains")
                else:
                    domain_input = subdomains_input = None
                if not domain_subdomain_in_ccc:
                    self.log("Since no domain or subdomains are present in Catalyst Center, the notification needs an update.", "INFO")
                    return True
                domain_in_ccc = domain_subdomain_in_ccc.get("domain")
                subdomain_in_ccc = domain_subdomain_in_ccc.get("subDomains")
                if domain_input and domain_input != domain_in_ccc:
                    self.log("Domain '{0}' given in the playbook does not match with domain in Cisco Catalyst Center".format(domain_input), "INFO")
                    return True
                if subdomains_input:
                    list_needs_update = self.is_element_missing(subdomains_input, subdomain_in_ccc)
                    if list_needs_update:
                        self.log(("Given subdomain_names '{0}' in the playbook do not match with the values present in "
                                 "Cisco Catalyst Center, so the notification needs an update.").format(subdomains_input), "INFO")
                    return True
            elif isinstance(value, list):
                if key == "severities":
                    severity_list = []
                    for item in value:
                        severity_list.append(int(item))
                    list_needs_update = self.is_element_missing(severity_list, filters_in_ccc[key])
                else:
                    list_needs_update = self.is_element_missing(value, filters_in_ccc[key])
                if list_needs_update:
                    self.log(("Parameter '{0}' given in the playbook does not match with the value present in Cisco Catalyst "
                             "Center so notification needs update.").format(key), "INFO")
                    return True
        return False
    def syslog_notification_needs_update(self, syslog_notification_params, syslog_notification_in_ccc):
        """
        Checks if a syslog notification needs update based on a comparison between playbook and CCC configurations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            syslog_notification_params (dict): Dictionary containing syslog notification parameters from the playbook.
            syslog_notification_in_ccc (dict): Dictionary containing syslog notification parameters from Cisco Catalyst Center.
        Returns:
            bool: True if the syslog notification needs update, False otherwise.
        Description:
            This function checks if a syslog notification needs update by comparing its parameters
            with the corresponding parameters in Cisco Catalyst Center.
            It compares the description, syslog destination, and filters between the playbook and CCC configurations.
            If any parameter mismatch is found, it logs a message indicating the need for an update and returns True.
            If all parameters match, it returns False indicating that no update is required.
        """
        syslog_notification_params = syslog_notification_params[0]
        name = syslog_notification_params.get("name")
        description_in_playbook = syslog_notification_params.get("description")
        description_in_ccc = syslog_notification_in_ccc.get("description")
        subs_endpoints = syslog_notification_params.get("subscriptionEndpoints")
        ccc_endpoints = syslog_notification_in_ccc.get("subscriptionEndpoints")[0]
        if description_in_playbook and description_in_playbook != description_in_ccc:
            self.log("Parameter 'description' does not match with the value of description present in Cisco Catalyst Center "
                     "so given Syslog Event Notification '{0}' needs an update".format(name), "INFO")
            return True
        if subs_endpoints:
            instance_id = subs_endpoints[0].get("instanceId")
            ccc_instance_id = ccc_endpoints.get("instanceId")
            if instance_id != ccc_instance_id:
                self.log("Given Syslog destination in the playbook is different from Syslog destination present in Cisco Catalyst Center "
                         "so given Syslog Event Notification '{0}' needs an update".format(name), "INFO")
                return True
        filters_in_playbook = syslog_notification_params.get("filter")
        filters_in_ccc = syslog_notification_in_ccc.get("filter")
        if self.compare_notification_filters(filters_in_playbook, filters_in_ccc):
            self.log("Notification filters differ between the playbook and Cisco Catalyst Center. Syslog Event Subscription Notification "
                     "'{0}' needs an update.".format(name), "INFO")
            return True
        return False
    def collect_notification_filter_params(self, playbook_params, filter, ccc_filter):
        """
        Collects notification filter parameters from playbook and CCC configurations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            playbook_params (dict): Dictionary containing parameters from the playbook.
            filter (dict): Dictionary containing filter parameters from the playbook.
            ccc_filter (dict): Dictionary containing filter parameters from Cisco Catalyst Center.
        Returns:
            dict: Dictionary containing updated playbook parameters with notification filter parameters.
        Description:
            This function collects notification filter parameters from both the playbook and CCC configurations.
            It checks if filter parameters are provided in the playbook. If provided, it updates the playbook parameters
            with the filter parameters from the playbook. If not provided, it updates the playbook parameters
            with the filter parameters from Cisco Catalyst Center.
        """
        filter_keys = ["eventIds", "domainsSubdomains", "types", "categories", "severities", "sources", "siteIds"]
        if filter:
            for key in filter_keys:
                playbook_params["filter"][key] = filter.get(key) or ccc_filter.get(key)
        else:
            # Need to take all required/optional parameter from Cisco Catalyst Center
            for key in filter_keys:
                playbook_params["filter"][key] = ccc_filter.get(key)
        return playbook_params
    def update_syslog_notification(self, syslog_notification_params, syslog_notification_in_ccc):
        """
        Updates a Syslog Event Notification subscription in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            syslog_notification_params (dict): Parameters for updating the Syslog Event Notification.
            syslog_notification_in_ccc (dict): Current configuration of the Syslog Event Notification in CCC.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                    successful or failed, any error messages encountered during operation.
        Description:
            This function updates a Syslog Event Notification subscription in Cisco Catalyst Center based on the provided parameters.
            It constructs the payload for the update operation and sends it as an API request to the Cisco Catalyst Center.
            After the update operation, it checks the status of the API request and logs appropriate messages based on the response.
        """
        syslog_notification_params = syslog_notification_params[0]
        sys_notification_update_params = []
        name = syslog_notification_params.get("name")
        playbook_params = {
            "subscriptionId": syslog_notification_in_ccc.get("subscriptionId"),
            "name": name,
            "description": syslog_notification_params.get("description") or syslog_notification_in_ccc.get("description"),
            "version": syslog_notification_params.get("version") or syslog_notification_in_ccc.get("version"),
            "filter": {}
        }
        subs_endpoints = syslog_notification_params.get("subscriptionEndpoints")
        if subs_endpoints:
            playbook_params["subscriptionEndpoints"] = subs_endpoints
        else:
            playbook_params["subscriptionEndpoints"] = []
            instance_id = syslog_notification_in_ccc.get("subscriptionEndpoints")[0].get("instanceId")
            playbook_params["subscriptionEndpoints"] = [{
                "instanceId": instance_id,
                "subscriptionDetails": {
                    "connectorType": "SYSLOG"
                }
            }]
        filter = syslog_notification_params.get("filter")
        ccc_filter = syslog_notification_in_ccc.get("filter")
        notification_params = self.collect_notification_filter_params(playbook_params, filter, ccc_filter)
        sys_notification_update_params.append(notification_params)
        try:
            self.log("Requested payload for update_syslog_event_subscription - {0}".format(str(sys_notification_update_params)), "INFO")
            response = self.dnac._exec(
                family="event_management",
                function='update_syslog_event_subscription',
                op_modifies=True,
                params={'payload': sys_notification_update_params}
            )
            time.sleep(1)
            self.log("Received API response from 'update_syslog_event_subscription': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Syslog Event Notification '{0}' updated successfully in Cisco Catalyst Center".format(name)
                self.log(self.msg, "INFO")
                self.update_notification.append(name)
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to update Syslog Event Notification '{0}' in Cisco Catalyst Center.".format(name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while updating the Syslog Event Notification with name '{0}' in Cisco Catalyst Center: {1}".format(name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def get_webhook_notification_details(self, name):
        """
        Retrieves the details of a Webhook Event Notification subscription from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the Webhook Event Notification to retrieve details for.
        Returns:
            dict or None: A dictionary containing the details of the Webhook Event Notification subscription if found.
                        Returns None if no subscription is found or if an error occurs during the API call.
        Description:
            This function calls an API to fetch the details of a specified Webhook Event Notification subscription. If the
            subscription exists, it returns the response containing the subscription details. If no subscription is found
            or an error occurs, it logs the appropriate message and handles the exception accordingly.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_rest_webhook_event_subscriptions',
                op_modifies=True,
                params={"name": name}
            )
            self.log("Received API response from 'get_rest_webhook_event_subscriptions': {0}".format(str(response)), "DEBUG")
            if not response:
                self.log("There is no Webhook Event Notification with given name '{0}' present in Cisco Catalyst Center.".format(name), "INFO")
                return response
            return response
        except Exception as e:
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Webhook Event Notification with the name '{0}'. "
                        "It was not found in Cisco Catalyst Center.".format(name), "WARNING"
                    )
                    return None
            self.status = "failed"
            self.log("Error while retrieving Webhook Event Notification details: {0}".format(str(e)), "ERROR")
            self.log(self.msg, "ERROR")
            self.check_return_status()
    def get_webhook_subscription_detail(self, destination):
        """
        Retrieves the details of a specific webhook destination subscription from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            destination (str): The name of the webhook destination for which details needs to be fetched.
        Returns:
            dict or list: A dictionary containing the details of the webhook destination subscription if found.
                        Returns an empty list if no destination is found or if an error occurs during the API call.
        Description:
            This function calls an API to fetch the details of all webhook destination from the Cisco Catalyst Center.
            It then searches for a subscription that matches the given `destination`. If a match is found, it returns
            details of the matching subscription. If no match is found or if an error occurs, it logs the appropriate message
            and handles the exception accordingly.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_rest_webhook_subscription_details',
                op_modifies=True,
                params={"name": destination}
            )
            self.log("Received API response from 'get_rest_webhook_subscription_details': {0}".format(str(response)), "DEBUG")
            if not response:
                self.log("Webhook destination with the name '{0}' not found in Cisco Catalyst Center.".format(destination), "INFO")
                return response
            return response[0]
        except Exception as e:
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Webhook destination with the name '{0}'. "
                        "It was not found in Cisco Catalyst Center.".format(destination), "WARNING"
                    )
                    return None
            self.status = "failed"
            self.msg = """Error while getting the details of webhook Subscription with given name '{0}' present in
                    Cisco Catalyst Center: {1}""".format(destination, str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
    def collect_webhook_notification_playbook_params(self, webhook_notification_details):
        """
        Collects and prepares parameters for creating or updating a webhook Event Notification.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_notification_details (dict): A dictionary containing the details required for creating or updating
                    the webhook Event Notification.
        Returns:
            list of dict: A list containing a dictionary with the parameters for creating the webhook Event Notification.
        Description:
            This function collects and structures the necessary parameters for creating or updating a webhook Event Notification.
            It fetches additional details such as instance IDs and connector types from the Cisco Catalyst Center
            and prepares the subscription endpoints and filters. The function handles missing or incorrect details by logging
            appropriate messages and adjusting the status and returns a list containing required parameter.
        """
        webhook_notification_params = []
        name = webhook_notification_details.get('name')
        playbook_params = {
            'name': name,
            'description': webhook_notification_details.get('description'),
            'version': webhook_notification_details.get('version'),
            'subscriptionEndpoints': [],
            'filter': {}
        }
        # Collect the Instance ID of the webhook destination
        self.log("Collecting parameters for Webhook Event Notification named '{0}'.".format(name), "INFO")
        destination = webhook_notification_details.get('destination')
        if destination:
            subscription_details = self.get_webhook_subscription_detail(destination)
            if not subscription_details:
                self.status = "failed"
                self.msg = """Unable to create/update the webhook event notification '{0}' as webhook destination '{1}' is not configured or
                        present in Cisco Catalyst Center""".format(name, destination)
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                self.check_return_status()
            instance_id = subscription_details.get('instanceId')
            connector_type = subscription_details.get('connectorType')
            temp_subscript_endpoint = {
                "instanceId": instance_id,
                "subscriptionDetails": {
                    "connectorType": connector_type
                }
            }
            playbook_params["subscriptionEndpoints"].append(temp_subscript_endpoint)
        events = webhook_notification_details.get('events')
        if events:
            events_ids = self.get_event_ids(events)
            if not events_ids:
                self.status = "failed"
                self.msg = (
                    "Unable to create/update Webhook event notification as the given event names '{0}' "
                    "are incorrect or could not be found."
                ).format(str(events))
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            playbook_params["filter"]["eventIds"] = events_ids
        domain = webhook_notification_details.get("domain")
        subdomains = webhook_notification_details.get("subdomains")
        if domain and subdomains:
            playbook_params["filter"]["domainsSubdomains"] = []
            domain_dict = {
                "domain": domain,
                "subDomains": subdomains
            }
            playbook_params["filter"]["domainsSubdomains"].append(domain_dict)
        # Add other filter parameters if present
        filter_keys = ["event_types", "event_categories", "event_severities", "event_sources"]
        filter_mapping = {
            "event_types": "types",
            "event_categories": "categories",
            "event_severities": "severities",
            "event_sources": "sources"
        }
        if webhook_notification_details.get("event_types"):
            self.is_valid_event_types(webhook_notification_details.get("event_types")).check_return_status()
        if webhook_notification_details.get("event_categories"):
            self.is_valid_event_categories(webhook_notification_details.get("event_categories")).check_return_status()
        if webhook_notification_details.get("event_severities"):
            self.is_valid_event_severities(webhook_notification_details.get("event_severities")).check_return_status()
        for key in filter_keys:
            value = webhook_notification_details.get(key)
            if value:
                playbook_params["filter"][filter_mapping[key]] = value
        sites = webhook_notification_details.get("sites")
        if sites:
            site_ids = self.get_site_ids(sites)
            if not site_ids:
                site_msg = (
                    "No Site IDs were found for the specified site(s) - '{0}' in the playbook input during the "
                    "Webhook event notification operation."
                ).format(sites)
                self.log(site_msg, "INFO")
            playbook_params["filter"]["siteIds"] = site_ids
            self.log("Site IDs '{0}' found for site names '{1}'. Added to filter.".format(site_ids, sites), "INFO")
        self.log("Webhook notification playbook parameters collected successfully for '{0}': {1}".format(name, playbook_params), "INFO")
        webhook_notification_params.append(playbook_params)
        return webhook_notification_params
    def mandatory_webhook_notification_parameter_check(self, webhook_notification_params):
        """
        Checks for the presence of mandatory parameters required for adding a webhook Event Notification.
        Args:
            webhook_notification_params (list of dict): A list containing a single dictionary with the parameters
                for the webhook Event Notification.
        Returns:
            self: The instance of the class with updated status and message if any required parameter is missing.
        Description:
            This function verifies the presence of required parameters for creating or updating a webhook Event Notification.
            If any required parameter is absent, it logs an error message, updates the status to "failed",
            and sets the message attribute. It then returns the instance of the class with the updated status and message.
        """
        required_params_absent = []
        webhook_params = webhook_notification_params[0]
        notification_name = webhook_params.get("name")
        description = webhook_params.get("description")
        subs_endpoints = webhook_params.get('subscriptionEndpoints')
        filters = webhook_params.get("filter")
        if not notification_name:
            required_params_absent.append("name")
        if not description:
            required_params_absent.append("description")
        if not subs_endpoints:
            required_params_absent.append("destination")
        if not filters.get("eventIds"):
            required_params_absent.append("events")
        if required_params_absent:
            self.status = "failed"
            self.msg = (
                "Missing required parameter(s) '{0}' for adding Webhook Event Notification with the given "
                "name '{1}'."
            ).format(str(required_params_absent), notification_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        return self
    def create_webhook_notification(self, webhook_notification_params):
        """
        Creates a webhook Event Notification subscription in Cisco Catalyst Center based on the provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_notification_params (list): A list containing a dictionary having the required parameter for creating
                    webhook event subscription notification.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                    successful or failed, any error messages encountered during operation.
        Description:
            This function makes an API call to create a webhook Event Notification subscription in Cisco Catalyst Center.
            It takes the provided parameters as input and constructs the payload for the API call. After making the
            API call, it checks the status of the execution and updates the status and result attributes accordingly.
            If the creation is successful, it sets the status to "success" and updates the result attribute with the
            success message. If an error occurs during the process, it sets the status to "failed" and logs the
            appropriate error message.
        """
        try:
            notification_name = webhook_notification_params[0].get('name')
            self.log("Requested payload for create_rest_webhook_event_subscription - {0}".format(str(webhook_notification_params)), "INFO")
            response = self.dnac._exec(
                family="event_management",
                function='create_rest_webhook_event_subscription',
                op_modifies=True,
                params={'payload': webhook_notification_params}
            )
            time.sleep(1)
            self.log("Received API response from 'create_rest_webhook_event_subscription': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Webhook Event Subscription Notification '{0}' created successfully in Cisco Catalyst Center".format(notification_name)
                self.log(self.msg, "INFO")
                self.create_notification.append(notification_name)
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to add Webhook Events Subscription Notification '{0}' in Cisco Catalyst Center.".format(notification_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while adding the webhook Event Notification with name '{0}' in Cisco Catalyst Center: {1}".format(notification_name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def webhook_notification_needs_update(self, webhook_notification_params, webhook_notification_in_ccc):
        """
        Checks if a webhook notification needs update based on a comparison between playbook and CCC configurations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_notification_params (dict): Dictionary containing webhook notification parameters from the playbook.
            webhook_notification_in_ccc (dict): Dictionary containing webhook notification parameters from Cisco Catalyst Center.
        Returns:
            bool: True if the webhook notification needs update, False otherwise.
        Description:
            This function checks if a webhook notification needs update by comparing its parameters
            with the corresponding parameters in Cisco Catalyst Center.
            It compares the description, webhook destination, and filters between the playbook and CCC configurations.
            If any parameter mismatch is found, it logs a message indicating the need for an update and returns True.
            If all parameters match, it returns False indicating that no update is required.
        """
        webhook_params = webhook_notification_params[0]
        name = webhook_params.get("name")
        description_in_playbook = webhook_params.get("description")
        description_in_ccc = webhook_notification_in_ccc.get("description")
        subs_endpoints = webhook_params.get("subscriptionEndpoints")
        ccc_endpoints = webhook_notification_in_ccc.get("subscriptionEndpoints")[0]
        if description_in_playbook and description_in_playbook != description_in_ccc:
            self.log("Parameter 'description' does not match with the value of description present in Cisco Catalyst Center "
                     "so given Webhook Event Notification '{0}' needs an update".format(name), "INFO")
            return True
        if subs_endpoints:
            instance_id = subs_endpoints[0].get("instanceId")
            ccc_instance_id = ccc_endpoints.get("instanceId")
            if instance_id != ccc_instance_id:
                self.log("Given Webhook destination in the playbook is different from Webhook destination present in Cisco Catalyst "
                         "Center so given Webhook Event Subscription Notification '{0}' needs an update".format(name), "INFO")
                return True
        filters_in_playbook = webhook_params.get("filter")
        filters_in_ccc = webhook_notification_in_ccc.get("filter")
        if self.compare_notification_filters(filters_in_playbook, filters_in_ccc):
            self.log("Notification filters differ between the playbook and Cisco Catalyst Center. Webhook Event Subscription Notification "
                     "'{0}' needs an update.".format(name), "INFO")
            return True
        return False
    def update_webhook_notification(self, webhook_notification_params, webhook_notification_in_ccc):
        """
        Updates a Webhook Event Notification subscription in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            webhook_notification_params (dict): Dictionary containing parameters for updating the webhook Event Notification.
            webhook_notification_in_ccc (dict): Dictionary containing current configuration of the webhook Event Notification in CCC.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                    successful or failed, any error messages encountered during operation.
        Description:
            This function updates a Webhook Event Notification subscription in Cisco Catalyst Center based on the provided parameters.
            It constructs the payload for the update operation and sends it as an API request to the Cisco Catalyst Center.
            After the update operation, it checks the status of the API request and logs appropriate messages based on the response.
        """
        webhook_params = webhook_notification_params[0]
        web_notification_update_params = []
        name = webhook_params.get("name")
        playbook_params = {
            "subscriptionId": webhook_notification_in_ccc.get("subscriptionId"),
            "name": name,
            "description": webhook_params.get("description") or webhook_notification_in_ccc.get("description"),
            "version": webhook_params.get("version") or webhook_notification_in_ccc.get("version"),
            "filter": {},
        }
        subs_endpoints = webhook_params.get("subscriptionEndpoints")
        if subs_endpoints:
            playbook_params["subscriptionEndpoints"] = subs_endpoints
        else:
            playbook_params["subscriptionEndpoints"] = []
            instance_id = webhook_notification_in_ccc.get("subscriptionEndpoints")[0].get("instanceId")
            temp_subscript_endpoint = {
                "instanceId": instance_id,
                "subscriptionDetails": {
                    "connectorType": "REST"
                }
            }
            playbook_params['subscriptionEndpoints'].append(temp_subscript_endpoint)
        filter = webhook_params.get("filter")
        ccc_filter = webhook_notification_in_ccc.get("filter")
        webhook_update_params = self.collect_notification_filter_params(playbook_params, filter, ccc_filter)
        web_notification_update_params.append(webhook_update_params)
        try:
            self.log("Requested payload for update_rest_webhook_event_subscription - {0}".format(str(web_notification_update_params)), "INFO")
            response = self.dnac._exec(
                family="event_management",
                function='update_rest_webhook_event_subscription',
                op_modifies=True,
                params={'payload': web_notification_update_params}
            )
            time.sleep(1)
            self.log("Received API response from 'update_rest_webhook_event_subscription': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Webhook Event Subscription Notification '{0}' updated successfully in Cisco Catalyst Center".format(name)
                self.log(self.msg, "INFO")
                self.update_notification.append(name)
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to update webhook Event Subscription Notification '{0}' in Cisco Catalyst Center.".format(name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Exception occurred while updating Webhook Notification with name '{0}': {1}.".format(name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def get_email_notification_details(self, name):
        """
        Retrieves the details of a Email Event Notification subscription from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the Email Event Notification to retrieve details for.
        Returns:
            dict or None: A dictionary containing the details of the email Event Notification subscription if found.
                        Returns None if no subscription is found or if an error occurs during the API call.
        Description:
            This function calls an API to fetch the details of a specified email Event Notification subscription. If the
            subscription exists, it returns the response containing the subscription details. If no subscription is found
            or an error occurs, it logs the appropriate message and handles the exception accordingly.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_email_event_subscriptions',
                op_modifies=True,
                params={"name": name}
            )
            self.log("Received API response from 'get_email_event_subscriptions': {0}".format(str(response)), "DEBUG")
            if not response:
                self.log("There is no Email Event Notification with given name '{0}' present in Cisco Catalyst Center.".format(name), "INFO")
                return response
            return response
        except Exception as e:
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Email Event Notification with the name '{0}'. "
                        "It was not found in Cisco Catalyst Center.".format(name), "WARNING"
                    )
                    return None
            self.msg = "Exception occurred while retrieving Email Event Subscription Notification: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
    def get_email_subscription_detail(self, instance):
        """
        Retrieves the details of a specific email destination subscription from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            instance (str): The name of the email destination for which details needs to be fetched.
        Returns:
            dict or list: A dictionary containing the details of the email destination subscription if found.
                        Returns an empty list if no destination is found or if an error occurs during the API call.
        Description:
            This function calls an API to fetch the details of all email destination from the Cisco Catalyst Center.
            It then searches for a subscription that matches the given `instance`. If a match is found, it returns
            details of the matching subscription. If no match is found or if an error occurs, it logs the appropriate message
            and handles the exception accordingly.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function='get_email_subscription_details',
                op_modifies=True,
                params={"name": instance}
            )
            self.log("Received API response from 'get_email_subscription_details': {0}".format(str(response)), "DEBUG")
            email_destination_details = None
            if not response:
                self.log("Email instance with given name '{0}' present in Cisco Catalyst Center.".format(instance), "INFO")
                return response
            return response[0]
        except Exception as e:
            expected_exception_msgs = [
                "Expecting value: line 1 column 1",
                "not iterable",
                "has no attribute"
            ]
            for msg in expected_exception_msgs:
                if msg in str(e):
                    self.log(
                        "An exception occurred while checking for the Email instance with the name '{0}'. "
                        "It was not found in Cisco Catalyst Center.".format(instance), "WARNING"
                    )
                    return None
            self.status = "failed"
            self.msg = """Error while getting the details of Email event Subscription with given destination name '{0}' present in
                    Cisco Catalyst Center: {1}""".format(instance, str(e))
            self.log(self.msg, "ERROR")
            self.check_return_status()
    def collect_email_notification_playbook_params(self, email_notification_details):
        """
        Collects and prepares parameters for creating or updating a email Event Notification.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_notification_details (dict): A dictionary containing the details required for creating or updating
                    the email Event Notification.
        Returns:
            list of dict: A list containing a dictionary with the parameters for creating the email Event Notification.
        Description:
            This function collects and structures the necessary parameters for creating or updating a email Event Notification.
            It fetches additional details such as instance IDs and connector types from the Cisco Catalyst Center
            and prepares the subscription endpoints and filters. The function handles missing or incorrect details by logging
            appropriate messages and adjusting the status and returns a list containing required parameter.
        """
        email_notification_params = []
        email_notf_name = email_notification_details.get('name')
        playbook_params = {
            'name': email_notf_name,
            'description': email_notification_details.get('description'),
            'version': email_notification_details.get('version'),
            'subscriptionEndpoints': [],
            'filter': {}
        }
        # Collect the Instance ID of the email destination
        self.log("Collecting parameters for Email Event Notification named '{0}'.".format(email_notf_name), "INFO")
        instance = email_notification_details.get('instance')
        if not instance:
            self.status = "failed"
            self.msg = "Instance name for Subscription Endpoints is required for Email notification '{0}'.".format(email_notf_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        subscription_details = self.get_email_subscription_detail(instance)
        if not subscription_details:
            instance_id = None
            sender_email = email_notification_details.get("sender_email")
            recipient_emails = email_notification_details.get("recipient_emails")
            subject = email_notification_details.get("subject")
            description = email_notification_details.get("instance_description")
        else:
            instance_id = subscription_details.get("instanceId")
            sender_email = email_notification_details.get("sender_email") or subscription_details.get("fromEmailAddress")
            recipient_emails = email_notification_details.get("recipient_emails") or subscription_details.get("toEmailAddresses")
            subject = email_notification_details.get("subject") or subscription_details.get("subject")
            description = email_notification_details.get("instance_description") or subscription_details.get("description")
        if not sender_email:
            self.status = "failed"
            self.msg = (
                "Unable to create/update Email event notification as missing the required parameter 'sender_email' "
                "in the playbook to create/update the Email Events Subscription Notification"
            )
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        if not recipient_emails:
            self.status = "failed"
            self.msg = (
                "Unable to create/update Email event notification as missing the required parameter 'recipient_emails' "
                "in the playbook to create/update the Email Events Subscription Notification"
            )
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        if not subject:
            self.status = "failed"
            self.msg = (
                "Unable to create/update Email event notification as missing the required parameter 'subject' "
                "in the playbook to create/update the Email Events Subscription Notification"
            )
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        if not self.is_valid_email(sender_email):
            self.status = "failed"
            self.msg = (
                "Unable to create/update Email event notification as the given sender_email '{0}' "
                "are incorrect or invalid given in the playbook."
            ).format(sender_email)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        for email in recipient_emails:
            if not self.is_valid_email(email):
                self.status = "failed"
                self.msg = (
                    "Unable to create/update Email event notification as the given recipient_email '{0}' "
                    "is incorrect or invalid given in the playbook."
                ).format(email)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
        temp_subscript_endpoint = {
            "instanceId": instance_id,
            "subscriptionDetails": {
                "connectorType": "EMAIL",
                "fromEmailAddress": sender_email,
                "toEmailAddresses": recipient_emails,
                "subject": subject,
                "name": instance,
                "description": description
            }
        }
        playbook_params["subscriptionEndpoints"].append(temp_subscript_endpoint)
        events = email_notification_details.get('events')
        if events:
            events_ids = self.get_event_ids(events)
            if not events_ids:
                self.status = "failed"
                self.msg = (
                    "Unable to create/update Email event notification as the given event names '{0}' "
                    "are incorrect or could not be found."
                ).format(str(events))
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()
            playbook_params["filter"]["eventIds"] = events_ids
        domain = email_notification_details.get("domain")
        subdomains = email_notification_details.get("subdomains")
        if domain and subdomains:
            playbook_params["filter"]["domainsSubdomains"] = []
            domain_dict = {
                "domain": domain,
                "subDomains": subdomains
            }
            playbook_params["filter"]["domainsSubdomains"].append(domain_dict)
        # Add other filter parameters if present
        filter_keys = ["event_types", "event_categories", "event_severities", "event_sources"]
        filter_mapping = {
            "event_types": "types",
            "event_categories": "categories",
            "event_severities": "severities",
            "event_sources": "sources"
        }
        if email_notification_details.get("event_types"):
            self.is_valid_event_types(email_notification_details.get("event_types")).check_return_status()
        if email_notification_details.get("event_categories"):
            self.is_valid_event_categories(email_notification_details.get("event_categories")).check_return_status()
        if email_notification_details.get("event_severities"):
            self.is_valid_event_severities(email_notification_details.get("event_severities")).check_return_status()
        for key in filter_keys:
            value = email_notification_details.get(key)
            if value:
                playbook_params["filter"][filter_mapping[key]] = value
        sites = email_notification_details.get("sites")
        if sites:
            site_ids = self.get_site_ids(sites)
            if not site_ids:
                site_msg = (
                    "No Site IDs were found for the specified site(s) - '{0}' in the playbook input during the "
                    "Email event notification operation."
                ).format(sites)
                self.log(site_msg, "INFO")
            playbook_params["filter"]["siteIds"] = site_ids
        email_notification_params.append(playbook_params)
        self.log(
            "Email notification playbook parameters collected successfully for "
            "'{0}': {1}"
            .format(email_notf_name, playbook_params), "INFO"
        )
        return email_notification_params
    def mandatory_email_notification_parameter_check(self, email_notification_params):
        """
        Checks for the presence of mandatory parameters required for adding a Email Event Subscription Notification.
        Args:
            email_notification_params (list of dict): A list containing a single dictionary with the parameters
                for the email Event Notification.
        Returns:
            self: The instance of the class with updated status and message if any required parameter is missing.
        Description:
            This function verifies the presence of required parameters for creating or updating a email Event Notification.
            If any required parameter is absent, it logs an error message, updates the status to "failed",
            and sets the message attribute. It then returns the instance of the class with the updated status and message.
        """
        required_params_absent = []
        email_notification_params = email_notification_params[0]
        notification_name = email_notification_params.get("name")
        description = email_notification_params.get("description")
        if not notification_name:
            required_params_absent.append("name")
        if not description:
            required_params_absent.append("description")
        filters = email_notification_params.get("filter")
        if not filters:
            required_params_absent.append("events")
        if required_params_absent:
            self.status = "failed"
            missing_params = ", ".join(required_params_absent)
            self.msg = "Missing required parameters [{0}] for adding Email Events Subscription Notification '{1}'.".format(missing_params, notification_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
            self.check_return_status()
        self.log("All mandatory parameters for Email Event Subscription Notification are present.", "INFO")
        return self
    def create_email_notification(self, email_notification_params):
        """
        Creates a Email Event Notification Subscription in Cisco Catalyst Center based on the provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_notification_params (list): A list containing a dictionary having the required parameter for creating
                    email event subscription notification.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                    successful or failed, any error messages encountered during operation.
        Description:
            This function makes an API call to create a Email Event Notification subscription in Cisco Catalyst Center.
            It takes the provided parameters as input and constructs the payload for the API call. After making the
            API call, it checks the status of the execution and updates the status and result attributes accordingly.
            If the creation is successful, it sets the status to "success" and updates the result attribute with the
            success message. If an error occurs during the process, it sets the status to "failed" and logs the
            appropriate error message.
        """
        try:
            notification_name = email_notification_params[0].get('name')
            self.log("Requested payload for create_email_event_subscription - {0}".format(str(email_notification_params)), "INFO")
            response = self.dnac._exec(
                family="event_management",
                function='create_email_event_subscription',
                op_modifies=True,
                params={'payload': email_notification_params}
            )
            time.sleep(1)
            self.log("Received API response from 'create_email_event_subscription': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Email Event Subscription Notification '{0}' created successfully in Cisco Catalyst Center".format(notification_name)
                self.log(self.msg, "INFO")
                self.create_notification.append(notification_name)
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to add Email Events Subscription Notification '{0}' in Cisco Catalyst Center.".format(notification_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Error while adding the Email Event Notification with name '{0}' in Cisco Catalyst Center: {1}".format(notification_name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def compare_email_subs_endpoints(self, subs_endpoints, ccc_endpoints):
        """
        Compare email subscription endpoints parameters to determine if they match or not.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            subs_endpoints (dict): A dictionary containing the subscription endpoint parameters from the playbook.
            ccc_endpoints (dict): A dictionary containing the current subscription endpoint parameters in Cisco Catalyst Center.
        Returns:
            bool: Returns True if there is any difference between the parameters in subs_endpoints and ccc_endpoints, otherwise False.
        Description:
            This function compares the specified parameters of email subscription endpoints from the provided dictionaries.
            If any of the parameters differ between subs_endpoints and ccc_endpoints, the function returns True, indicating
            that the subscription endpoints need to be updated. If all parameters match, the function returns False.
        """
        params_to_compare = ["fromEmailAddress", "toEmailAddresses", "subject", "name", "description"]
        subs_endpoints = subs_endpoints.get("subscriptionDetails")
        ccc_endpoints = ccc_endpoints.get("subscriptionDetails")
        for param in params_to_compare:
            playbook_param = subs_endpoints.get(param)
            if isinstance(playbook_param, list):
                ccc_list_param = ccc_endpoints.get(param)
                list_needs_update = self.is_element_missing(playbook_param, ccc_list_param)
                if list_needs_update:
                    self.log("""Parameter '{0}' given in the playbook does not match with the value present in Cisco Catalyst Center
                                so notification needs update.""".format(param), "INFO")
                    return True
            elif subs_endpoints.get(param) != ccc_endpoints.get(param):
                return True
        return False
    def email_notification_needs_update(self, email_notification_params, email_notification_in_ccc):
        """
        Checks if a Email notification needs update based on a comparison between playbook and CCC configurations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_notification_params (dict): Dictionary containing email notification parameters from the playbook.
            email_notification_in_ccc (dict): Dictionary containing email notification parameters from Cisco Catalyst Center.
        Returns:
            bool: True if the email notification needs update, False otherwise.
        Description:
            This function checks if a email notification needs update by comparing its parameters
            with the corresponding parameters in Cisco Catalyst Center.
            It compares the description, email destination, and filters between the playbook and CCC configurations.
            If any parameter mismatch is found, it logs a message indicating the need for an update and returns True.
            If all parameters match, it returns False indicating that no update is required.
        """
        email_notification_params = email_notification_params[0]
        name = email_notification_params.get("name")
        description_in_playbook = email_notification_params.get("description")
        description_in_ccc = email_notification_in_ccc.get("description")
        subs_endpoints = email_notification_params.get("subscriptionEndpoints")
        ccc_endpoints = email_notification_in_ccc.get("subscriptionEndpoints")[0]
        if description_in_playbook and description_in_playbook != description_in_ccc:
            self.log("Parameter 'description' does not match with the value of description present in Cisco Catalyst Center "
                     "so given Email Event Notification '{0}' needs an update".format(name), "INFO")
            return True
        if subs_endpoints:
            subs_endpoints = subs_endpoints[0]
            notification_update = self.compare_email_subs_endpoints(subs_endpoints, ccc_endpoints)
            if notification_update:
                self.log("Given Email Instance details in the playbook is different from email instance present in Cisco Catalyst "
                         "Center so given email Event Subscription Notification {0} needs an update".format(name), "INFO")
                return True
        filters_in_playbook = email_notification_params.get("filter")
        filters_in_ccc = email_notification_in_ccc.get("filter")
        if self.compare_notification_filters(filters_in_playbook, filters_in_ccc):
            self.log("Notification filters differ between the playbook and Cisco Catalyst Center. Email Event Subscription Notification "
                     "'{0}' needs an update.".format(name), "INFO")
            return True
        return False
    def update_email_notification(self, email_notification_params, email_notification_in_ccc):
        """
        Updates a Email Event Notification subscription in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            email_notification_params (dict): Dictionary containing parameters for updating the Email Event Notification.
            email_notification_in_ccc (dict): Dictionary containing current configuration of the Email Event Notification in CCC.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                    successful or failed, any error messages encountered during operation.
        Description:
            This function updates a email Event Notification subscription in Cisco Catalyst Center based on the provided parameters.
            It constructs the payload for the update operation and sends it as an API request to the Cisco Catalyst Center.
            After the update operation, it checks the status of the API request and logs appropriate messages based on the response.
        """
        email_notification_params = email_notification_params[0]
        notification_update_params = []
        name = email_notification_params.get("name")
        # Prepare the parameters for the update operation
        playbook_params = {
            "subscriptionId": email_notification_in_ccc.get("subscriptionId"),
            "name": name,
            "description": email_notification_params.get("description", email_notification_in_ccc.get("description")),
            "version": email_notification_params.get("version", email_notification_in_ccc.get("version")),
            "filter": {},
            "subscriptionEndpoints": []
        }
        subs_endpoints = email_notification_params.get("subscriptionEndpoints")
        subs_endpoints_in_ccc = email_notification_in_ccc.get("subscriptionEndpoints")[0]
        instance_id = subs_endpoints_in_ccc.get("instanceId")
        if subs_endpoints:
            playbook_params["subscriptionEndpoints"] = subs_endpoints
        else:
            playbook_params["subscriptionEndpoints"] = [{
                "instanceId": instance_id,
                "subscriptionDetails": {
                    "connectorType": "EMAIL"
                },
                "fromEmailAddress": subs_endpoints_in_ccc.get('fromEmailAddress'),
                "toEmailAddresses": subs_endpoints_in_ccc.get('toEmailAddresses'),
                "subject": subs_endpoints_in_ccc.get('subject'),
                "name": subs_endpoints_in_ccc.get('name'),
                "description": subs_endpoints_in_ccc.get('description')
            }]
        filter = email_notification_params.get("filter")
        ccc_filter = email_notification_in_ccc.get("filter")
        email_update_params = self.collect_notification_filter_params(playbook_params, filter, ccc_filter)
        notification_update_params.append(email_update_params)
        try:
            self.log("Updating Email Event Notification '{0}' with following payload: {1}".format(name, str(notification_update_params)), "INFO")
            response = self.dnac._exec(
                family="event_management",
                function='update_email_event_subscription',
                op_modifies=True,
                params={'payload': notification_update_params}
            )
            time.sleep(2)
            self.log("Received API response from 'update_email_event_subscription': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Email Event Subscription Notification '{0}' updated successfully in Cisco Catalyst Center".format(name)
                self.log(self.msg, "INFO")
                self.update_notification.append(name)
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to update Email Event Subscription Notification '{0}' in Cisco Catalyst Center.".format(name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "An error occurred while updating Email Event Subscription Notification '{0}': {1}".format(name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def delete_events_subscription_notification(self, subscription_id, subscription_name):
        """
        Delete an event subscription notification from Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            subscription_id (str): The ID of the subscription notification to be deleted.
            subscription_name (str): The name of the subscription notification to be deleted.
        Returns:
            self (object): Returns the instance of the class with updated status and result.
        Description:
            This function deletes an event subscription notification from Cisco Catalyst Center using the provided
            subscription ID for Webhook, Email and Syslog events subscription notification. If the deletion is successful,
            it updates the status to 'success' and logs the success message. If the deletion fails, it updates the status
            to 'failed' and logs the error message.
            The function also calls 'check_status_api_events' to monitor the deletion status and ensure the process
            is completed successfully before returning the result.
        """
        try:
            response = self.dnac._exec(
                family="event_management",
                function="delete_event_subscriptions",
                op_modifies=True,
                params={"subscriptions": subscription_id},
            )
            self.log("Received API response from 'update_email_event_subscription': {0}".format(str(response)), "DEBUG")
            status = response.get('statusUri')
            status_execution_id = status.split("/")[-1]
            status_response = self.check_status_api_events(status_execution_id)
            if status_response['apiStatus'] == "SUCCESS":
                self.status = "success"
                self.result['changed'] = True
                self.msg = "Event Subscription Notification '{0}' deleted successfully from Cisco Catalyst Center".format(subscription_name)
                self.log(self.msg, "INFO")
                self.delete_notification.append(subscription_name)
                return self
            self.status = "failed"
            error_messages = status_response.get('errorMessage')
            if error_messages:
                self.msg = error_messages.get('errors')
            else:
                self.msg = "Unable to delete Event Subscription Notification '{0}' from Cisco Catalyst Center.".format(subscription_name)
            self.log(self.msg, "ERROR")
            self.result['response'] = self.msg
        except Exception as e:
            self.status = "failed"
            self.msg = "Exception occurred while deleting Event Subscription Notification '{0}' due to: {1}".format(subscription_name, str(e))
            self.log(self.msg, "ERROR")
        return self
    def update_destination_notification_messages(self):
        """
        Updates the destination and notification messages for Cisco Catalyst Center.
        Args:
            self (object): Instance of the class containing attributes for destinations and notifications.
        Attributes:
            self.create_dest (list): List of destinations to be created.
            self.update_dest (list): List of destinations to be updated.
            self.no_update_dest (list): List of destinations that need no update.
            self.create_notification (list): List of notifications to be created.
            self.update_notification (list): List of notifications to be updated.
            self.no_update_notification (list): List of notifications that need no update.
            self.delete_dest (list): List of destinations to be deleted.
            self.absent_dest (list): List of destinations that are not present or cannot be deleted.
            self.delete_notification (list): List of notifications to be deleted.
            self.absent_notification (list): List of notifications that are not present and cannot be deleted.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                successful or failed, any error messages encountered during operation.
        Description:
            This method constructs and logs messages based on the actions performed (create, update, or delete)
            on destinations and event subscription notifications. It updates the `self.result` dictionary to
            indicate if changes were made and compiles the messages into a single string.
        """
        self.result["changed"] = False
        result_msg_list = []
        if self.create_dest:
            create_dest_msg = "Destination(s) '{0}' created successfully in Cisco Catalyst Center.".format(self.create_dest)
            result_msg_list.append(create_dest_msg)
        if self.update_dest:
            update_dest_msg = "Destination(s) '{0}' updated successfully in Cisco Catalyst Center.".format(self.update_dest)
            result_msg_list.append(update_dest_msg)
        if self.no_update_dest:
            no_update_dest_msg = "Destination(s) '{0}' need no update in Cisco Catalyst Center.".format(self.no_update_dest)
            result_msg_list.append(no_update_dest_msg)
        if self.create_notification:
            create_notf_msg = "Event subscription notification(s) '{0}' created successfully in Cisco Catalyst Center.".format(self.create_notification)
            result_msg_list.append(create_notf_msg)
        if self.update_notification:
            update_notf_msg = "Event subscription notification(s) '{0}' updated successfully in Cisco Catalyst Center.".format(self.update_notification)
            result_msg_list.append(update_notf_msg)
        if self.no_update_notification:
            no_update_notf_msg = "Event subscription notification(s) '{0}' need no update in Cisco Catalyst Center.".format(self.no_update_notification)
            result_msg_list.append(no_update_notf_msg)
        if self.delete_dest:
            delete_dest_msg = "Destination(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(self.delete_dest)
            result_msg_list.append(delete_dest_msg)
        if self.absent_dest:
            absent_dest_msg = "Unable to delete destination(s) '{0}' as they are not present in Cisco Catalyst Center.".format(self.absent_dest)
            result_msg_list.append(absent_dest_msg)
        if self.delete_notification:
            delete_notification_msg = (
                "Events subscription notification(s) '{0}' deleted successfully from the Cisco Catalyst Center."
            ).format(self.delete_notification)
            result_msg_list.append(delete_notification_msg)
        if self.absent_notification:
            absent_notification_msg = (
                "Unable to delete event subscription notifications '{0}' as they are not present in Cisco Catalyst Center."
            ).format(self.absent_notification)
            result_msg_list.append(absent_notification_msg)
        if self.create_dest or self.update_dest or self.create_notification or self.update_notification or self.delete_dest or self.delete_notification:
            self.result["changed"] = True
        self.msg = " ".join(result_msg_list)
        self.log(self.msg, "INFO")
        self.result["response"] = self.msg
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
        # Create/Update Rest Webhook destination in Cisco Catalyst Center
        if config.get('webhook_destination'):
            webhook_details = self.want.get('webhook_details')
            destination = webhook_details.get('name')
            if not destination:
                self.status = "failed"
                self.msg = "Name is required parameter for adding/updating Webhook destination for creating/updating the event."
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            webhook_params = self.collect_webhook_playbook_params(webhook_details)
            url = webhook_params.get('url')
            regex_pattern = re.compile(
                r'^https:\/\/'  # ensure the URL starts with https://
                r'((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|'  # domain name
                r'((\d{1,3}\.){3}\d{1,3})|'  # OR IPv4 address
                r'(\[[0-9a-fA-F:.]+\]))'  # OR IPv6 address
                r'(\:\d+)?(\/[-a-z\d%_.~+]*)*'  # port and path
                r'(\?[;&a-z\d%_.~+=-]*)?'  # query string
                r'(\#[-a-z\d_]*)?$',  # fragment locator
                re.IGNORECASE
            )
            # Check if the input string matches the pattern
            if url and not regex_pattern.match(url):
                self.status = "failed"
                self.msg = (
                    "Given url '{0}' is invalid url for Creating/Updating Webhook destination. It must starts with "
                    "'https://' and follow the valid https url format.".format(url)
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            if webhook_params.get("method") and webhook_params.get("method") not in ["POST", "PUT"]:
                self.status = "failed"
                self.msg = (
                    "Invalid Webhook method name '{0}' for creating/updating Webhook destination in Cisco Catalyst Center. "
                    "Select one of the following method 'POST/PUT'.".format(webhook_params.get('method'))
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            webhook_dest_detail_in_ccc = self.have.get("webhook_destinations")
            if not self.have.get("webhook_destinations"):
                # Need to add snmp destination in Cisco Catalyst Center with given playbook params
                if not url:
                    self.status = "failed"
                    self.msg = "Url is required parameter for creating Webhook destination for creating/updating the event in Cisco Catalyst Center."
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self
                self.add_webhook_destination(webhook_params).check_return_status()
            else:
                # Check destination needs update and if yes then update SNMP Destination
                webhook_need_update = self.webhook_dest_needs_update(webhook_params, webhook_dest_detail_in_ccc)
                if not webhook_need_update:
                    self.msg = "Webhook Destination with name '{0}' needs no update in Cisco Catalyst Center".format(destination)
                    self.log(self.msg, "INFO")
                    self.no_update_dest.append(destination)
                else:
                    # Update the syslog destination with given
                    self.update_webhook_destination(webhook_params, webhook_dest_detail_in_ccc).check_return_status()
        # Create/Update Email destination in Cisco Catalyst Center
        if config.get("email_destination"):
            email_details = self.want.get("email_details")
            email_params = self.collect_email_playbook_params(email_details)
            primary_config = email_params.get("primarySMTPConfig")
            if primary_config and primary_config.get("hostName"):
                server_address = primary_config.get("hostName")
                special_chars = r'[!@#$%^&*()_+\=\[\]{};\'\\:"|,<>\/?]'
                if server_address and re.search(special_chars, server_address):
                    self.status = "failed"
                    self.msg = (
                        "Invalid Primary SMTP server hostname '{0}' as special character present in the input server "
                        "address so unable to add/update the email destination in CCC".format(server_address)
                    )
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self
            if not self.have.get("email_destination"):
                # Need to add email destination in Cisco Catalyst Center with given playbook params
                invalid_email_params = []
                if email_params.get("primarySMTPConfig") and not email_params.get("primarySMTPConfig").get("hostName"):
                    self.status = "failed"
                    self.msg = (
                        "Required parameter '{0}' for configuring Email Destination in Cisco Catalyst Center "
                        "is missing.".format(str(invalid_email_params))
                    )
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
                    self.no_update_dest.append("Email destination")
                else:
                    # Update the email destination with given details in the playbook
                    self.update_email_destination(email_params, email_dest_detail_in_ccc).check_return_status()
        # Create/Update Syslog destination in Cisco Catalyst Center
        if config.get("syslog_destination"):
            syslog_details = self.want.get("syslog_details")
            name = syslog_details.get("name")
            port = syslog_details.get("port")
            server_address = syslog_details.get("server_address")
            if not name:
                self.status = "failed"
                self.msg = "Name is required parameter for adding/updating syslog destination for creating/updating the event."
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            if isinstance(port, str):
                if not port.isdigit() or (int(port) not in range(1, 65536)):
                    self.status = "failed"
                    self.msg = """Invalid Syslog destination port '{0}' given in playbook. Please choose a port within the range of
                            numbers (1, 65535)""".format(port)
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self
            if isinstance(port, int) and (int(port) not in range(1, 65536)):
                self.status = "failed"
                self.msg = "Invalid Syslog destination port '{0}' given in playbook. Please choose a port within the range of numbers (1, 65535)".format(port)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            if server_address and not self.is_valid_server_address(server_address):
                self.status = "failed"
                self.msg = "Invalid server address '{0}' given in the playbook for configuring Syslog destination".format(server_address)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            syslog_details_in_ccc = self.have.get('syslog_destinations')
            if not syslog_details_in_ccc:
                # We need to add the Syslog Destination in the Catalyst Center
                self.add_syslog_destination(syslog_details).check_return_status()
            else:
                # Check destination needs update and if yes then update Syslog Destination
                syslog_need_update = self.syslog_dest_needs_update(syslog_details, syslog_details_in_ccc)
                if not syslog_need_update:
                    self.msg = "Syslog Destination with name '{0}' needs no update in Cisco Catalyst Center".format(name)
                    self.log(self.msg, "INFO")
                    self.no_update_dest.append(name)
                else:
                    # Update the syslog destination with given
                    self.update_syslog_destination(syslog_details, syslog_details_in_ccc).check_return_status()
        # Create/Update snmp destination in Cisco Catalyst Center
        if config.get("snmp_destination"):
            snmp_details = self.want.get("snmp_details")
            destination = snmp_details.get("name")
            if not destination:
                self.status = "failed"
                self.msg = "Name is required parameter for adding/updating SNMP destination for creating/updating the event."
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            snmp_params = self.collect_snmp_playbook_params(snmp_details)
            snmp_dest_detail_in_ccc = self.have.get('snmp_destinations')
            if snmp_params.get('port'):
                try:
                    port = int(snmp_params.get('port'))
                    if port not in range(1, 65536):
                        self.status = "failed"
                        self.msg = "Invalid Notification trap port '{0}' given in playbook. Select port from the number range(1, 65535)".format(port)
                        self.log(self.msg, "ERROR")
                        self.result['response'] = self.msg
                        return self
                except Exception as e:
                    self.status = "failed"
                    self.msg = "Invalid Notification trap port '{0}' given in playbook. Select port from the number range(1, 65535)".format(port)
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self
            privacy_type = snmp_params.get("snmpPrivacyType")
            if privacy_type and privacy_type not in ["AES128", "DES"]:
                self.status = "failed"
                self.msg = """Invalid SNMP Privacy type '{0}' given in playbook. Select either AES128/DES as privacy type to add/update the snmp
                        destination '{1}' in the Cisco Catalyst Center.""".format(privacy_type, destination)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            if not self.have.get("snmp_destinations"):
                # Need to add snmp destination in Cisco Catalyst Center with given playbook params
                self.check_snmp_required_parameters(snmp_params).check_return_status()
                self.log("""Required parameter validated successfully for adding SNMP Destination with name '{0}' in Cisco
                            Catalyst Center.""".format(destination), "INFO")
                self.add_snmp_destination(snmp_params).check_return_status()
            else:
                # Check destination needs update and if yes then update SNMP Destination
                snmp_need_update = self.snmp_dest_needs_update(snmp_params, snmp_dest_detail_in_ccc)
                if not snmp_need_update:
                    self.msg = "SNMP Destination with name '{0}' needs no update in Cisco Catalyst Center".format(destination)
                    self.log(self.msg, "INFO")
                    self.no_update_dest.append(destination)
                    self.result['changed'] = False
                    self.result['response'] = self.msg
                else:
                    # Update the email destination with given details in the playbook
                    self.update_snmp_destination(snmp_params, snmp_dest_detail_in_ccc).check_return_status()
        # Create/Update ITSM Integration Settings in Cisco Catalyst Center
        if config.get("itsm_setting"):
            itsm_details = self.want.get("itsm_details")
            itsm_name = itsm_details.get("instance_name")
            if not itsm_name:
                self.status = "failed"
                self.msg = "Instance name is required parameter for adding/updating ITSM integration setting in Cisco Catalyst Center."
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            itsm_params = self.collect_itsm_playbook_params(itsm_details)
            itsm_detail_in_ccc = self.have.get('itsm_setting')
            if not itsm_detail_in_ccc:
                self.log("There is no ITSM Intergartion setting present in Cisco Catalyst Center", "INFO")
            else:
                # collect the ITSM id with given name
                itsm_id = itsm_detail_in_ccc[0].get("id")
            if not itsm_detail_in_ccc:
                # Need to add snmp destination in Cisco Catalyst Center with given playbook params
                invalid_itsm_params = []
                invalid_itsm_params = self.check_required_itsm_param(itsm_params, invalid_itsm_params)
                connection_setting = itsm_params.get('data').get('ConnectionSettings')
                if not connection_setting:
                    invalid_itsm_params.extend(["url", "username", "password"])
                    self.status = "failed"
                    self.msg = (
                        "Required parameter '{0}' for configuring ITSM Intergartion setting in Cisco Catalyst "
                        "is missing.".format(str(invalid_itsm_params))
                    )
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self
                # Check whether the url exist or not and if exists is it valid
                url = connection_setting.get('Url')
                if not url and "Url" not in invalid_itsm_params:
                    invalid_itsm_params.append("url")
                if invalid_itsm_params:
                    self.status = "failed"
                    self.msg = (
                        "Required parameter '{0}' for configuring ITSM Intergartion setting in Cisco Catalyst "
                        "is missing.".format(str(invalid_itsm_params))
                    )
                    self.log(self.msg, "ERROR")
                    self.result['response'] = self.msg
                    return self
                regex_pattern = r'https://\S+'
                if not re.match(regex_pattern, url):
                    self.status = "failed"
                    self.msg = "Given url '{0}' is invalid url for ITSM Intergartion setting. It must starts with 'https://'".format(url)
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
                    self.result['response'] = self.msg
                    return self
                # Check destination needs update and if yes then update Email Destination
                itsm_need_update = self.itsm_needs_update(itsm_params, itsm_in_ccc)
                if not itsm_need_update:
                    self.msg = "ITSM Intergartion setting with name '{0}' needs no update in Cisco Catalyst Center".format(itsm_name)
                    self.log(self.msg, "INFO")
                    self.no_update_dest.append(itsm_name)
                else:
                    # Update the ITSM integration settings with given details in the playbook
                    self.update_itsm_integration_setting(itsm_params, itsm_in_ccc).check_return_status()
        # Create Rest Webhook Events Subscription Notification in Cisco Catalyst Center
        if config.get("webhook_event_notification"):
            webhook_notification_details = self.want.get("webhook_event_notification")
            notification_name = webhook_notification_details.get("name")
            if not notification_name:
                self.status = "failed"
                self.msg = (
                    "Name is required parameter for creating/updating webhook events subscription notification"
                    "in Cisco Catalyst Center."
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            webhook_notification_params = self.collect_webhook_notification_playbook_params(webhook_notification_details)
            if not self.have.get("webhook_subscription_notifications"):
                # Need to create webhook event notification in Cisco Catalyst Center
                self.mandatory_webhook_notification_parameter_check(webhook_notification_params).check_return_status()
                self.log("""Successfully validated the required parameter for creating the Webhook Event Notification with
                    given name '{0}'""".format(notification_name), "INFO")
                self.create_webhook_notification(webhook_notification_params).check_return_status()
            else:
                webhook_notification_in_ccc = self.have.get("webhook_subscription_notifications")[0]
                # Check whether the webhook evenet notification needs any update or not.
                notification_update = self.webhook_notification_needs_update(webhook_notification_params, webhook_notification_in_ccc)
                if not notification_update:
                    self.msg = "Webhook Notification with name '{0}' needs no update in Cisco Catalyst Center".format(notification_name)
                    self.log(self.msg, "INFO")
                    self.no_update_notification.append(notification_name)
                else:
                    # Update the webhook notification with given playbook parameters
                    self.update_webhook_notification(webhook_notification_params, webhook_notification_in_ccc).check_return_status()
        # Create Email Events Subscription Notification in Cisco Catalyst Center
        if config.get("email_event_notification"):
            email_notification_details = self.want.get("email_event_notification")
            notification_name = email_notification_details.get("name")
            if not notification_name:
                self.status = "failed"
                self.msg = (
                    "Name is required parameter for creating/updating Email events subscription notification"
                    "in Cisco Catalyst Center."
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            email_notification_params = self.collect_email_notification_playbook_params(email_notification_details)
            if not self.have.get("email_subscription_notifications"):
                # Need to create email event notification in Cisco Catalyst Center
                self.mandatory_email_notification_parameter_check(email_notification_params).check_return_status()
                self.log("""Successfully validated the required parameter for creating the email Event Notification with
                    given name '{0}'""".format(notification_name), "INFO")
                self.create_email_notification(email_notification_params).check_return_status()
            else:
                email_notification_in_ccc = self.have.get("email_subscription_notifications")[0]
                # Check whether the email evenet notification needs any update or not.
                notification_update = self.email_notification_needs_update(email_notification_params, email_notification_in_ccc)
                if not notification_update:
                    self.msg = "Email Notification with name '{0}' needs no update in Cisco Catalyst Center".format(notification_name)
                    self.log(self.msg, "INFO")
                    self.no_update_notification.append(notification_name)
                else:
                    # Update the email notification with given playbook parameters
                    self.update_email_notification(email_notification_params, email_notification_in_ccc).check_return_status()
        # Create Syslog Events Subscription Notification in Cisco Catalyst Center
        if config.get("syslog_event_notification"):
            syslog_notification_details = self.want.get("syslog_event_notification")
            notification_name = syslog_notification_details.get("name")
            if not notification_name:
                self.status = "failed"
                self.msg = (
                    "Name is required parameter for creating/updating Syslog events subscription notification"
                    "in Cisco Catalyst Center."
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            syslog_notification_params = self.collect_syslog_notification_playbook_params(syslog_notification_details)
            if not self.have.get("syslog_subscription_notifications"):
                # Need to create syslog event notification in Cisco Catalyst Center
                self.mandatory_syslog_notification_parameter_check(syslog_notification_params).check_return_status()
                self.log("""Successfully validated the required parameter for creating the Syslog Event Notification with
                    given name '{0}'""".format(notification_name), "INFO")
                self.create_syslog_notification(syslog_notification_params).check_return_status()
            else:
                syslog_notification_in_ccc = self.have.get("syslog_subscription_notifications")[0]
                # Check whether the syslog evenet notification needs any update or not.
                sys_notification_update = self.syslog_notification_needs_update(syslog_notification_params, syslog_notification_in_ccc)
                if not sys_notification_update:
                    self.msg = "Syslog Notification with name '{0}' needs no update in Cisco Catalyst Center".format(notification_name)
                    self.log(self.msg, "INFO")
                    self.no_update_notification.append(notification_name)
                else:
                    # Update the syslog notification with given playbook parameters
                    self.update_syslog_notification(syslog_notification_params, syslog_notification_in_ccc).check_return_status()
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
        if config.get('webhook_destination'):
            self.status = "failed"
            self.msg = "Deleting the Webhook destination is not supported in Cisco Catalyst Center because of API limitations"
            self.log(self.msg, "ERROR")
            self.result['changed'] = False
            self.result['response'] = self.msg
            return self
        if config.get('email_destination'):
            self.status = "failed"
            self.msg = "Deleting the Email destination is not supported in Cisco Catalyst Center because of API limitations"
            self.log(self.msg, "ERROR")
            self.result['changed'] = False
            self.result['response'] = self.msg
            return self
        if config.get('syslog_destination'):
            self.status = "failed"
            self.msg = "Deleting the Syslog destination is not supported in Cisco Catalyst Center because of API limitations"
            self.log(self.msg, "ERROR")
            self.result['changed'] = False
            self.result['response'] = self.msg
            return self
        if config.get('snmp_destination'):
            self.status = "failed"
            self.msg = "Deleting the SNMP destination is not supported in Cisco Catalyst Center because of API limitations"
            self.log(self.msg, "ERROR")
            self.result['changed'] = False
            self.result['response'] = self.msg
            return self
        # Delete ITSM Integration setting from Cisco Catalyst Center
        if config.get('itsm_setting'):
            itsm_details = self.want.get('itsm_details')
            itsm_name = itsm_details.get('instance_name')
            itsm_detail_in_ccc = self.have.get('itsm_setting')
            if not itsm_detail_in_ccc:
                self.status = "success"
                self.msg = """There is no ITSM Intergartion setting present in Cisco Catalyst Center so cannot delete
                            the ITSM Integartion setting with name '{0}'""".format(itsm_name)
                self.log(self.msg, "INFO")
                self.absent_dest.append(itsm_name)
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
                self.absent_dest.append(itsm_name)
        # Delete Webhook Events Subscription Notification from Cisco Catalyst Center
        if config.get('webhook_event_notification'):
            webhook_notification_details = self.want.get('webhook_event_notification')
            webhook_notification_name = webhook_notification_details.get('name')
            if not webhook_notification_name:
                self.status = "failed"
                self.msg = (
                    "A name is a required parameter for deleting syslog events subscription notification"
                    " in Cisco Catalyst Center."
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            if not self.have.get("webhook_subscription_notifications"):
                self.status = "success"
                self.msg = (
                    "There is no Webhook Event Subscription Notification with name '{0}' present in in Cisco Catalyst Center "
                    "so cannot delete the notification.".format(webhook_notification_name)
                )
                self.log(self.msg, "INFO")
                self.absent_notification.append(webhook_notification_name)
                return self
            webhook_notification_id = self.have.get("webhook_subscription_notifications")[0].get("subscriptionId")
            if webhook_notification_id:
                self.delete_events_subscription_notification(webhook_notification_id, webhook_notification_name).check_return_status()
            else:
                self.msg = (
                    "Unable to delete Webhook Event Subscription Notification with name '{0}' as it is not present in "
                    "Cisco Catalyst Center.".format(webhook_notification_name)
                )
                self.log(self.msg, "INFO")
                self.absent_notification.append(webhook_notification_name)
        # Delete Email Events Subscription Notification from Cisco Catalyst Center
        if config.get('email_event_notification'):
            email_notification_details = self.want.get('email_event_notification')
            email_notification_name = email_notification_details.get('name')
            if not email_notification_name:
                self.status = "failed"
                self.msg = (
                    "A name is a required parameter for deleting email events subscription notification"
                    " in Cisco Catalyst Center."
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            if not self.have.get("email_subscription_notifications"):
                self.status = "success"
                self.msg = (
                    "There is no Email Event Subscription Notification with name '{0}' present in in Cisco Catalyst Center "
                    "so cannot delete the notification.".format(email_notification_name)
                )
                self.log(self.msg, "INFO")
                self.absent_notification.append(email_notification_name)
                return self
            email_notification_id = self.have.get("email_subscription_notifications")[0].get("subscriptionId")
            if email_notification_id:
                self.delete_events_subscription_notification(email_notification_id, email_notification_name).check_return_status()
            else:
                self.msg = (
                    "Unable to delete Email Event Subscription Notification with name '{0}' as it is not present in "
                    "Cisco Catalyst Center.".format(email_notification_name)
                )
                self.log(self.msg, "INFO")
                self.absent_notification.append(email_notification_name)
        # Delete Syslog Events Subscription Notification from Cisco Catalyst Center
        if config.get('syslog_event_notification'):
            syslog_notification_details = self.want.get('syslog_event_notification')
            syslog_notification_name = syslog_notification_details.get('name')
            if not syslog_notification_name:
                self.status = "failed"
                self.msg = (
                    "A name is a required parameter for deleting syslog events subscription notification"
                    " in Cisco Catalyst Center."
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                return self
            if not self.have.get("syslog_subscription_notifications"):
                self.status = "success"
                self.msg = (
                    "There is no Syslog Event Subscription Notification with name '{0}' present in in Cisco Catalyst Center "
                    "so cannot delete the notification.".format(syslog_notification_name)
                )
                self.log(self.msg, "INFO")
                self.absent_notification.append(syslog_notification_name)
                return self
            syslog_notification_id = self.have.get("syslog_subscription_notifications")[0].get("subscriptionId")
            if syslog_notification_id:
                self.delete_events_subscription_notification(syslog_notification_id, syslog_notification_name).check_return_status()
            else:
                self.msg = (
                    "Unable to delete Syslog Event Subscription Notification with name '{0}' as it is not present in "
                    "Cisco Catalyst Center.".format(syslog_notification_name)
                )
                self.log(self.msg, "INFO")
                self.absent_notification.append(syslog_notification_name)
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
        if config.get("syslog_destination"):
            syslog_details = self.want.get("syslog_details")
            syslog_name = syslog_details.get("name")
            destinations_in_ccc = self.have.get("syslog_destinations")
            if destinations_in_ccc:
                self.status = "success"
                msg = """Requested Syslog Destination '{0}' have been successfully added/updated to the Cisco Catalyst Center and their
                    addition/updation has been verified.""".format(syslog_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that the Syslog destination with name
                        '{0}' addition/updation task may not have executed successfully.""".format(syslog_name), "INFO")
        if config.get("snmp_destination"):
            snmp_details = self.want.get("snmp_details")
            snmp_dest_name = snmp_details.get("name")
            if self.have.get("snmp_destinations"):
                self.status = "success"
                msg = """Requested SNMP Destination '{0}' have been successfully added/updated to the Cisco Catalyst Center and their
                    addition/updation has been verified.""".format(snmp_dest_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that the SNMP destination with name
                        '{0}' addition/updation task may not have executed successfully.""".format(snmp_dest_name), "INFO")
        if config.get("webhook_destination"):
            webhook_details = self.want.get("webhook_details")
            webhook_name = webhook_details.get("name")
            if self.have.get("webhook_destinations"):
                self.status = "success"
                msg = """Requested Rest Webhook Destination '{0}' have been successfully added/updated to the Cisco Catalyst Center and their
                    addition/updation has been verified.""".format(webhook_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Rest Webhook destination with name
                        '{0}' addition/updation task may not have executed successfully.""".format(webhook_name), "INFO")
        if config.get("email_destination"):
            if self.have.get("email_destination"):
                self.status = "success"
                msg = """Requested Email Destination have been successfully configured to the Cisco Catalyst Center and their
                    configuration has been verified."""
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Email destination configuration
                         task may not have executed successfully.""", "INFO")
        if config.get("itsm_setting"):
            itsm_details = self.want.get("itsm_details")
            itsm_name = itsm_details.get("instance_name")
            itsm_detail_in_ccc = self.have.get("itsm_setting")
            if itsm_detail_in_ccc:
                self.status = "success"
                msg = """Requested ITSM Integration setting '{0}' have been successfully added/updated to the Cisco Catalyst Center
                    and their addition/updation has been verified.""".format(itsm_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that ITSM Integration setting with
                        name '{0}' addition/updation task may not have executed successfully.""".format(itsm_name), "INFO")
        if config.get("webhook_event_notification"):
            webhook_notification_details = self.want.get("webhook_event_notification")
            web_notification_name = webhook_notification_details.get("name")
            if self.have.get("webhook_subscription_notifications"):
                self.status = "success"
                msg = """Requested Webhook Events Subscription Notification '{0}' have been successfully created/updated to the Cisco Catalyst Center
                    and their creation/updation has been verified.""".format(web_notification_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Webhook Event Subscription Notification with
                        name '{0}' creation/updation task may not have executed successfully.""".format(web_notification_name), "INFO")
        if config.get("email_event_notification"):
            email_notification_details = self.want.get("email_event_notification")
            email_notification_name = email_notification_details.get("name")
            if self.have.get("email_subscription_notifications"):
                self.status = "success"
                msg = """Requested Email Events Subscription Notification '{0}' have been successfully created/updated to the Cisco Catalyst Center
                    and their creation/updation has been verified.""".format(email_notification_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Email Event Subscription Notification with
                        name '{0}' creation/updation task may not have executed successfully.""".format(email_notification_name), "INFO")
        if config.get("syslog_event_notification"):
            syslog_notification_details = self.want.get("syslog_event_notification")
            syslog_notification_name = syslog_notification_details.get("name")
            if self.have.get("syslog_subscription_notifications"):
                self.status = "success"
                msg = """Requested Syslog Events Subscription Notification '{0}' have been successfully created/updated to the Cisco Catalyst Center
                    and their creation/updation has been verified.""".format(syslog_notification_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Syslog Event Subscription Notification with
                        name '{0}' creation/updation task may not have executed successfully.""".format(syslog_notification_name), "INFO")
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
        if config.get("itsm_setting"):
            itsm_details = self.want.get("itsm_details")
            itsm_name = itsm_details.get("instance_name")
            itsm_detail_in_ccc = self.have.get("itsm_setting")
            if not itsm_detail_in_ccc:
                self.status = "success"
                msg = """Requested ITSM Integration setting '{0}' have been successfully deleted from the Cisco Catalyst Center
                    and their deletion has been verified.""".format(itsm_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that ITSM Integration setting with
                        name '{0}' deletion task may not have executed successfully.""".format(itsm_name), "INFO")
        if config.get("webhook_event_notification"):
            webhook_notification_details = self.want.get("webhook_event_notification")
            web_notification_name = webhook_notification_details.get("name")
            if not self.have.get("webhook_subscription_notifications"):
                self.status = "success"
                msg = """Requested Webhook Events Subscription Notification '{0}' have been successfully deleted from the Cisco Catalyst Center
                    and their deletion has been verified.""".format(web_notification_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Webhook Events Subscription Notification
                        with name '{0}' deletion task may not have executed successfully.""".format(web_notification_name), "INFO")
        if config.get("email_event_notification"):
            email_notification_details = self.want.get("email_event_notification")
            email_notification_name = email_notification_details.get("name")
            if not self.have.get("email_subscription_notifications"):
                self.status = "success"
                msg = """Requested Email Events Subscription Notification '{0}' have been successfully deleted from the Cisco Catalyst Center
                    and their deletion has been verified.""".format(email_notification_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Email Events Subscription Notification
                        with name '{0}' deletion task may not have executed successfully.""".format(email_notification_name), "INFO")
        if config.get("syslog_event_notification"):
            syslog_notification_details = self.want.get("syslog_event_notification")
            syslog_notification_name = syslog_notification_details.get("name")
            if not self.have.get("syslog_subscription_notifications"):
                self.status = "success"
                msg = """Requested Syslog Events Subscription Notification '{0}' have been successfully deleted from the Cisco Catalyst Center
                    and their deletion has been verified.""".format(syslog_notification_name)
                self.log(msg, "INFO")
            else:
                self.log("""Playbook's input does not match with Cisco Catalyst Center, indicating that Syslog Events Subscription Notification
                        with name '{0}' deletion task may not have executed successfully.""".format(syslog_notification_name), "INFO")
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
    if ccc_events.compare_dnac_versions(ccc_events.get_ccc_version(), "2.3.5.3") < 0:
        ccc_events.msg = (
            "The specified version '{0}' does not support the events and notifications workflow. "
            "Supported versions start from '2.3.5.3' onwards."
            .format(ccc_events.get_ccc_version())
        )
        ccc_events.set_operation_result("failed", False, ccc_events.msg, "ERROR").check_return_status()
    config_verify = ccc_events.params.get("config_verify")
    for config in ccc_events.validated_config:
        ccc_events.reset_values()
        ccc_events.get_want(config).check_return_status()
        ccc_events.get_have(config).check_return_status()
        ccc_events.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_events.verify_diff_state_apply[state](config).check_return_status()
    # Invoke the API to check the status and log the output of each destination and notification on the console
    ccc_events.update_destination_notification_messages().check_return_status()
    module.exit_json(**ccc_events.result)
if __name__ == '__main__':
    main()
