# !/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Madhan Sankaranarayanan, Syed Khadeer Ahmed")

DOCUMENTATION = r"""
---
module: application_policy_workflow_manager
short_description: Resource module for managing application policies in Cisco Catalyst Center.
description:
  - Provides functionality to create, update, and delete applications, application sets, queuing profiles, and application policies in Cisco Catalyst Center.
  - Supports managing queuing profiles and application policies for traffic classification and prioritization.

version_added: "6.29.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Syed Khadeer Ahmed (@syed-khadeerahmed)
  - Madhan Sankaranarayanan (@madhansansel)

options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center after applying the playbook config.
    type: bool
    default: True
  state:
    description: The desired state of the configuration after module execution.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: A list of dictionaries containing application queuing profile details.
    type: list
    elements: dict
    required: true
    suboptions:
      application_queuing_details:
        description: Defines queuing profile settings for applications.
        type: list
        elements: dict
        suboptions:
          profile_name:
            description:
              - Name of the queuing profile.
              - Required for create, update, and delete operations.
            type: str
          new_profile_name:
            description: New name for the queuing profile (used for updates).
            type: str
          profile_description:
            description: Description of the queuing profile.
            type: str
          bandwidth_settings:
            description: Specifies bandwidth allocation details.
            type: dict
            suboptions:
              is_common_between_all_interface_speeds:
                description: Indicates whether bandwidth settings apply uniformly across all interface speeds.
                type: bool
              interface_speed_bandwidth_clauses:
                description: Defines bandwidth allocation for different types of network traffic based on interface speed.
                type: list
                elements: dict
                suboptions:
                  interface_speed:
                    description: |
                      - Specifies the data transfer rate of a network interface.
                      - Permissible values:
                        - "ALL": Applies to all interface speeds.
                        - "HUNDRED_GBPS": 100 Gbps.
                        - "TEN_GBPS": 10 Gbps.
                        - "ONE_GBPS": 1 Gbps.
                        - "HUNDRED_MBPS": 100 Mbps.
                        - "TEN_MBPS": 10 Mbps.
                        - "ONE_MBPS": 1 Mbps.
                    type: str
                  bandwidth_percentages:
                    description: Specifies the percentage of bandwidth allocated to different traffic categories.
                    type: dict
                    suboptions:
                      transactional_data:
                        description: Bandwidth allocated to transactional data traffic.
                        type: str
                      best_effort:
                        description: Bandwidth for non-priority, general-purpose traffic.
                        type: str
                      voip_telephony:
                        description: Bandwidth for voice and video calls over IP.
                        type: str
                      multimedia_streaming:
                        description: Bandwidth for real-time audio and video streaming.
                        type: str
                      real_time_interactive:
                        description: Bandwidth for low-latency applications requiring immediate response.
                        type: str
                      multimedia_conferencing:
                        description: Bandwidth for combined audio-video conferencing traffic.
                        type: str
                      signaling:
                        description: Bandwidth for network control messages managing communication sessions.
                        type: str
                      scavenger:
                        description: Bandwidth for low-priority traffic that can be delayed or dropped.
                        type: str
                      ops_admin_mgmt:
                        description: Bandwidth for operations and administration management traffic.
                        type: str
                      broadcast_video:
                        description: Bandwidth for one-to-many video distribution.
                        type: str
                      network_control:
                        description: Bandwidth for traffic related to network management and operation.
                        type: str
                      bulk_data:
                        description: Bandwidth for large-volume, non-time-sensitive data transfers.
                        type: str
          dscp_settings:
            description: Specifies the DSCP (Differentiated Services Code Point) values assigned to different traffic categories.
            type: list
            elements: dict
            suboptions:
              transactional_data:
                description: DSCP value for transactional data traffic, involving data exchanges between systems.
                type: str
              best_effort:
                description: DSCP value for best-effort traffic, which does not require specific quality or priority guarantees.
                type: str
              voip_telephony:
                description: DSCP value for voice and video calls transmitted over IP networks.
                type: str
              multimedia_streaming:
                description: DSCP value for real-time audio and video streaming traffic.
                type: str
              real_time_interactive:
                description: DSCP value for interactive applications requiring low latency and immediate responsiveness.
                type: str
              multimedia_conferencing:
                description: DSCP value for multimedia conferencing traffic, including both audio and video communication.
                type: str
              signaling:
                description: DSCP value for signaling traffic used to establish, manage, and terminate communication sessions.
                type: str
              scavenger:
                description: DSCP value for low-priority traffic that can be delayed or dropped in case of congestion.
                type: str
              ops_admin_mgmt:
                description: DSCP value for operations, administration, and management traffic.
                type: str
              broadcast_video:
                description: DSCP value for broadcast video traffic, typically distributed in a one-to-many model.
                type: str
              network_control:
                description: DSCP value for network control traffic related to management and operation.
                type: str
              bulk_data:
                description: DSCP value for large-volume data transfers that can tolerate delays or interruptions.
                type: str
      application_set_details:
        description:
          - Defines a logical grouping of network applications that share common policies and configuration settings.
          - Application sets enable network administrators to manage and apply policies to multiple applications simultaneously, 
          streamlining policy enforcement, monitoring, and optimization.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Specifies the name of the application set.
              - Required for deleting an application set.
            type: str
      application_details:
        description:
          - Defines individual applications within an application set that share a common purpose or function.
          - Grouping similar applications into sets allows administrators to apply uniform policies efficiently.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Specifies the name of the application.
              - Required for create, update, and delete operations.
            type: str
          description:
            description: A brief description of the application.
            type: str
          help_string:
            description: Provides the purpose or intended use of the application.
            type: str
          type:
            description: |
              - Specifies how the application is identified within the network.
              - Permissible values:
                - server_name: Custom application identified by server name.
                - url: Custom application identified by URL.
                - server_ip: Custom application identified by server IP address.
            type: str
          server_name:
            description: Required if `type` is `server_name`; specifies the server name for application identification.
            type: str
          dscp:
            description:
              - Required if `type` is `server_ip`; specifies DSCP value or `network_identity` details for the application.
              - DSCP value must be in the range 0 - 63.
            type: str
          network_identity:
            description: Required if `type` is `server_ip`; defines network-related parameters for application identification.
            type: list
            elements: dict
            suboptions:
              protocol:
                description: Specifies the network protocol used by the application.
                type: str
              port:
                description: Specifies the communication port number for the application.
                type: str
              ip_subnet:
                description: List of IP addresses or subnets associated with the application.
                type: list
                elements: str
              lower_port:
                description: Specifies the lower range of ports for network communication.
                type: str
              upper_port:
                description: Specifies the upper range of ports for network communication.
                type: str
          app_protocol:
            description: |
              - Required if `type` is `url` or `server_ip`; specifies the protocol used by the application.
              - If `type` is `url`, `app_protocol` must be `TCP`.
              - Permissible values:
                - 'TCP': Transmission Control Protocol (reliable, connection-oriented).
                - 'UDP': User Datagram Protocol (fast, connectionless, no guaranteed delivery).
                - 'TCP_UDP': Supports both TCP and UDP communication.
                - 'IP': Internet Protocol for network addressing and routing.
            type: str
          url:
            description: Required if `type` is `url`; specifies the URL for application identification.
            type: str
          traffic_class:
            description: |
              - Defines traffic prioritization based on network policies, ensuring critical applications receive the required bandwidth.
              - Permissible values:
                  - "BROADCAST_VIDEO": Video traffic broadcasted to multiple recipients.
                  - "BULK_DATA": Large data transfers like file uploads or backups.
                  - "MULTIMEDIA_CONFERENCING": Audio and video traffic for conferencing.
                  - "MULTIMEDIA_STREAMING": Streaming video or audio content.
                  - "NETWORK_CONTROL": Traffic for managing and controlling network infrastructure.
                  - "OPS_ADMIN_MGMT": Traffic for network operational and administrative tasks.
                  - "REAL_TIME_INTERACTIVE": Low-latency traffic for real-time interactive applications.
                  - "SIGNALING": Control traffic for setting up and managing sessions (e.g., VoIP).
                  - "TRANSACTIONAL_DATA": Data related to transactions, like financial or retail operations.
                  - "VOIP_TELEPHONY": Voice traffic over IP networks.
                  - "BEST_EFFORT": Non-critical traffic delivered on a best-effort basis.
                  - "SCAVENGER": Low-priority traffic, often background tasks.
            type: str
          ignore_conflict:
            description: Flag to indicate whether to ignore conflicts during configuration.
            type: str
          rank:
            description: Specifies the priority ranking of the application.
            type: str
          engine_id:
            description: Identifier for the engine managing the application.
            type: str
          application_set_name:
            description: Specifies the application set under which this application is created.
            type: str
      application_policy_details:
        description: Defines how an application's traffic is managed and prioritized within a network.
        type: list
        elements: dict
        suboptions:
          name:
            description: Name of the application policy
            type: str
          application_set_name:
            description:
              - The application sets to be removed from the application policy.
              - Only the specified sets will be removed.
              - Applicable only when the policy is in the deleted state.
            type: str
          policy_details:
            description: |
              - Represents the current status of the application policy.
              - Helps track whether the policy is active, deleted, or restored.
              - Permissible values:
                  - "NONE": The policy is active and in its original, operational state.
                  - "DELETED": The policy has been removed and is no longer active.
                  - "RESTORED": The policy has been reactivated after being deleted.
            type: str
          site_name:
            description: The site or area within the network where the policy should be enforced.
            type: str
          device_type:
            description: Indicates whether the device is wired or wireless.
            type: list
            elements: dict
            suboptions:
              device_ip:
                description:
                  - Required if the device type is wireless.
                  - The IP address assigned to the device for network communication.
                type: str
              wlan_id:
                description:
                  - Required if the device type is wireless.
                  - The WLAN ID associated with the device for traffic segmentation.
                type: str
          application_queuing_profile_name:
            description: Defines rules for traffic management by prioritizing network traffic within the application policy.
            type: str
          clause:
            description: Defines specific rules or conditions under which an application set is added to the application policy.
            type: list
            elements: dict
            suboptions:
              clause_type:
                description: |
                  - Specifies the type of clause for the application policy.
                  - Permissible values:
                    - "BUSINESS_RELEVANCE": Defines the importance of the application to business operations, affecting its priority and
                    handling in the network policy.
                    - "APPLICATION_POLICY_KNOBS": Configurable settings that manage the application's network behavior, such as traffic prioritization and resource allocation.
                type: str
              relevance_details:
                description: Details about how relevant the application is to business operations.
                type: list
                elements: dict
                suboptions:
                  relevance:
                    description: |
                      - Specifies whether the application set is relevant to the application policy.
                      - Permissible values:
                        - "BUSINESS_RELEVANT": The application is critical for business functions.
                        - "BUSINESS_IRRELEVANT": The application is not essential for business operations.
                        - "DEFAULT": A default setting when no specific relevance is assigned.
                    type: str
                  application_set_name:
                    description: Include all the application sets for which the application policy has to be created
                    type: str
requirements:
- dnacentersdk >= 2.9.3
- python >= 3.9.19
notes:
- SDK Methods used are
  - application_policy.ApplicationPolicy.get_application_policy
  - application_policy.ApplicationPolicy.application_policy_intent
  - application_policy.ApplicationPolicy.get_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.update_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.create_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.delete_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.get_application_sets
  - application_policy.ApplicationPolicy.create_application_set
  - application_policy.ApplicationPolicy.delete_application_set
  - application_policy.ApplicationPolicy.get_applications
  - application_policy.ApplicationPolicy.create_application
  - application_policy.ApplicationPolicy.update_application
  - application_policy.ApplicationPolicy.delete_application

- Paths used are
  - GET/dna/intent/api/v1/app-policy
  - POST/dna/intent/api/v1/app-policy-intent
  - GET/dna/intent/api/v1/app-policy-queuing-profile
  - POST/dna/intent/api/v1/app-policy-queuing-profile
  - PUT/dna/intent/api/v1/app-policy-queuing-profile
  - DELETE/dna/intent/api/v1/app-policy-queuing-profile/{id}
  - GET/dna/intent/api/v1/application-policy-application-set
  - POST//dna/intent/api/v1/application-policy-application-set
  - DELETE/dna/intent/api/v2/application-policy-application-set/{id}
  - GET/dna/intent/api/v2/applications
  - POST/dna/intent/api/v2/applications
  - PUT/dna/intent/api/v1/applications
  - DELETE/dna/intent/api/v2/applications/{id}
"""

EXAMPLES = r"""
---
#Playbook - application queuing profile - type both ("bandwidth", "dscp")

- name: Create Enterprise QoS Profile for Optimized Network Performance
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Create Enterprise QoS Profile for Optimized Network Performance
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_queuing_details:
              - profile_name: "Enterprise-QoS-Profile"
                profile_description: "QoS profile optimized for business-critical applications"
                bandwidth_settings:
                  is_common_between_all_interface_speeds: true
                  interface_speed: "ALL"
                  bandwidth_percentages:
                      transactional_data: "5"
                      best_effort: "10"
                      voip_telephony: "15"
                      multimedia_streaming: "10"
                      real_time_interactive: "20"
                      multimedia_conferencing: "10"
                      signaling: "10"
                      scavenger: "5"
                      ops_admin_mgmt: "5"
                      broadcast_video: "2"
                      network_control: "3"
                      bulk_data: "5"
                dscp_settings:
                multimedia_conferencing: "20"
                ops_admin_mgmt: "23"
                transactional_data: "28"
                voip_telephony: "45"
                multimedia_streaming: "27"
                broadcast_video: "46"
                network_control: "48"
                best_effort: "0"
                signaling: "4"
                bulk_data: "10"
                scavenger: "2"
                real_time_interactive: "34"


#Playbook - Enterprise QoS Profile (Common Across All Interface Speeds) 

- name: Deploy Enterprise QoS Profile in Cisco Catalyst Center 
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Configure Enterprise QoS Profile for Consistent Traffic Prioritization
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_queuing_details:
              - profile_name: "Enterprise-QoS-All-Speeds"
                profile_description: "Optimized QoS profile for consistent traffic prioritization across all interface speeds"
                bandwidth_settings:
                  is_common_between_all_interface_speeds: true
                  interface_speed: "ALL"
                  bandwidth_percentages:
                      transactional_data: "5"
                      best_effort: "10"
                      voip_telephony: "15"
                      multimedia_streaming: "10"
                      real_time_interactive: "20"
                      multimedia_conferencing: "10"
                      signaling: "10"
                      scavenger: "5"
                      ops_admin_mgmt: "5"
                      broadcast_video: "2"
                      network_control: "3"
                      bulk_data: "5"

# Playbook - QoS Profile Based on Interface Speeds

---
- name: Deploy Interface-Specific QoS Profile in Cisco Catalyst Center
  hosts: localhost
  vars_files:
    - "credentials.yml"
  connection: local
  gather_facts: no
  tasks:
    - name: Configure QoS Profile for Different Interface Speeds
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{dnac_host}}"
        dnac_username: "{{dnac_username}}"
        dnac_password: "{{dnac_password}}"
        dnac_verify: "{{dnac_verify}}"
        dnac_port: "{{dnac_port}}"
        dnac_version: "{{dnac_version}}"
        dnac_debug: "{{dnac_debug}}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_queuing_details:
              - profile_name: "Enterprise-Speed-Based-QoS"
                profile_description: "Optimized traffic prioritization based on interface speed"
                bandwidth_settings:
                  is_common_between_all_interface_speeds: false
                  interface_speed_settings:
                    - interface_speed: "HUNDRED_GBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "10"
                        voip_telephony: "20"
                        multimedia_streaming: "5"
                        real_time_interactive: "20"
                        multimedia_conferencing: "10"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"
                    - interface_speed: "TEN_GBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "5"
                        voip_telephony: "25"
                        multimedia_streaming: "5"
                        real_time_interactive: "20"
                        multimedia_conferencing: "5"
                        signaling: "4"
                        scavenger: "6"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "15"
                    - interface_speed: "ONE_GBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "10"
                        voip_telephony: "15"
                        multimedia_streaming: "10"
                        real_time_interactive: "20"
                        multimedia_conferencing: "10"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"
                    - interface_speed: "HUNDRED_MBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "10"
                        voip_telephony: "5"
                        multimedia_streaming: "15"
                        real_time_interactive: "25"
                        multimedia_conferencing: "10"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"
                    - interface_speed: "TEN_MBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "10"
                        voip_telephony: "15"
                        multimedia_streaming: "10"
                        real_time_interactive: "20"
                        multimedia_conferencing: "10"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"
                    - interface_speed: "ONE_MBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "5"
                        voip_telephony: "25"
                        multimedia_streaming: "10"
                        real_time_interactive: "20"
                        multimedia_conferencing: "5"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"

#Playbook - for some interface speeds having common bandwidth percentage

- name: Configure an Application Queueing Profile for Traffic Prioritization
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Create an Application Queueing Profile for Traffic Prioritization
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_queuing_details:
              - profile_name: "Enterprise_Traffic_Policy"
                profile_description: "Queueing profile for optimizing enterprise application traffic."
                bandwidth_settings:
                  is_common_between_all_interface_speeds: false
                  interface_speed_settings:
                    - interface_speed: "HUNDRED_GBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "10"
                        voip_telephony: "20"
                        multimedia_streaming: "5"
                        real_time_interactive: "20"
                        multimedia_conferencing: "10"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"
                    - interface_speed: "TEN_GBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "5"
                        voip_telephony: "25"
                        multimedia_streaming: "5"
                        real_time_interactive: "20"
                        multimedia_conferencing: "5"
                        signaling: "6"
                        scavenger: "5"
                        ops_admin_mgmt: "4"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "15"
                    - interface_speed: "HUNDRED_MBPS"
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "10"
                        voip_telephony: "5"
                        multimedia_streaming: "15"
                        real_time_interactive: "25"
                        multimedia_conferencing: "10"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"
                    - interface_speed: TEN_MBPS,ONE_MBPS,ONE_GBPS
                      bandwidth_percentages:
                        transactional_data: "5"
                        best_effort: "10"
                        voip_telephony: "15"
                        multimedia_streaming: "10"
                        real_time_interactive: "20"
                        multimedia_conferencing: "10"
                        signaling: "10"
                        scavenger: "5"
                        ops_admin_mgmt: "5"
                        broadcast_video: "2"
                        network_control: "3"
                        bulk_data: "5"

#Playbook - application queuing profile - type dscp

- name: Configure Application Queuing Profile (DSCP) in Cisco Catalyst Center 
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Create an Application Queuing Profile with DSCP Settings
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_queuing_details:
              - profile_name: "Enterprise_DSCP_Profile"
                profile_description: "DSCP-based queuing profile for traffic prioritization."
                dscp_settings:
                  multimedia_conferencing: "20"
                  ops_admin_mgmt: "23"
                  transactional_data: "28"
                  voip_telephony: "45"
                  multimedia_streaming: "27"
                  broadcast_video: "46"
                  network_control: "48"
                  best_effort: "0"
                  signaling: "4"
                  bulk_data: "10"
                  scavenger: "2"
                  real_time_interactive: "34"

# Playbook - update application queuing profile

- name: Application Queuing Profile update in Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"  
  tasks:
    - name: Update Application Queuing Profile in Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_queuing_details:
              - profile_name: "Enterprise_Traffic_Profile" # Existing profile to be updated
	              new_profile_name: "Enterprise_Traffic_Profile_v2"  # New profile name after update
                profile_description: "Traffic queuing profile for enterprise applications."
	              new_profile_description: "Updated queuing profile for optimized traffic management."
                bandwidth_settings:
                  is_common_between_all_interface_speeds: true
                  interface_speed: "ALL"
                  bandwidth_percentages:
                      transactional_data: "5"
                      best_effort: "10"
                      voip_telephony: "15"
                      multimedia_streaming: "10"
                      real_time_interactive: "20"
                      multimedia_conferencing: "10"
                      signaling: "10"
                      scavenger: "5"
                      ops_admin_mgmt: "5"
                      broadcast_video: "2"
                      network_control: "3"
                      bulk_data: "5"
                dscp_settings:
                  multimedia_conferencing: "20"
                  ops_admin_mgmt: "23"
                  transactional_data: "28"
                  voip_telephony: "45"
                  multimedia_streaming: "27"
                  broadcast_video: "46"
                  network_control: "48"
                  best_effort: "0"
                  signaling: "4"
                  bulk_data: "10"
                  scavenger: "2"
                  real_time_interactive: "34"

#Playbook - delete application queuing profile

- name: Delete application queuing profile from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Delete application queuing profile from Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: deleted
        config:
          - application_queuing_details:
              - profile_name: "Enterprise_Traffic_Profile"  # Profile to be deleted

#Playbook - create application - type server_name

- name: Create application on Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Create Application with Server Name on Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
           - application_details:
                name: "Security_Gateway_App"
                help_string: "Application for network security and access control"
                description: "Security Gateway Application"
                type: "server_name"
                server_name: "www.securitygateway.com"
                traffic_class: "BROADCAST_VIDEO"
                ignore_conflict: "true"
                rank: 23
                engineId: 4
                application_set_name: "Security_Gateway_Set"

#Playbook - create application - type server_ip

- name: Create application on Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Create application with Server IP on Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_details:
              name: "Security_Gateway_IP_App"
              help_string: "Security Gateway Application based on IP"
              description: "Defines security gateway policies using server IPs"
              type: "server_ip"
              network_identity_setting:
                protocol: "UDP"
                port: "2000"
                ip_subnet: ["1.1.1.1","2.2.2.2","3.3.3.3"]
                lower_port: 10
                upper_port: 100
              dscp: 2
              traffic_class: "BROADCAST_VIDEO"
              ignore_conflict: "true"
              rank: "23"
              engine_id: "4"
              application_set_name: "Security_Gateway_Set"

#Playbook - create application - type url

- name: Define and Register Application in Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Create Application with URL Type in Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_details:
              name: "video_streaming_app"
              help_string: "Manages video streaming application traffic"
              description: "Defines security gateway policies using server urls"
              type: "url"
              app_protocol: "TCP"
              url: "www.securitygateway.com"
              traffic_class: "BROADCAST_VIDEO"
              ignore_conflict: true
              rank: "23"
              engine_id: "4"
              application_set_name: "local-services"

#Playbook - delete application

- name: Delete application from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Delete Video Streaming Application from Cisco Catalyst Center
      cisco.dnac.sample_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: deleted
        config:
          - application_details:
              name: "video_streaming_app"


#Playbook - create application policy – wired

- name: Create Wired Application Policy in Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"  
  tasks:
    - name: Define and Deploy Wired Application Policy
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_policy_details:
              name: "WiredTrafficOptimizationPolicy"
              policy_status: "deployed"                                   
              site_name: ["Global/INDIA"]     
              device_type: "wired"
              application_queuing_profile_name: "WiredStreamingQueuingProfile"      
              clause: 
                - clause_type: "BUSINESS_RELEVANCE"                              
                  relevance_details:                            
                    - relevance: "BUSINESS_RELEVANT"                            
                      application_set_name: ["collaboration-apps"]
                    - relevance: "BUSINESS_IRRELEVANT"                            
                      application_set_name: ["email","tunneling"]
                    - relevance: "DEFAULT"                            
                      application_set_name: ["backup-and-storage", "general-media", "file-sharing"]

#Playbook - create application policy – wireless

- name: Create Wireless Application Policy in Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"  
  tasks:
    - name: Define and Deploy Wireless Application Policy
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_policy_details:
              name: "wireless_traffic_optimization_policy"
              policy_status: "deployed"                                   
              site_name: ["global/Chennai/FLOOR1"]     
              device_type: "wireless"     
              device:            
                device_ip: "204.1.2.3"
                wlan_id: "17"
              application_queuing_profile_name: "sample_queuing_profile"      
              clause: 
                - clause_type: “BUSINESS_RELEVANCE"                              
                  relevance_details:                            
                    - relevance: "BUSINESS_RELEVANT"                            
                      application_set_name: ["file-sharing"]
                    - relevance: "BUSINESS_IRRELEVANT"                            
                      application_set_name: ["email","backup-and-storage"]
                    - relevance: "DEFAULT"                            
                      application_set_name: ["collaboration-apps","tunneling", "general-media"]

#Playbook - delete application policy

- name: Delete Application Policy from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
  - name: Delete application policy from Cisco Catalyst Center
    cisco.dnac.application_policy_workflow_manager:
      dnac_host: "{{ dnac_host }}"
      dnac_username: "{{ dnac_username }}"
      dnac_password: "{{ dnac_password }}"
      dnac_verify: "{{ dnac_verify }}"
      dnac_port: "{{ dnac_port }}"
      dnac_version: "{{ dnac_version }}"
      dnac_debug: "{{ dnac_debug }}"
      dnac_log: True
      dnac_log_level: DEBUG
      config_verify: True
      dnac_api_task_timeout: 1000
      dnac_task_poll_interval: 1
      state: deleted
      config:
        - application_policy_details:
            name: "ObsoleteTrafficPolicy"
"""

RETURN = r"""

# Case 1: Successful creation of application queuing profile

creation_of_application_queuing_profile_response_task_tracking:
  description: A dictionary containing task tracking details such as task ID and URL from the Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

creation _of_application_queuing_profile_response_task_execution:
  description: A dictionary with additional details for successful task execution, including progress and data.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str"
      },
      "version": "str"
    }


# Case 2: Successful updation of application queuing profile

updation_of_application_queuing_profile_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

updation_of_application_queuing_profile_response_task_execution:
  description: With task id get details for successfull updation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 3: Successful deletion of application queuing profile

deletion_of_application_queuing_profile_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
deletion_of_application_queuing_profile_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 4: Error during application queuing profile (create/update/delete)

error_during_application_queuing_profile_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_queuing_profile_response_task_execution:
  description: With task id get details for error during application queuing profile (create/update/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 5: Application queuing profile not found (during delete operation)

application_queuing_profile_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_queuing_profile_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }


# Case 6: Successful creation of application set

successful_creation_of_application_set_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_creation_of_application_set_response_task_execution:
  description: With task id get details for successfull creation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 7: Successful deletion of application set

successful_deletion_of_application set_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_deletion_of_application_set_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 8: Error during application set operation (create/delete)

error_during_application_set_operation_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_set_operation_response_task_execution:
  description: With task id get details for error during application set (create/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 9: Application set not found (during delete operation)

application_set_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_set_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 10: Successful creation of application

successful_creation_of_application_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_creation_of_application_response_task_execution:
  description: With task id get details for successfull creation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 11: Successful updation of application

successful updation_of_application_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_updation_of_application_response_task_execution:
  description: With task id get details for successfull updation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 12: Successful deletion of application

deletion_of_application_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

deletion_of_application_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 13: Error during application operation (create/update/delete)

error_during_application_operation_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_operation_response_task_execution:
  description: With task id get details for error during application (create/update/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 14: Application not found (during delete operation)

application_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 15: Successful creation of application policy

successful_creation_of_application_policy_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_creation_of_application_policy_response_task_execution:
  description: With task id get details for successfull creation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

#Case 16: Successful updation of application policy

successful_updation_of_application_policy_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_updation_of_application_policy_response_task_execution:
  description: With task id get details for successfull updation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 17: Successful deletion of application policy

successful_deletion_of_application_policy_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_deletion_of_application_policy_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 18: Error during application policy operation(create/update/delete)

error_during_application_policy_operation_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_policy_operation_response_task_execution:
  description: With task id get details for error during application policy(create/update/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 19: Application policy not found (during delete operation)

application_policy_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_policy_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }
"""

from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
from ansible.module_utils.basic import AnsibleModule
import json

# Defer this feature as API issue is there once it's fixed we will addresses it in upcoming release
support_for_application_set = False


class ApplicationPolicy(DnacBase):
    """Class containing member attributes for application_policy_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Args:
        - self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
        The method returns an instance of the class with updated attributes:
        - self.msg: A message describing the validation result.
        - self.status: The status of the validation (either 'success' or 'failed').
        - self.validated_config: If successful, a validated version of 'config' parameter.

        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
        If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
        will contain the validated configuration. If it fails, 'self.status' will be 'failed',
        'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.msg = "Configuration is not available in the playbook for validation"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        if not isinstance(self.config, list):
            self.msg = "Config should be a list, found: {0}".format(type(self.config))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        config_data = self.config[0] if self.config else {}

        application_queuing_details = config_data.get('application_queuing_details', [])
        if not isinstance(application_queuing_details, list):
            self.msg = "'application_queuing_details' should be a list, found: {0}".format(type(application_queuing_details))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        application_set_details = config_data.get('application_set_details', [])
        if not isinstance(application_set_details, list):
            self.msg = "'application_set_details' should be a list, found: {0}".format(type(application_set_details))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        application_details = config_data.get('application_details', {})
        if not isinstance(application_details, dict):
            self.msg = "'application_details' should be a dict, found: {0}".format(type(application_details))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        application_policy_details = config_data.get('application_policy_details', {})
        self.log(application_policy_details)
        if not isinstance(application_policy_details, dict):
            self.msg = "'application_policy_details' should be a dict, found: {0}".format(type(application_policy_details))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        for item in application_queuing_details:
            if not isinstance(item, dict):
                self.msg = "Each item in 'application_queuing_details' should be a dictionary, found: {0}".format(type(item))
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self
        self.validated_config = self.config

        config_spec = {
            'application_details': {
                'type': 'dict',
                'elements': {
                    'name': {'type': 'str'},
                    'description': {'type': 'str'},
                    'help_string': {'type': 'str'},
                    'type': {'type': 'str'},
                    'server_name': {'type': 'str'},
                    'traffic_class': {'type': 'str'},
                    'ignore_conflict': {'type': 'bool'},
                    'rank': {'type': 'str'},
                    'engine_id': {'type': 'str'},
                    'application_set_name': {'type': 'str'},
                },
            },
            'application_queuing_details': {
                'type': 'list',
                'elements': 'dict',
                'profile_name': {'type': 'str'},
                'new_profile_name': {'type': 'str'},
                'profile_description': {'type': 'str'},
                'bandwidth_settings': {
                    'type': 'dict',
                    'elements': 'dict',
                    'is_common_between_all_interface_speeds': {'type': 'bool'},
                    'interface_speed': {'type': 'str'},
                    'bandwidth_percentages': {
                        'type': 'dict',
                        'elements': 'dict',
                        'transactional_data': {'type': 'str'},
                        'best_effort': {'type': 'str'},
                        'voip_telephony': {'type': 'str'},
                        'multimedia_streaming': {'type': 'str'},
                        'real_time_interactive': {'type': 'str'},
                        'multimedia_conferencing': {'type': 'str'},
                        'signaling': {'type': 'str'},
                        'scavenger': {'type': 'str'},
                        'ops_admin_mgmt': {'type': 'str'},
                        'broadcast_video': {'type': 'str'},
                        'network_control': {'type': 'str'},
                        'bulk_data': {'type': 'str'},
                    },
                },
                'dscp_settings': {
                    'type': 'dict',
                    'elements': 'dict',
                    'multimedia_conferencing': {'type': 'str'},
                    'ops_admin_mgmt': {'type': 'str'},
                    'transactional_data': {'type': 'str'},
                    'voip_telephony': {'type': 'str'},
                    'multimedia_streaming': {'type': 'str'},
                    'broadcast_video': {'type': 'str'},
                    'network_control': {'type': 'str'},
                    'best_effort': {'type': 'str'},
                    'signaling': {'type': 'str'},
                    'bulk_data': {'type': 'str'},
                    'scavenger': {'type': 'str'},
                    'real_time_interactive': {'type': 'str'},
                },

            },
            'application_policy_details': {
                'type': 'dict',
                'element': 'dict',
                'name': {'type': 'str'},
                'policy_status': {'type': 'str'},
                'site_name': {'type': 'list', 'elements': 'str'},
                'device_type': {'type': 'str'},
                'device': {
                    'type': 'dict',
                    'element': 'dict',
                    'device_ip': {'type': 'str'},
                    'Wlan_id': {'type': 'str'},
                },
                'application_queuing_profile_name': {'type': 'str'},
                'clause': {
                    'type': 'list',
                    'element': 'dict',
                    'clause_type': {'type': 'str'},
                    'relevance_details': {
                        'type': 'list',
                        'element': 'dict',
                        'relevance': {'type': 'str'},
                        'application_set_name': {'type': 'list', 'elements': 'str'},
                    },
                },
            },
        }

        self.log(json.dumps(self.config, indent=4))

        # Validate the input configuration
        valid_config, invalid_params = validate_list_of_dicts(
            self.config, config_spec
        )

        if invalid_params:
            self.log("Invalid configuration parameters: {}".format(invalid_params))
        else:
            self.log("Configuration validated successfully: {}".format(valid_config))

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        return self

    def get_want(self, config):
        """
        Retrieve and store details from the playbook configuration related to application queuing, application, application set and application policies.

        Args:
            self (object): An instance of a class interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the playbook configuration with details for 
                           application queuing, application, application set and application policies.

        Returns:
            self: The current instance of the class with updated 'want' attributes, including 
                  application-related configurations.

        Description:
            This function extracts the following details from the provided configuration:
            - application_queuing_details
            - application_set_details
            - application_details
            - application_policy_details
            
            These details are stored in the 'want' attribute of the instance for future use.

        """

        want = {}
        want["application_queuing_details"] = config.get("application_queuing_details")
        want["application_set_details"] = config.get("application_set_details")
        want["application_details"] = config.get("application_details")
        want["application_policy_details"] = config.get("application_policy_details")

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_queuing_profile_details(self, name):
        """
        Retrieves the details of an application queuing profile by its name.

        Description:
            This method queries the Cisco Catalyst Center API to check if a queuing profile with the specified name exists.
            It fetches the profile details if available. If the profile does not exist or an error occurs, the method logs
            the issue and returns default values indicating that the profile was not found.

        Args:
            name (str): The name of the queuing profile to retrieve.

        Returns:
            tuple: A tuple containing:
                - queuing_profile_exists (bool): Indicates whether the queuing profile exists.
                - current_queuing_profile (dict): A dictionary containing the details of the queuing profile, or an
                empty dictionary if the profile does not exist.

        Raises:
            Exception: Logs the error and updates the status if an API call fails or an unexpected issue occurs.
        """

        queuing_profile_exists = False
        current_queuing_profile = {}

        try:
            params = dict(name=name)
            response = self.dnac._exec(
                family="application_policy",
                function='get_application_policy_queuing_profile',
                params=params
            )
            self.log("Received API response from 'get_application_policy_queuing_profile': {0}".format(str(response)), "DEBUG")

            if not response:
                self.msg = "No response received from get_application_policy_queuing_profile"
                self.set_operation_result("failed", False, self.msg, "ERROR")

            if not response.get("response"):
                self.log("Empty response {0}".format(response))
                return queuing_profile_exists, current_queuing_profile

            current_queuing_profile = response.get("response")
            queuing_profile_exists = True
            self.log("Got the details for queuing_profile_exists: {0} and current_queuing_profile: {1}".format(queuing_profile_exists, current_queuing_profile))
            return queuing_profile_exists, current_queuing_profile

        except Exception as e:
            self.msg = "Error occured while getting queuing profile: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_application_set_details(self, name):
        """
        Retrieves the details of an application set by its name.
        Description:
            This method queries the Cisco Catalyst Center API to determine if an application set with the specified
            name exists. It fetches the details of the application set if available. If the application set does not
            exist or an error occurs, the method logs the issue and either raises an exception or returns default values
            indicating that the application set was not found.

        Args:
            name (str): The name of the application set to retrieve.

        Returns:
            tuple: A tuple containing:
                - application_set_exists (bool): Indicates whether the application set exists.
                - current_application_set (dict): A dictionary containing the details of the application set, or an
                empty dictionary if the application set does not exist.

        Raises:
            Exception: If the API response is unexpected or indicates failure, an exception is raised, and the
            status is updated to "failed".
        """

        application_set_exists = False
        current_application_set = {}
        try:

            response = self.dnac._exec(
                family="application_policy",
                function='get_application_sets',
                params={"name": name}
            )
            self.log("Received API response from 'get_application_sets': {0}".format(str(response)), "DEBUG")

            if not response:
                self.msg = "No response received from get_application_sets"
                self.set_operation_result("failed", False, self.msg, "ERROR")

            if not response.get("response"):
                self.log("Empty response {0}".format(response))
                return application_set_exists, current_application_set

            current_application_set = response.get("response")
            application_set_exists = True
            self.log("Got the details for queuing_profile_exists: {0} and current_application_set: {1}".format(application_set_exists, current_application_set))
            return application_set_exists, current_application_set

        except Exception as e:
            self.msg = "An error occurred while retreiving the application set details: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_application_set_id(self, name):
        """
        Retrieves the details of an application set by its name.

        Description:
            This method queries the Cisco Catalyst Center API to determine if an application set with the specified
            name exists. It fetches the details of the application set if available. If the application set does not
            exist or an error occurs, the method logs the issue and either raises an exception or returns default values
            indicating that the application set was not found.

        Args:
            name (str): The name of the application set to retrieve.

        Returns:
            tuple: A tuple containing:
                - application_set_exists (bool): Indicates whether the application set exists.
                - current_application_set (dict): A dictionary containing the details of the application set, or an
                empty dictionary if the application set does not exist.

        Raises:
            Exception: If the API response is unexpected or indicates failure, an exception is raised, and the
            status is updated to "failed".
        """

        application_set_id = ''
        try:
            response = self.dnac._exec(
                family="application_policy",
                function='get_application_sets',
                params={"name": name}
            )
            self.log("Received API response from 'get_application_sets': {0}".format(str(response)), "DEBUG")

            if not response:
                self.msg = "No response received from get_application_sets"
                self.set_operation_result("failed", False, self.msg, "ERROR")

            if not response.get("response"):
                self.log("Empty response {0}".format(response))
                raise Exception("No application set found in the Cisco Catalyst Center")

            current_application_set = response.get("response")
            application_set_id = current_application_set[0].get('id')

        except Exception as e:
            self.msg = "An error occurred while retriving the application set details: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        return application_set_id

    def get_application_details(self, name):
        """
        Retrieve the details of a specific application by its name.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            name (str): The name of the application to retrieve.

        Returns:
            tuple: A tuple containing:
                - application_exists (bool): Indicates whether the application exists.
                - current_application (dict): The details of the application if found, otherwise an empty dictionary.

        Description:
            This function fetches the details of a specific application using the Cisco Catalyst Center API. It sends
            a request to retrieve the application data by specifying its name along with additional parameters for
            attributes, offset, and limit. If the response contains the application details, they are returned along
            with a flag indicating the existence of the application. In case of an error or unexpected response, the
            function logs the error, updates the status, and handles the exception gracefully.
        """
        application_exists = False
        current_application = {}
        try:

            response = self.dnac._exec(
                family="application_policy",
                function='get_applications',
                params={'attributes': "application", 'name': name, 'offset': 1, 'limit': 500}
            )
            self.log("Received API response from 'get_applications': {0}".format(str(response)), "DEBUG")

            if not response:
                self.msg = "No response received from get_applications"
                self.set_operation_result("failed", False, self.msg, "ERROR")

            if not response.get("response"):
                self.log("Empty response {0}".format(response))
                return application_exists, current_application

            current_application = response.get("response")
            application_exists = True
            self.log("Got the details for application_exists: {0} and current_application_set: {1}".format(application_exists, current_application))
            return application_exists, current_application

        except Exception as e:
            self.msg = "An error occurred while retreiving the application details: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_current_application_details(self):
        """
        Retrieve the details of applications from Cisco Catalyst Center.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.

        Returns:
            dict: A dictionary containing the details of the applications retrieved from Cisco Catalyst Center.

        Description:
            This function fetches the details of applications using the Cisco Catalyst Center API. It sends a request
            to retrieve application data with specified attributes, offset, and limit. If a response is received, it
            extracts the application details and logs the data. In case the response is empty, the function logs a
            message and returns an empty dictionary.
        """
        current_application = {}

        try:
            # Fetching application data
            response = self.dnac._exec(
                family="application_policy",
                function="get_applications",
                params={"attributes": "application", "offset": 1, "limit": 500}
            )

            self.log("Received API response from 'get_applications': {0}".format(response), "DEBUG")

            # Check if the response contains data
            if not response.get("response"):
                self.log("Empty response received: {0}".format(response))
                return current_application

            current_application = response.get("response")

            self.log(
                "Retrieved application details successfully. Application Data: {0}".format(current_application),
                "DEBUG"
            )
            return current_application

        except Exception as e:
            self.msg = "Error occurred while fetching application details: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_application_policy_details(self, name):
        """
        Get application policy details for the specified policy name.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            name (str): The name of the application policy to retrieve.

        Returns:
            tuple: A tuple containing:
                - application_policy_exists (bool): Indicates whether the application policy exists.
                - current_application_policy (dict): The details of the application policy if found, otherwise an empty dictionary.

        Description:
            This function interacts with the Cisco Catalyst Center API to retrieve the details of an application policy
            specified by its name. It sends an API request to fetch the policy details and processes the response.
            If the response contains the policy details, they are returned along with a flag indicating its existence.
            In case of an exception, the function updates the status and logs an appropriate error message.
        """
        application_policy_exists = False
        current_application_policy = {}
        try:

            response = self.dnac._exec(
                family="application_policy",
                function='get_application_policy',
                params={"policyScope": name}
            )
            self.log("Received API response from 'get_application_policy': {0}".format(str(response)), "DEBUG")

            if not response:
                self.msg = "No response received from get_application_policy"
                self.set_operation_result("failed", False, self.msg, "ERROR")
                

            if not response.get("response"):
                self.log("Empty response {0}".format(response))
                return application_policy_exists, current_application_policy

            current_application_policy = response.get("response")
            application_policy_exists = True
            self.log(
                "Got the details for queuing_profile_exists: {0} and current_application_policy: {1}"
                .format(application_policy_exists, current_application_policy)
            )
            return application_policy_exists, current_application_policy

        except Exception as e:
            self.msg = "{0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_have(self):
        """
            Retrieve and store the current configuration details of various Cisco Catalyst Center components based on user-provided data.

            Args:
                self (object): An instance of the class used for interacting with Cisco Catalyst Center.

            Returns:
                self: The current instance of the class, with the 'have' dictionary populated with current configuration details.

            Description:
                The method performs the following actions:
                - Checks for the existence of the specified application queuing profile and retrieves its details.
                - Verifies the existence of the application set and retrieves its details.
                - Validates the presence of an application policy and retrieves its details.
                - Retrieves details for the specified application and its associated application set.
                
                If any mandatory parameter is missing (e.g., profile name, application name), the method raises an error and 
                stops further execution. The retrieved configuration details are stored in the 'have' dictionary for future 
                reference and processing.
            """
            
        have = {}
        if self.want.get("application_queuing_details"):
            application_queuing_details = self.want.get("application_queuing_details")
            for detail in application_queuing_details:
                application_queuing_name = detail.get("profile_name")
                if not application_queuing_name:
                    self.msg = (
                        "The following parameter(s): 'profile_name' could not be found "
                        "and are mandatory to create or update application queuinig profile."
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                queuing_profile_exists, current_queuing_profile = self.get_queuing_profile_details(application_queuing_name)
                have["current_queuing_profile"] = current_queuing_profile
                have["queuing_profile_exists"] = queuing_profile_exists

        if self.want.get("application_set_details"):
            application_set_details = self.want.get("application_set_details")[0]
            if application_set_details.get("application_set_name"):
                application_set_name = application_set_details.get("application_set_name")
                application_set_exists, current_application_set = self.get_application_set_details(application_set_name)
                have["current_application_set"] = current_application_set
                have["application_set_exists"] = application_set_exists

        if self.want.get("application_policy_details"):
            application_policy_details = self.want.get("application_policy_details")
            application_policy_name = self.want.get("application_policy_details", {}).get("name")

            if not application_policy_name:
                self.msg = (
                    "The following parameter(s): 'name' could not be found  and are mandatory to create or update application policy ."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if application_policy_details.get("application_queuing_profile_name"):
                queuing_profile_name = application_policy_details.get("application_queuing_profile_name")
                queuing_profile_exists, current_queuing_profile = self.get_queuing_profile_details(queuing_profile_name)
                have["current_queuing_profile"] = current_queuing_profile
                have["queuing_profile_exists"] = queuing_profile_exists

                if not queuing_profile_exists:
                    self.msg = (
                        "The application queuing profile does not exist - {0} ".format(queuing_profile_name)
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if application_policy_details.get("name"):
                application_policy_name = application_policy_details.get("name")
                application_policy_exists, current_application_policy = self.get_application_policy_details(application_policy_name)
                have["current_application_policy"] = current_application_policy
                have["application_policy_exists"] = application_policy_exists

        if self.want.get("application_details"):
            application_details = self.want.get("application_details")
            self.log(application_details)
            application_name = application_details.get("name")

            if not application_name:
                self.msg = (
                    "The following parameter(s): 'name' could not be found  and are mandatory to create or update application ."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if application_details.get("name"):
                application_name = application_details.get("name")
                application_exists, current_application = self.get_application_details(application_name)
                have["current_application"] = current_application
                have["application_exists"] = application_exists

            if application_details.get("application_set_name"):
                application_set_name = application_details.get("application_set_name")
                application_set_exists, current_application_set = self.get_application_set_details(application_set_name)
                have["current_application_set"] = current_application_set
                have["application_set_exists"] = application_set_exists

        self.have = have
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        return self

    def get_diff_merged(self, config):
        """
            Retrieves application queuing details and triggers related tasks based on the configuration provided in the playbook.

            Args:
                self (object): An instance of the class used for interacting with Cisco Catalyst Center.
                config (dict): The configuration dictionary containing the details for application queuing, application sets,
                            applications, and application policies.

            Returns:
                self: The current instance of the class, with updated 'result' and 'have' attributes based on the task statuses.

            Description:
                This method processes the configuration details provided in the playbook. It checks for the presence of specific 
                configuration options, such as application queuing, application sets, applications, and application policies. 
                Based on the configuration, it sequentially triggers the corresponding tasks (like checking the status of 
                application queuing profile, application set, etc.).

                The method monitors the progress of each operation and updates the 'result' dictionary accordingly. If any task 
                is successful, the 'changed' attribute is set to True to indicate that a change was made during the operation.
            """

        self.config = config

        if config.get("application_queuing_details"):
            self.get_diff_queuing_profile().check_return_status()

        if support_for_application_set:
            if config.get("application_set_details"):
                self.get_diff_application_set().check_return_status()

        if config.get("application_details"):
            self.get_diff_application().check_return_status()

        if config.get("application_policy_details"):
            self.get_diff_application_policy().check_return_status()

        return self

    def is_update_required_for_application_policy(self):
        """
        Check if updates are required for the application policy and trigger necessary updates.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            bool:
                - True if updates are required for the application policy.
                - False if no updates are necessary.

        Description:
            This function evaluates whether updates are required for the application policy configuration in Cisco Catalyst Center
            based on the desired state provided in the configuration. It validates the existence of the application policy,
            identifies mismatches in queuing profiles and site mappings, and checks for missing application set names
            categorized as BUSINESS_RELEVANT, BUSINESS_IRRELEVANT, or DEFAULT.

            The function ensures the application policy aligns with the desired configuration while minimizing unnecessary updates.
        """

        application_policy_details = self.have

        # If application policy does not exist, create it and return
        if application_policy_details.get("application_policy_exists") is False:
            self.create_application_policy()
            return self

        req_application_policy_details = self.config.get("application_policy_details")
        application_queuing_profile_name = req_application_policy_details.get("application_queuing_profile_name")
        site_names = req_application_policy_details.get("site_name")
        site_ids = [self.get_site_id(site_name)[1] for site_name in site_names]
        current_application_policy = application_policy_details.get("current_application_policy")

        self.log(req_application_policy_details)

        # Flags to check if updates are required
        is_update_required_for_queuing_profile = any(
            application_queuing_profile_name not in contract.get("name")
            for contract in current_application_policy if contract.get('contract')
        )
        is_update_required_for_site = any(
            set(site_ids) != set(application_policy.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("groupId"))
            for application_policy in current_application_policy
        )

        # Logging the update status
        if is_update_required_for_queuing_profile:
            self.log("Update required for queuing profile")
        else:
            self.log("No update required for queuing profile")

        if is_update_required_for_site:
            self.log("Update required for site")
        else:
            self.log("No update required for site")

        other_check_names = ["application_queuing_profile", "site_name"]
        no_update_require = []
        if not is_update_required_for_queuing_profile:
            no_update_require.append("application_queuing_profile")
        if not is_update_required_for_site:
            no_update_require.append("site_name")

        update_not_required = True
        for check in other_check_names:
            if check not in no_update_require:
                update_not_required = False
                break

        # Final check: If no update is required for both queuing profile and site name
        if all(check in no_update_require for check in ["application_queuing_profile", "site_name"]):
            self.log("No update required for application policy")
            return False

        # Prepare application set names based on relevance
        want_business_relevant_set_name, want_business_irrelevant_set_name, want_default_set_name = [], [], []
        have_business_relevant_set_name, have_business_irrelevant_set_name, have_default_set_name = [], [], []

        application_set_names = req_application_policy_details.get("clause")
        for item in application_set_names:
            for relevance in item['relevance_details']:
                if relevance['relevance'] == 'BUSINESS_RELEVANT':
                    want_business_relevant_set_name.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'BUSINESS_IRRELEVANT':
                    want_business_irrelevant_set_name.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'DEFAULT':
                    want_default_set_name.extend(relevance['application_set_name'])

        # Process current application set names from existing policy
        for application_sets in current_application_policy:
            clause = application_sets.get("exclusiveContract", {}).get("clause")
            if clause and clause[0].get("relevanceLevel"):
                current_relevance_type = clause[0].get("relevanceLevel")
                app_set_name = application_sets.get("name").replace(application_sets.get("policyScope") + '_', "")

                if current_relevance_type == "BUSINESS_RELEVANT":
                    have_business_relevant_set_name.append(app_set_name)
                elif current_relevance_type == "BUSINESS_IRRELEVANT":
                    have_business_irrelevant_set_name.append(app_set_name)
                elif current_relevance_type == "DEFAULT":
                    have_default_set_name.append(app_set_name)

        # Compare and append missing items
        final_business_relevant_set_name, final_business_irrelevant_set_name, final_default_set_name = [], [], []
        for want_item, have_item, final_item in [
            (want_business_relevant_set_name, have_business_relevant_set_name, final_business_relevant_set_name),
            (want_business_irrelevant_set_name, have_business_irrelevant_set_name, final_business_irrelevant_set_name),
            (want_default_set_name, have_default_set_name, final_default_set_name)
        ]:
            final_item.extend(item for item in want_item if item not in have_item)

        # Ensure the default list is empty if no relevant/default values are there
        if not want_default_set_name:
            final_default_set_name = []
        if not want_business_relevant_set_name:
            final_business_relevant_set_name = []
        if not want_business_irrelevant_set_name:
            final_business_irrelevant_set_name = []

        if update_not_required :
            if not any([final_business_relevant_set_name, final_business_irrelevant_set_name, final_default_set_name]):
                self.log("no update required for application policy")
                return False

        return True

    def get_diff_application_policy(self):
        """
        Get the differences in application policy configuration and trigger necessary updates.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self: The current instance of the class with updated 'result', 'status', and 'msg' attributes.

        Description:
            This function identifies differences between the current and desired application policy configurations in Cisco
            Catalyst Center. It validates the presence of mandatory parameters, checks for updates in queuing profiles and
            site mappings, and categorizes application sets based on relevance levels (BUSINESS_RELEVANT, BUSINESS_IRRELEVANT,
            and DEFAULT). The function generates a payload for required updates and ensures the application's compliance
            with the desired state.

            If discrepancies exist between the current and desired configurations, the function prepares and sends the
            appropriate API payloads to update the policy. Additionally, it ensures that no unexpected application sets
            are added. Errors or inconsistencies are logged, and the status, result, and message attributes are updated
            accordingly.

            This function also ensures the desired application policy reflects the latest configurations by performing
            detailed comparisons and triggering updates only when necessary.
        """

        application_policy_details = self.have
        application_policy_name = self.want.get("application_policy_details", {}).get("name")
        current_application_policy_details = self.config.get("application_policy_details")

        site_names = current_application_policy_details.get("site_name")
        application_queuing_profile_name = current_application_policy_details.get("application_queuing_profile_name")
        clause = current_application_policy_details.get("clause")

        missing_fields = []

        if not site_names:
            missing_fields.append("site_name")
        if not application_queuing_profile_name:
            missing_fields.append("application_queuing_profile_name")
        if not clause:
            missing_fields.append("clause")

        if missing_fields:
            self.msg = "Application policy operation failed. The following mandatory parameters are missing or empty: {}.".format(", ".join(missing_fields))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        if application_policy_details.get("application_policy_exists") is False:
            self.create_application_policy()
            return self

        req_application_policy_details = self.config.get("application_policy_details")
        site_names = req_application_policy_details.get("site_name")
        site_ids = []
        for site_name in site_names:
            site_exists, site_id = self.get_site_id(site_name)
            site_ids.append(site_id)
        application_set_names = req_application_policy_details.get("clause")
        application_queuing_profile_name = req_application_policy_details.get("application_queuing_profile_name")
        queuing_profile_id = application_policy_details.get('current_queuing_profile', [])[0].get('id', None)
        current_application_policy = application_policy_details.get("current_application_policy")

        self.log(req_application_policy_details)

        is_update_required_for_queuing_profile = False
        is_update_required_for_site = False

        no_update_require = []
        other_check_names = ["application_queuing_profile", "site_name"]
        final_app_set_payload = []

        for contract in current_application_policy:
            if 'contract' in contract and contract['contract']:
                current_application_policy_queuing_id = contract.get("id")
                advanced_policy_scope_for_queuing_profile = contract.get("advancedPolicyScope").get("id")
                advanced_policy_scope_element_for_queuing_profile = contract.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("id")
                name = contract.get("name")
                if application_queuing_profile_name not in name:
                    is_update_required_for_queuing_profile = True
                    break

        # Check if the site IDs match
        for application_policy in current_application_policy:
            curent_site_ids = application_policy.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("groupId")
            # Compare the site_ids and curent_site_ids
            if set(site_ids) != set(curent_site_ids):
                is_update_required_for_site = True
                break

        if is_update_required_for_site or is_update_required_for_queuing_profile:
            if is_update_required_for_queuing_profile:
                self.log("Update required for queuing profile")
            else:
                self.log("Update required for site")

            if is_update_required_for_site:
                group_id = site_ids
            else:
                group_id = curent_site_ids

            payload = {
                "id": current_application_policy_queuing_id,
                "name": "{}_{}".format(application_policy_name, application_queuing_profile_name),
                "deletePolicyStatus": current_application_policy[0].get("deletePolicyStatus"),
                "policyScope": current_application_policy[0].get("policyScope"),
                "priority": current_application_policy[0].get("priority"),
                "advancedPolicyScope": {
                    "id": advanced_policy_scope_for_queuing_profile,
                    "name": application_policy_name,
                    "advancedPolicyScopeElement": [
                        {
                            "id": advanced_policy_scope_element_for_queuing_profile,
                            "groupId": group_id,
                            "ssid": []
                        }
                    ]
                },
                "contract": {
                    "idRef": queuing_profile_id
                }
            }

            final_app_set_payload.append(payload)
            self.log(json.dumps(payload, indent=4))
        else:
            self.log("No update is required for queuing profile")
            no_update_require.append("application_queuing_profile")

        if is_update_required_for_site is True:
            self.log("Update required for site")
        else:
            self.log("No update is required for site")
            no_update_require.append("site_name")

        update_not_required = True
        for check in other_check_names:
            if check not in no_update_require:
                update_not_required = False
                break

        want_business_relevant_set_name, want_business_irrelevant_set_name, want_default_set_name = [], [], []
        have_business_relevant_set_name, have_business_irrelevant_set_name, have_default_set_name = [], [], []
        final_business_relevant_set_name, final_business_irrelevant_set_name, final_default_set_name = [], [], []

        # Application data (replace with actual data or mock data)
        application_set_names = req_application_policy_details.get("clause")

        total_current_app_set = []
        total_want_app_set = []
        # Populate the lists based on relevance
        for item in application_set_names:
            for relevance in item['relevance_details']:
                if relevance['relevance'] == 'BUSINESS_RELEVANT':
                    want_business_relevant_set_name.extend(relevance['application_set_name'])
                    total_want_app_set.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'BUSINESS_IRRELEVANT':
                    want_business_irrelevant_set_name.extend(relevance['application_set_name'])
                    total_want_app_set.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'DEFAULT':
                    want_default_set_name.extend(relevance['application_set_name'])
                    total_want_app_set.extend(relevance['application_set_name'])

        self.log("Wanted Business Irrelevant Set: {}".format(want_business_irrelevant_set_name))
        self.log("Wanted Business Relevant Set: {}".format(want_business_relevant_set_name))
        self.log("Wanted Default Set: {}".format(want_default_set_name))

        # Populate current application set names
        for application_sets in current_application_policy:
            clause = application_sets.get("exclusiveContract", {}).get("clause")
            if clause and clause[0].get("relevanceLevel") is not None:
                current_relevance_type = clause[0].get("relevanceLevel")

                # Process Business Relevant
                if current_relevance_type == "BUSINESS_RELEVANT":
                    full_name = application_sets.get("name")
                    policy_name = application_sets.get("policyScope") + '_'
                    app_set_name = full_name.replace(policy_name, "")
                    have_business_relevant_set_name.append(app_set_name)
                    total_current_app_set.append(app_set_name)

                    for set_name in want_business_relevant_set_name:
                        if set_name in application_sets.get("name"):
                            self.log("No update required for: {}".format(set_name))

                elif current_relevance_type == "BUSINESS_IRRELEVANT":
                    full_name = application_sets.get("name")
                    policy_name = application_sets.get("policyScope") + '_'
                    app_set_name = full_name.replace(policy_name, "")
                    have_business_irrelevant_set_name.append(app_set_name)
                    total_current_app_set.append(app_set_name)

                    for set_name in want_business_irrelevant_set_name:
                        if set_name in application_sets.get("name"):
                            self.log("No update required for: {}".format(set_name))

                elif current_relevance_type == "DEFAULT":
                    full_name = application_sets.get("name")
                    policy_name = application_sets.get("policyScope") + '_'
                    app_set_name = full_name.replace(policy_name, "")
                    have_default_set_name.append(app_set_name)
                    total_current_app_set.append(app_set_name)

                    for set_name in want_default_set_name:
                        if set_name in application_sets.get("name"):
                            self.log("No update required for: {}".format(set_name))

        self.log("Total Current Application Set: {}".format(total_current_app_set))
        self.log("Total Want Application Set: {}".format(total_want_app_set))

        current_set = set(total_current_app_set)
        want_set = set(total_want_app_set)

        extra_in_want = want_set - current_set

        if extra_in_want:
            self.msg = "no extra application sets can be added to the application policy"
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        else:
            self.log("Comparison passed. No extra items in want.")

        want_lists = [
            (want_business_relevant_set_name, have_business_relevant_set_name, final_business_relevant_set_name),
            (want_business_irrelevant_set_name, have_business_irrelevant_set_name, final_business_irrelevant_set_name),
            (want_default_set_name, have_default_set_name, final_default_set_name)
        ]

        for want_item, have_item, final_item in want_lists:
            for w in want_item:
                if w not in have_item:
                    final_item.append(w)
            if not want_item:
                final_item.extend([item for item in have_item if item not in final_item])

        if not want_default_set_name:
            final_default_set_name = []
        if not want_business_relevant_set_name:
            final_business_relevant_set_name = []
        if not want_business_irrelevant_set_name:
            final_business_irrelevant_set_name = []

        self.log("Have Business Relevant: {}".format(have_business_relevant_set_name))
        self.log("Have Business Irrelevant: {}".format(have_business_irrelevant_set_name))
        self.log("Have Default: {}".format(have_default_set_name))

        self.log("Final Business Relevant: {}".format(final_business_relevant_set_name))
        self.log("Final Business Irrelevant: {}".format(final_business_irrelevant_set_name))
        self.log("Final Default: {}".format(final_default_set_name))

        final_want_business_relevant = []
        final_want_business_irrelevant = []
        final_want_default = []

        for item in have_business_relevant_set_name:
            if (item not in final_business_relevant_set_name and
                    item not in final_business_irrelevant_set_name and
                    item not in final_default_set_name):
                final_want_business_relevant.append(item)

        for item in have_business_irrelevant_set_name:
            if (item not in final_business_relevant_set_name and
                    item not in final_business_irrelevant_set_name and
                    item not in final_default_set_name):
                final_want_business_irrelevant.append(item)

        for item in have_default_set_name:
            if (item not in final_business_relevant_set_name and
                    item not in final_business_irrelevant_set_name and
                    item not in final_default_set_name):
                final_want_default.append(item)

        self.log("Final want Business Relevant (Diff): {}".format(final_want_business_relevant))
        self.log("Final want Business Irrelevant (Diff): {}".format(final_want_business_irrelevant))
        self.log("Final want Default (Diff): {}".format(final_want_default))
        self.application_policy_updated = self.is_update_required_for_application_policy()
        self.log(self.application_policy_updated)
        if update_not_required :
            if not (final_business_irrelevant_set_name or final_business_relevant_set_name or final_default_set_name):
                self.log("No update required for application policy")
                self.status = "success"
                self.result['changed'] = False
                self.msg = "Application policy '{0}' does not need any update. ".format(application_policy_name)
                self.result['msg'] = self.msg
                self.result['response'] = self.msg
                self.log(self.msg, "INFO")
                return self

        for application_sets in current_application_policy:
            group_id = site_ids if is_update_required_for_site else curent_site_ids
            for app_set in final_business_relevant_set_name + final_business_irrelevant_set_name + final_default_set_name:
                if app_set in final_business_relevant_set_name:
                    relevance_level = "BUSINESS_RELEVANT"
                elif app_set in final_business_irrelevant_set_name:
                    relevance_level = "BUSINESS_IRRELEVANT"
                elif app_set in final_default_set_name:
                    relevance_level = "DEFAULT"

                if relevance_level and app_set in application_sets.get("name"):
                    self.log(app_set)
                    app_set_payload = {
                        "id": application_sets.get("id"),
                        "name": "{}_{}".format(application_sets.get('policyScope'), app_set),
                        "deletePolicyStatus": application_sets.get("deletePolicyStatus"),
                        "policyScope": application_sets.get('policyScope'),
                        "priority": application_sets.get('priority'),
                        "advancedPolicyScope": {
                            "id": application_sets.get("advancedPolicyScope").get("id"),
                            "name": application_sets.get("advancedPolicyScope").get("name"),
                            "advancedPolicyScopeElement": [
                                {
                                    "id": application_sets.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("id"),
                                    "groupId": group_id,
                                    "ssid": []
                                }
                            ]
                        },
                        "exclusiveContract": {
                            "id": application_sets.get("exclusiveContract").get("id"),
                            "clause": [
                                {
                                    "id": application_sets.get("exclusiveContract").get("clause")[0].get("id"),
                                    "type": application_sets.get("exclusiveContract").get("clause")[0].get("type"),
                                    "relevanceLevel": relevance_level
                                }
                            ]
                        },
                        "producer": {
                            "id": application_sets.get("producer").get("id"),
                            "scalableGroup": [
                                {
                                    "idRef": application_sets.get("producer").get("scalableGroup")[0].get("idRef")
                                }
                            ]
                        }
                    }
                    final_app_set_payload.append(app_set_payload)

        for application_sets in current_application_policy:
            if is_update_required_for_site is True:
                group_id = site_ids if is_update_required_for_site else curent_site_ids
                for app_set in final_want_business_relevant + final_want_business_irrelevant + final_want_default:
                    if app_set in final_want_business_relevant:
                        relevance_level = "BUSINESS_RELEVANT"
                    elif app_set in final_want_business_irrelevant:
                        relevance_level = "BUSINESS_IRRELEVANT"
                    elif app_set in final_want_default:
                        relevance_level = "DEFAULT"

                    if relevance_level and app_set in application_sets.get("name"):
                        self.log(app_set)
                        app_set_payload = {
                            "id": application_sets.get("id"),
                            "name": "{}_{}".format(application_sets.get('policyScope'), app_set),
                            "deletePolicyStatus": application_sets.get("deletePolicyStatus"),
                            "policyScope": application_sets.get('policyScope'),
                            "priority": application_sets.get('priority'),
                            "advancedPolicyScope": {
                                "id": application_sets.get("advancedPolicyScope").get("id"),
                                "name": application_sets.get("advancedPolicyScope").get("name"),
                                "advancedPolicyScopeElement": [
                                    {
                                        "id": application_sets.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("id"),
                                        "groupId": group_id,
                                        "ssid": []
                                    }
                                ]
                            },
                            "exclusiveContract": {
                                "id": application_sets.get("exclusiveContract").get("id"),
                                "clause": [
                                    {
                                        "id": application_sets.get("exclusiveContract").get("clause")[0].get("id"),
                                        "type": application_sets.get("exclusiveContract").get("clause")[0].get("type"),
                                        "relevanceLevel": relevance_level
                                    }
                                ]
                            },
                            "producer": {
                                "id": application_sets.get("producer").get("id"),
                                "scalableGroup": [
                                    {
                                        "idRef": application_sets.get("producer").get("scalableGroup")[0].get("idRef")
                                    }
                                ]
                            }
                        }
                        final_app_set_payload.append(app_set_payload)

        self.log(json.dumps(final_app_set_payload, indent=4))
        try:
            response = self.dnac._exec(
                family="application_policy",
                function='application_policy_intent',
                op_modifies=True,
                params={'updateList': final_app_set_payload, }
            )

            self.log("Received API response from 'application_policy_intent' for Update: {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "application_policy_intent")

            if self.status not in ["failed", "exited"]:
                self.log("Application policy '{0}' updated successfully.".format(application_policy_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application policy '{0}' updated successfully.".format(application_policy_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Update of the application policy failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "{0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR")

    def get_ssid_from_wc(self, device_id, wlan_id):
        """
        Get the SSID name associated with a specific WLAN ID from a wireless controller.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_id (str): The unique identifier of the wireless device (controller) in Cisco Catalyst Center.
            wlan_id (str): The WLAN ID for which the SSID name is required.

        Returns:
            str or None: The SSID name corresponding to the provided WLAN ID if found, otherwise None.

        Description:
            This function retrieves the SSID name associated with a given WLAN ID for a specific wireless controller
            in Cisco Catalyst Center.

            The function extracts the SSID name from the response for the WLAN ID provided and logs the result. If the
            SSID is found, it is returned; otherwise, a log message indicates that no SSID was found for the given WLAN ID.

            In the event of an error during the API call or processing, an exception is raised, and an appropriate error 
            message is logged.

            This function is useful for fetching the SSID details dynamically for specific wireless controllers in 
            Cisco Catalyst Center.
        """

        try:
            response = self.dnac._exec(
                family="wireless",
                function='get_ssid_details_for_specific_wireless_controller',
                op_modifies=True,
                params={'network_device_id': device_id, }
            )

            self.log("Received API response from 'get_ssid_details_for_specific_wireless_controller' : {0}".format(response), "DEBUG")
            # Initialize the variable to store the SSID name
            ssid_name = None

            # Iterate through the list of dictionaries inside the 'response' key
            for item in response.get("response"):
                if item['wlanId'] == int(wlan_id):
                    # Assign the corresponding SSID name to the variable
                    ssid_name = item['ssidName']
                    break  # Exit the loop as we found the match

            # Print the result
            if ssid_name:
                self.log("The SSID name for WLAN ID {} is: {}".format(wlan_id, ssid_name))
            else:
                self.log("No SSID name found for WLAN ID {}.".format(wlan_id))

            return ssid_name

        except Exception as e:
            self.msg = "{0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def create_application_policy(self):
        """
        Create an application policy and trigger its deployment details based on the configuration provided in the playbook.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self: The current instance of the class with updated 'result', 'status', and 'msg' attributes.

        Description:
            This function creates an application policy in the Catalyst Center by processing the configuration details
            provided in the playbook. It retrieves site information, identifies application queuing profiles, and
            categorizes application sets based on relevance levels (BUSINESS_RELEVANT, BUSINESS_IRRELEVANT, and DEFAULT).
            The application sets are mapped to their IDs, and a payload is generated for API submission. The function
            then sends a request to create the application policy and validates the response.
            In case of an error or failure in creation, appropriate error messages are logged, and the function updates
            the status and result attributes.
        """

        new_application_policy_details = self.config.get("application_policy_details")
        application_policy_name = self.want.get("application_policy_details", {}).get("name")
        device_type = self.want.get("application_policy_details", {}).get("device_type")
        device = self.want.get("application_policy_details", {}).get("device", {})
        device_ip = None
        Wlan_id = None

        if device.get("device"):
            device_ip = device.get("device_ip")
            Wlan_id = device.get("Wlan_id")

        site_names = new_application_policy_details.get("site_name")
        application_queuing_profile_name = new_application_policy_details.get("application_queuing_profile_name")
        clause = new_application_policy_details.get("clause")

        missing_fields = []

        if not site_names:
            missing_fields.append("site_name")
        if not application_queuing_profile_name:
            missing_fields.append("application_queuing_profile_name")
        if not clause:
            missing_fields.append("clause")

        if missing_fields:
            self.msg = "Application policy operation failed. The following mandatory parameters are missing or empty: {}.".format(", ".join(missing_fields))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        site_ids = []
        for site_name in site_names:
            site_exists, site_id = self.get_site_id(site_name)
            site_ids.append(site_id)
        application_policy_details = self.have
        application_set_names = new_application_policy_details.get("clause")
        application_queuing_profile_name = new_application_policy_details.get("application_queuing_profile_name")
        queuing_profile_id = application_policy_details.get('current_queuing_profile', [])[0].get('id', None)

        if device_type == "wireless":
            wc_device_id = self.get_device_ids_from_device_ips([device_ip])
            ssid = self.get_ssid_from_wc(wc_device_id.get(device_ip), Wlan_id)
            self.log(ssid)
            if ssid:
                ssid = [ssid]
        else:
            ssid = []
        self.log(ssid)

        business_relevant_set_name, business_relevant_set_id = [], []
        business_irrelevant_set_name, business_irrelevant_set_id = [], []
        default_set_name, default_set_id = [], []

        for item in application_set_names:
            for relevance in item['relevance_details']:
                if relevance['relevance'] == 'BUSINESS_RELEVANT':
                    business_relevant_set_name.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'BUSINESS_IRRELEVANT':
                    business_irrelevant_set_name.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'DEFAULT':
                    default_set_name.extend(relevance['application_set_name'])

        for app_set_name in business_relevant_set_name:
            app_set_id = self.get_application_set_id(app_set_name)
            if app_set_id:
                business_relevant_set_id.append({"name": app_set_name, "id": app_set_id})
            else:
                self.log("No app set found for {}".format(app_set_name))

        for app_set_name in business_irrelevant_set_name:
            app_set_id = self.get_application_set_id(app_set_name)
            if app_set_id:
                business_irrelevant_set_id.append({"name": app_set_name, "id": app_set_id})
            else:
                self.log("No app set found for {}".format(app_set_name))

        for app_set_name in default_set_name:
            app_set_id = self.get_application_set_id(app_set_name)
            if app_set_id:
                default_set_id.append({"name": app_set_name, "id": app_set_id})
            else:
                self.log("No app set found for {}".format(app_set_name))

        self.log("Business Relevant Set IDs: {}".format(business_relevant_set_id))
        self.log("Business Irrelevant Set IDs: {}".format(business_irrelevant_set_id))
        self.log("Default Set IDs: {}".format(default_set_id))

        policy_status = new_application_policy_details.get("policy_status")
        delete_policy_status = {
            "deployed": "NONE",
            "deleted": "DELETED",
            "restored": "RESTORED"
        }.get(policy_status, "NONE")

        relevance_map = {
            "BUSINESS_RELEVANT": business_relevant_set_id,
            "BUSINESS_IRRELEVANT": business_irrelevant_set_id,
            "DEFAULT": default_set_id
        }

        payload = []
        payload.append({
            "name": "{}_{}".format(application_policy_name, application_queuing_profile_name),
            "deletePolicyStatus": delete_policy_status,
            "policyScope": "{}".format(application_policy_name),
            "priority": "100",
            "advancedPolicyScope": {
                "name": "{}".format(application_policy_name),
                "advancedPolicyScopeElement": [
                    {
                        "groupId": site_ids,
                        "ssid": ssid
                    }
                ]
            },
            "contract": {
                "idRef": queuing_profile_id
            }
        })

        for relevance_detail in new_application_policy_details['clause'][0]['relevance_details']:
            relevance_level = relevance_detail['relevance']
            application_set_names = relevance_detail['application_set_name']

            for app_set_name in application_set_names:
                matching_set = next((item for item in relevance_map[relevance_level] if item['name'] == app_set_name), None)
                if not matching_set:
                    continue

                payload.append({
                    "name": "{}_{}".format(application_policy_name, app_set_name),
                    "deletePolicyStatus": delete_policy_status,
                    "policyScope": "{}".format(application_policy_name),
                    "priority": "100",
                    "advancedPolicyScope": {
                        "name": "{}".format(application_policy_name),
                        "advancedPolicyScopeElement": [
                            {
                                "groupId": site_ids,
                                "ssid": ssid
                            }
                        ]
                    },
                    "exclusiveContract": {
                        "clause": [
                            {
                                "type": "BUSINESS_RELEVANCE",
                                "relevanceLevel": relevance_level
                            }
                        ]
                    },
                    "producer": {
                        "scalableGroup": [
                            {
                                "idRef": matching_set['id']
                            }
                        ]
                    }
                })

        self.log(json.dumps(payload, indent=4))

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='application_policy_intent',
                op_modifies=True,
                params={'createList': payload}
            )

            self.log("Received API response from 'application_policy_intent' for creation: {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "application_policy_intent")

            if self.status not in ["failed", "exited"]:
                self.log("Application policy '{0}' created successfully.".format(application_policy_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application policy '{0}' created successfully.".format(application_policy_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Creation of the application policy failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "{0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def is_update_required_for_application(self):
        """
        Determine if an update is required for the application based on differences between
        required and current application details.

        Returns:
            bool: True if an update is required, False otherwise.
        """

        required_application_details = self.want.get("application_details")
        current_application_details = self.have.get("current_application")[0]
        application_set_id = None

        current_application_set = self.have.get("current_application_set")
        if current_application_set and isinstance(current_application_set, list) and len(current_application_set) > 0:
            application_set_id = current_application_set[0].get("id")

        fields_to_check = {
            "description": "longDescription",
            "help_string": "helpString",
            "traffic_class": "trafficClass",
            "server_name": "serverName"
        }

        for required_key, current_key in fields_to_check.items():
            required_value = required_application_details.get(required_key)
            current_value = current_application_details.get("networkApplications")[0].get(current_key)

            if current_value is None and required_value is not None:
                self.log("Update required for {} as current value is None.".format(required_key))
                return True

            if required_value != current_value:
                self.log("Update required for {}".format(required_key))
                return True

        # Check for application_set_id
        if application_set_id != current_application_details.get("parentScalableGroup").get("idRef") and application_set_id is not None:
            self.log("Update required for application_set")
            return True

        self.log("No updates required.")
        return False

    def get_diff_application(self):
        """
        Retrieve and update differences between current and required application configurations.

        Args:
            self (object): An instance of the class for interacting with Cisco Catalyst Center.

        Returns:
            self: The updated instance with 'status', 'msg', and 'result' attributes.

        Description:
            Compares the existing application details ('have') with the desired configuration ('want') and updates
            the application if discrepancies are found. Handles mandatory field validation, constructs the update
            payload, logs required actions, and sends an API request to apply changes.
        """

        application_name = self.want.get("application_details", {}).get("name")
        application_set_name = self.want.get("application_details").get("application_set_name")

        if application_name is None:
            self.msg = "Mandatory field 'application_name' is missing"
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        application_details = self.have
        required_application_details = self.want.get("application_details")

        if application_details.get("application_set_exists") is False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = (
                "The application set '{0}' is not available in the Cisco Catalyst Center. "
                "Only the default application sets can be used. "
                "Defer this feature as API issue is there. "
                "Once it's fixed, we will address it in the upcoming release.".format(application_set_name)
            )
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        if application_details.get("application_exists") is False:
            self.create_application()
            return self

        current_application_details = application_details.get("current_application")[0]

        current_application_set = application_details.get("current_application_set")

        application_set_id = None
        if current_application_set and isinstance(current_application_set, list) and len(current_application_set) > 0:
            application_set_id = current_application_set[0].get("id")

        application_name = current_application_details.get("name")
        self.log(current_application_details)
        if required_application_details.get("name") != current_application_details.get("name"):
            self.log("Application name cannot be updated")

        fields_to_check = {
            "description": "longDescription",
            "help_string": "helpString",
            "traffic_class": "trafficClass",
            "server_name": "serverName",
            "url": "url"
        }

        update_required_keys = []

        for required_key, current_key in fields_to_check.items():
            required_value = required_application_details.get(required_key)
            current_value = current_application_details.get("networkApplications")[0].get(current_key)
            if current_value is None:
                if required_value is not None:
                    self.log("Update required for {} as current value is None.".format(required_key))
                    update_required_keys.append(required_key)
                else:
                    self.log("Skipping {} as both values are None.".format(required_key))
                continue

            if required_value == current_value or required_value is None:
                self.log("Update not required for {}".format(required_key))
            else:
                self.log("Update required for {}".format(required_key))
                update_required_keys.append(required_key)

        if application_set_id == current_application_details.get("parentScalableGroup").get("idRef") or application_set_id is None:
            self.log("Update not required for application_set")
            application_set_id = current_application_details.get("parentScalableGroup").get("idRef")
        else:
            self.log("Update required for application set")
            update_required_keys.append("application_set")

        self.application_updated = self.is_update_required_for_application()

        if not update_required_keys:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "Application '{0}' does not need any update. ".format(application_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        help_string = (
            required_application_details.get("help_string")
            if "help_string" in update_required_keys
            else current_application_details.get("networkApplications")[0].get("helpString")
        )

        long_description = (
            required_application_details.get("description")
            if "description" in update_required_keys
            else current_application_details.get("networkApplications")[0].get("longDescription")
        )

        # Now conditionally add fields to the payload
        network_application_payload = {
            "id": current_application_details.get("networkApplications")[0].get("id"),
            "applicationSubType": current_application_details.get("networkApplications")[0].get("applicationSubType"),
            "applicationType": current_application_details.get("networkApplications")[0].get("applicationType"),
            "categoryId": current_application_details.get("networkApplications")[0].get("categoryId"),
            "displayName": current_application_details.get("networkApplications")[0].get("displayName"),
            "name": current_application_details.get("networkApplications")[0].get("name"),
            "popularity": current_application_details.get("networkApplications")[0].get("popularity"),
            "rank": (
                required_application_details.get("rank")
                if "rank" in update_required_keys
                else current_application_details.get("networkApplications")[0].get("rank")
            ),
            "selectorId": current_application_details.get("networkApplications")[0].get("selectorId"),
            "trafficClass": (
                required_application_details.get("traffic_class")
                if "traffic_class" in update_required_keys
                else current_application_details.get("networkApplications")[0].get("trafficClass")
            ),
        }

        # Conditionally add the helpString and longDescription fields if they exist
        if help_string:
            network_application_payload["helpString"] = help_string

        if long_description:
            network_application_payload["longDescription"] = long_description




        self.log(current_application_details.get("networkApplications")[0].get("trafficClass"))
        if "server_name" in required_application_details:
            network_application_payload["serverName"] = required_application_details.get("server_name")
            if "serverName" in current_application_details.get("networkApplications")[0]:
                network_application_payload["serverName"] = current_application_details.get("networkApplications")[0].get("serverName")
        else:
            if "url" in required_application_details:
                network_application_payload["url"] = required_application_details.get("url")
            elif "url" in current_application_details.get("networkApplications")[0]:
                network_application_payload["url"] = current_application_details.get("networkApplications")[0].get("url")
            if "app_protocol" in required_application_details:
                network_application_payload["appProtocol"] = required_application_details.get("app_protocol")
            elif "appProtocol" in current_application_details.get("networkApplications")[0]:
                network_application_payload["appProtocol"] = current_application_details.get("networkApplications")[0].get("appProtocol")

        network_identity_setting = {}

        if "network_identity_setting" in required_application_details:
            network_identity_details = required_application_details["network_identity_setting"]

            key_mapping = {
                "protocol": "protocol",
                "port": "ports",
                "ip_subnet": "ipv4Subnet",
                "lower_Port": "lowerPort",
                "upper_port": "upperPort"
            }

            for source_key, target_key in key_mapping.items():
                if source_key in network_identity_details:
                    network_identity_setting[target_key] = network_identity_details[source_key]

        self.log(network_identity_setting)

        # Construct the full payload
        param = [
            {
                "id": current_application_details.get("id"),
                "instanceId": current_application_details.get("instanceId"),
                "displayName": current_application_details.get("displayName"),
                "instanceVersion": current_application_details.get("instanceVersion"),
                "name": current_application_details.get("name"),
                "namespace": current_application_details.get("namespace"),
                "networkApplications": [network_application_payload],
                "parentScalableGroup": {
                    "idRef": application_set_id
                },
                **(
                    {"networkIdentity": [network_identity_setting]}
                    if "network_identity_setting" in required_application_details
                    else {}
                ),
                "qualifier": current_application_details.get("qualifier"),
                "scalableGroupExternalHandle": current_application_details.get("scalableGroupExternalHandle"),
                "scalableGroupType": current_application_details.get("scalableGroupType"),
                "type": current_application_details.get("type"),
            }
        ]

        self.log("Payload for update application: {}".format(json.dumps(param, indent=4)))

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='edit_applications',
                op_modifies=True,
                params={"payload": param}
            )

            self.log("Received API response from 'edit_applications': {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "edit_applications")

            if self.status not in ["failed", "exited"]:
                self.log("Application '{0}' updated successfully.".format(application_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application '{0}' updated successfully.".format(application_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Updation of the application failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "Updation of the application failed due to: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def create_application(self):
        """
        Create a new application in Cisco Catalyst Center.

        Args:
            self (object): An instance of the class for interacting with Cisco Catalyst Center.

        Returns:
            self: The updated instance with 'status', 'msg', and 'result' attributes.

        Description:
            This method creates a new application by comparing the desired configuration ('want') with the existing
            application details ('have'). It checks for missing mandatory fields, validates the application type,
            and constructs the payload for the application creation request. The method sends an API request to
            Cisco Catalyst Center to create the application and logs success or failure. If any errors are encountered,
            they are handled and returned with appropriate messages.
        """

        new_application_set_details = self.want
        application_set_name = new_application_set_details.get('application_details', {}).get('application_set_name')
        application_set_id = self.get_application_set_id(application_set_name)
        application_details = self.want.get("application_details")
        application_name = application_details.get("name")
        application_traffic_class = application_details.get("traffic_class")
        application_type = application_details.get("type")
        application_details_set = self.have
        get_application_set = application_details.get("current_application_set")

        missing_fields = []

        if application_traffic_class is None:
            missing_fields.append("traffic_class")
        if application_name is None:
            missing_fields.append("application_name")
        if application_set_name is None:
            missing_fields.append("application_set_name")
        if application_type is None:
            missing_fields.append("type")

        if missing_fields:
            self.msg = "As we need to create a new application - mandatory field(s) missing: {}".format(', '.join(missing_fields))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        get_application_list = self.get_current_application_details()

        category_id = None

        for app in get_application_list:
            if app.get("parentScalableGroup", {}).get("idRef") == application_set_id:
                network_applications = app.get("networkApplications")
                if network_applications and isinstance(network_applications, list):
                    category_id = network_applications[0].get("categoryId")
                break

        supported_types = ["server_name", "url", "server_ip"]

        if application_details.get("type") not in ["server_name", "url", "server_ip"]:
            self.msg = "Unsupported application type: '{0}'. Supported values are: {1}".format(application_type, ', '.join(supported_types))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        network_application = {
            "applicationType": "CUSTOM",
            "trafficClass": application_details.get("traffic_class"),
            "categoryId": category_id,
            "type": "_server-ip" if application_details.get("type") == "server_ip" else
                    "_url" if application_details.get("type") == "url" else "_servername"
        }

        # Add optional fields if they exist in the application_details
        optional_fields = [
            ("ignore_conflict", "ignoreConflict"),
            ("rank", "rank"),
            ("engine_id", "engineId"),
            ("help_string", "helpString"),
            ("description", "longDescription")
        ]

        for field, key in optional_fields:
            value = application_details.get(field)
            if value is not None:  # Only add to payload if the value exists
                network_application[key] = value if key not in ("rank", "engineId") else int(value)

        # Add specific fields for 'server_name', 'url', or 'server_ip'
        app_type = application_details.get("type")

        if app_type == "server_name":
            if application_details.get("server_name") is None:
                self.msg = ("server_name is required for the type - server_name")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            network_application["serverName"] = application_details.get("server_name")

        elif app_type == "url":
            if application_details.get("app_protocol") is None or application_details.get("url") is None:
                self.msg = ("app_protocol and url are required for the type - url")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            network_application["appProtocol"] = application_details.get("app_protocol")
            network_application["url"] = application_details.get("url")

        dscp = application_details.get("dscp")
        network_identity_setting = application_details.get("network_identity_setting", {})

        network_identity_list = None

        if app_type == "server_ip":
            if not dscp and not network_identity_setting:
                self.msg = ("Either 'dscp' or 'network_identity_setting' must be provided for the type - server_ip.")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if dscp:
                network_application["dscp"] = dscp

            if network_identity_setting:
                protocol = network_identity_setting.get("protocol")
                ports = network_identity_setting.get("port")

                if not protocol or not ports:
                    self.msg = ("Both 'protocol' and 'ports' are required for the network identity in server_ip type.")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                network_identity = {
                    "protocol": protocol,
                    "ports": str(ports)
                }

                optional_network_identity_fields = [
                    ("ip_subnet", "ipv4Subnet"),
                    ("lower_port", "lowerPort"),
                    ("upper_port", "upperPort")
                ]

                for field, key in optional_network_identity_fields:
                    value = network_identity_setting.get(field)
                    if value is not None:
                        network_identity[key] = value

                network_identity_list = [network_identity]

        param = {
            "name": application_details.get("name"),
            "parentScalableGroup": {
                "idRef": application_set_id
            },
            "scalableGroupType": "APPLICATION",
            "type": "scalablegroup",
            "networkApplications": [network_application],
        }

        if network_identity_list:
            param["networkIdentity"] = network_identity_list
        self.log(param)
        try:
            response = self.dnac._exec(
                family="application_policy",
                function='create_applications',
                op_modifies=True,
                params={"payload": [param]}
            )

            self.log("Received API response from 'create_applications': {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "create_applications")

            if self.status not in ["failed", "exited"]:
                self.log("Application '{0}' created successfully.".format(application_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application '{0}' created successfully.".format(application_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Creation of the application failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_diff_application_set(self):
        """
        Manages the creation of an application set by checking for its existence.

        Description:
            This method checks if an application set already exists using the `have` attribute.
            If the application set exists, it logs the status and skips creation. If it does not
            exist, the method calls `create_application_set` to create a new application set.

        Args:
            None: This method relies on the class instance's `have` attribute for determining the current state.

        Returns:
            self: The current instance of the class, updated with the result of the operation.

        Raises:
            None: All conditions and errors are handled internally.
        """

        application_set_details = self.have
        if application_set_details.get("application_set_exists") is True:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "application set already exist and hence cannot be updated"
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self
        if application_set_details.get("application_set_exists") is False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "Defer this feature as API issue is there once it's fixed we will addresses it in upcoming release"
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        # self.create_application_set()
        return self

    def create_application_set(self):
        """
        Creates a new application set in Cisco Catalyst Center.
        Description:
            This method retrieves the application set details from the `config` attribute and constructs a payload
            required to create the application set. It then triggers the appropriate API call to create the application set
            and monitors the task's response status. If the creation is successful, the method updates the status and logs
            a success message.

        Args:
            None: The method uses the `config` attribute from the class instance to retrieve application set details.

        Returns:
            self: Returns the current instance of the class with updated attributes such as `status`, `result`, and `msg`.

        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """
        new_application_set_details = self.want
        application_set_name = new_application_set_details.get('application_details', {}).get('application_set_name')
        param = {"name": application_set_name}
        try:
            response = self.dnac._exec(
                family="application_policy",
                function='create_application_set',
                op_modifies=True,
                params={"payload": [param]}
            )
            self.log("Received API response from 'create_application_set': {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "create_application_set")

            if self.status not in ["failed", "exited"]:
                self.log("Application set '{0}' created successfully.".format(application_set_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application set '{0}' created successfully.".format(application_set_name))
                self.result['response'] = self.msg
                return self

        except Exception as e:
            self.msg = "An error occured while creating application set: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_diff_queuing_profile(self):
        """
        Creates a new application queuing profile based on the provided configuration.

        Description:
            This method retrieves queuing profile details from the `config` attribute and validates mandatory fields.
            It constructs the payload required for creating a queuing profile and triggers the appropriate API call
            to Cisco Catalyst Center. The response from the API is logged for debugging and tracking purposes.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Raises:
            ValueError: If any mandatory fields (`profile_name`, `type`, or `tc_bandwidth_settings`) are missing
            in the configuration.

        Returns:
            None: The method updates the system state by calling the API and logs the API response.
        """
        queuing_profile = self.have
        required_queuing_profile_details = self.want

        if queuing_profile.get("queuing_profile_exists") is False:
            self.create_queuing_profile()
            return self

        required_details = required_queuing_profile_details['application_queuing_details'][0]
        current_profiles = queuing_profile.get('current_queuing_profile', [])
        if required_details.get('bandwidth_settings', {}):
            is_common = required_details.get('bandwidth_settings', {}).get('is_common_between_all_interface_speeds')

        for item in current_profiles:
            for clause in item.get('clause', []):
                if clause.get('isCommonBetweenAllInterfaceSpeeds') is True:
                    is_common = True
                    break

                is_common = False

        if 'new_profile_name' in required_details:
            profile_name = required_details['new_profile_name']
        else:
            profile_name = queuing_profile['current_queuing_profile'][0].get("name")

        if is_common:
            if required_details.get('bandwidth_settings', {}):
                want_bandwidth_settings = {
                    key.upper(): value for key, value in required_details['bandwidth_settings']['bandwidth_percentages'].items()
                }
            else:
                want_bandwidth_settings = {}

            if required_details.get('dscp_settings', {}):
                want_dscp_settings = {
                    key.upper(): value.upper() if isinstance(value, str) else value
                    for key, value in required_details['dscp_settings'].items()
                }

            else:
                want_dscp_settings = {}
            self.log(queuing_profile)

            have_bandwidth_settings = {}
            have_dscp_settings = {}

            for clause in queuing_profile.get('current_queuing_profile', [])[0].get('clause', []):
                if 'interfaceSpeedBandwidthClauses' in clause:
                    for interface_speed_clause in clause['interfaceSpeedBandwidthClauses']:
                        for tc in interface_speed_clause.get('tcBandwidthSettings', []):
                            have_bandwidth_settings[tc['trafficClass']] = tc['bandwidthPercentage']

                if 'tcDscpSettings' in clause:
                    for tc in clause.get('tcDscpSettings', []):
                        have_dscp_settings[tc['trafficClass']] = tc['dscp']

            final_want_bandwidth_dict = {}
            self.log(want_bandwidth_settings)
            self.log(have_bandwidth_settings)
            for traffic_class, want_value in want_bandwidth_settings.items():
                want_value = int(want_value)

                if traffic_class in have_bandwidth_settings:
                    have_value = have_bandwidth_settings[traffic_class]
                    final_want_bandwidth_dict[traffic_class] = want_value
                else:
                    final_want_bandwidth_dict[traffic_class] = want_value

            for traffic_class, have_value in have_bandwidth_settings.items():
                if traffic_class not in final_want_bandwidth_dict:
                    final_want_bandwidth_dict[traffic_class] = have_value

            self.log(have_bandwidth_settings)
            self.log("Final Want bandwidth Dict:")
            self.log(final_want_bandwidth_dict)

            final_want_dscp_dict = {}
            for traffic_class, want_value in want_dscp_settings.items():
                want_value = int(want_value)

                if traffic_class in have_dscp_settings:
                    have_value = have_dscp_settings[traffic_class]
                    final_want_dscp_dict[traffic_class] = want_value
                else:
                    final_want_dscp_dict[traffic_class] = want_value

            for traffic_class, have_value in have_dscp_settings.items():
                if traffic_class not in final_want_dscp_dict:
                    final_want_dscp_dict[traffic_class] = have_value

            self.log("Final Want dscp Dict:")
            self.log(final_want_dscp_dict)

            id_bandwidth_mapping = {}
            id_dscp_mapping = {}

            current_profiles = queuing_profile.get('current_queuing_profile', [])
            self.log(current_profiles)
            for profile in current_profiles:
                for clause in profile.get('clause', []):
                    if clause.get('type') == 'BANDWIDTH':
                        for interface_clause in clause.get('interfaceSpeedBandwidthClauses', []):
                            for bandwidth_setting in interface_clause.get('tcBandwidthSettings', []):
                                traffic_class = bandwidth_setting.get('trafficClass')
                                instance_id = bandwidth_setting.get('instanceId')
                                if traffic_class and instance_id:
                                    id_bandwidth_mapping[traffic_class] = instance_id
                    elif clause.get('type') == 'DSCP_CUSTOMIZATION':
                        for dscp_setting in clause.get('tcDscpSettings', []):
                            dscp = dscp_setting.get('dscp')
                            traffic_class = dscp_setting.get('trafficClass')
                            instance_id = dscp_setting.get('instanceId')
                            if dscp and traffic_class and instance_id:
                                id_dscp_mapping[traffic_class] = instance_id

            update_required = False

            for key, value in final_want_bandwidth_dict.items():
                if key in have_bandwidth_settings:
                    if have_bandwidth_settings[key] != value:
                        update_required = True
                else:
                    update_required = True

            for key, value in final_want_dscp_dict.items():
                if key in have_dscp_settings:
                    if int(have_dscp_settings[key]) != value:
                        update_required = True
                else:
                    update_required = True

            profile_name = queuing_profile['current_queuing_profile'][0].get("name")
            new_profile_name = required_details['new_profile_name']
            
            self.log(profile_name)
            self.log(new_profile_name)

            if 'new_profile_name' in required_details :
                if not (new_profile_name == profile_name):
                    profile_name = required_details['new_profile_name']
                    update_required = True
            else:
                profile_name = queuing_profile['current_queuing_profile'][0].get("name")

            if 'profile_description' in required_details:
                if queuing_profile['current_queuing_profile'][0].get("description") != required_details['profile_description']:
                    profile_desc = required_details['profile_description']
                    update_required = True
            else:
                profile_desc = queuing_profile['current_queuing_profile'][0].get("description")

            if not update_required:
                self.status = "success"
                self.result['changed'] = False
                self.msg = "Application queuing profile '{0}' does not need any update".format(profile_name)
                self.result['msg'] = self.msg
                self.result['response'] = self.msg
                self.log(self.msg, "INFO")
                return self
            self.log("Update required.")

            instance_ids = {}
            for clause in queuing_profile['current_queuing_profile'][0]['clause']:
                if clause['type'] == 'BANDWIDTH':
                    instance_ids['bandwidth'] = clause['instanceId']
                elif clause['type'] == 'DSCP_CUSTOMIZATION':
                    instance_ids['dscp'] = clause['instanceId']
            self.log(queuing_profile)
            current_queuing_profile = queuing_profile.get('current_queuing_profile')
            if current_queuing_profile and len(current_queuing_profile) > 0:
                clause = current_queuing_profile[0].get('clause')
                if clause and len(clause) > 0:
                    interface_speed_bandwidth_clauses = clause[0].get('interfaceSpeedBandwidthClauses')
                    if interface_speed_bandwidth_clauses and len(interface_speed_bandwidth_clauses) > 0:
                        interface_speed_clause = interface_speed_bandwidth_clauses[0]
                    else:
                        self.log("interfaceSpeedBandwidthClauses is None or empty")
                else:
                    self.log("clause is None or empty")
            else:
                self.log("current_queuing_profile is None or empty")

            if interface_speed_clause['interfaceSpeed'] == 'ALL':
                interface_speed_all_instance_id = interface_speed_clause['instanceId']

            if 'profile_description' in required_details:
                profile_desc = required_details['profile_description']
            else:
                profile_desc = queuing_profile['current_queuing_profile'][0].get("description")

            payload = [
                {
                    "id": queuing_profile['current_queuing_profile'][0].get("id"),
                    "name": profile_name,
                    "description": profile_desc,
                    "clause": [
                        {
                            "instanceId": instance_ids.get('bandwidth'),
                            "type": "BANDWIDTH",
                            "isCommonBetweenAllInterfaceSpeeds": True,
                            "interfaceSpeedBandwidthClauses": [
                                {
                                    "instanceId": interface_speed_all_instance_id,
                                    "interfaceSpeed": "ALL",
                                    "tcBandwidthSettings": [
                                        {
                                            "instanceId": id_bandwidth_mapping[traffic_class],
                                            "trafficClass": traffic_class,
                                            "bandwidthPercentage": final_want_bandwidth_dict[traffic_class]
                                        }
                                        for traffic_class in final_want_bandwidth_dict
                                    ]
                                }
                            ]
                        },
                        {
                            "instanceId": instance_ids.get('dscp'),
                            "type": "DSCP_CUSTOMIZATION",
                            "tcDscpSettings": [
                                {
                                    "instanceId": id_dscp_mapping[traffic_class],
                                    "trafficClass": traffic_class,
                                    "dscp": final_want_dscp_dict[traffic_class]
                                }
                                for traffic_class in final_want_dscp_dict
                            ]
                        }
                    ]
                }
            ]

            self.log(json.dumps(payload, indent=2))

        else:
            want_bandwidth_settings_100_GBPS = None
            want_bandwidth_settings_10_GBPS = None
            want_bandwidth_settings_1_GBPS = None
            want_bandwidth_settings_100_MBPS = None
            want_bandwidth_settings_10_MBPS = None
            want_bandwidth_settings_1_MBPS = None

            if required_details.get('bandwidth_settings', {}):
                for setting in required_details['bandwidth_settings']['interface_speed_settings']:
                    if "HUNDRED_GBPS" in setting['interface_speed']:
                        want_bandwidth_settings_100_GBPS = setting.get("bandwidth_percentages")
                    if "HUNDRED_MBPS" in setting['interface_speed']:
                        want_bandwidth_settings_100_MBPS = setting.get("bandwidth_percentages")
                    if "TEN_GBPS" in setting['interface_speed']:
                        want_bandwidth_settings_10_GBPS = setting.get("bandwidth_percentages")
                    if "TEN_MBPS" in setting['interface_speed']:
                        want_bandwidth_settings_10_MBPS = setting.get("bandwidth_percentages")
                    if "ONE_GBPS" in setting['interface_speed']:
                        want_bandwidth_settings_1_GBPS = setting.get("bandwidth_percentages")
                    if "ONE_MBPS" in setting['interface_speed']:
                        want_bandwidth_settings_1_MBPS = setting.get("bandwidth_percentages")

            have_bandwidth_settings_100_GBPS, have_bandwidth_settings_100_MBPS, have_bandwidth_settings_10_GBPS = {}, {}, {}
            have_bandwidth_settings_10_MBPS, have_bandwidth_settings_1_GBPS, have_bandwidth_settings_1_MBPS = {}, {}, {}

            instance_id_bandwidth_settings_100_GBPS, instance_id_bandwidth_settings_100_MBPS, instance_id_bandwidth_settings_10_GBPS = {}, {}, {}
            instance_id_bandwidth_settings_10_MBPS, instance_id_bandwidth_settings_1_GBPS, instance_id_bandwidth_settings_1_MBPS = {}, {}, {}

            for profile in current_profiles:
                for clause in profile.get('clause', []):
                    for interface_speed_bandwidth_clause in clause.get('interfaceSpeedBandwidthClauses', []):
                        if interface_speed_bandwidth_clause.get("interfaceSpeed") == "HUNDRED_GBPS":
                            for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                                traffic_class = setting['trafficClass'].upper().replace(' ', '_')
                                bandwidth_percentage = str(setting['bandwidthPercentage'])
                                instance_id = (setting['instanceId'])
                                have_bandwidth_settings_100_GBPS[traffic_class] = bandwidth_percentage
                                instance_id_bandwidth_settings_100_GBPS[traffic_class] = instance_id

                        if interface_speed_bandwidth_clause.get("interfaceSpeed") == "HUNDRED_MBPS":
                            for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                                traffic_class = setting['trafficClass'].upper().replace(' ', '_')
                                bandwidth_percentage = str(setting['bandwidthPercentage'])
                                instance_id = (setting['instanceId'])
                                have_bandwidth_settings_100_MBPS[traffic_class] = bandwidth_percentage
                                instance_id_bandwidth_settings_100_MBPS[traffic_class] = instance_id

                        if interface_speed_bandwidth_clause.get("interfaceSpeed") == "TEN_GBPS":
                            for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                                traffic_class = setting['trafficClass'].upper().replace(' ', '_')
                                bandwidth_percentage = str(setting['bandwidthPercentage'])
                                instance_id = (setting['instanceId'])
                                have_bandwidth_settings_10_GBPS[traffic_class] = bandwidth_percentage
                                instance_id_bandwidth_settings_10_GBPS[traffic_class] = instance_id

                        if interface_speed_bandwidth_clause.get("interfaceSpeed") == "TEN_MBPS":
                            for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                                traffic_class = setting['trafficClass'].upper().replace(' ', '_')
                                bandwidth_percentage = str(setting['bandwidthPercentage'])
                                instance_id = (setting['instanceId'])
                                have_bandwidth_settings_10_MBPS[traffic_class] = bandwidth_percentage
                                instance_id_bandwidth_settings_10_MBPS[traffic_class] = instance_id

                        if interface_speed_bandwidth_clause.get("interfaceSpeed") == "ONE_GBPS":
                            for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                                traffic_class = setting['trafficClass'].upper().replace(' ', '_')
                                bandwidth_percentage = str(setting['bandwidthPercentage'])
                                instance_id = (setting['instanceId'])
                                have_bandwidth_settings_1_GBPS[traffic_class] = bandwidth_percentage
                                instance_id_bandwidth_settings_1_GBPS[traffic_class] = instance_id
                        if interface_speed_bandwidth_clause.get("interfaceSpeed") == "ONE_MBPS":
                            for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                                traffic_class = setting['trafficClass'].upper().replace(' ', '_')
                                bandwidth_percentage = str(setting['bandwidthPercentage'])
                                instance_id = (setting['instanceId'])
                                have_bandwidth_settings_1_MBPS[traffic_class] = bandwidth_percentage
                                instance_id_bandwidth_settings_1_MBPS[traffic_class] = instance_id

            final_want_bandwidth_settings_100_GBPS = {}
            final_want_bandwidth_settings_100_MBPS = {}
            final_want_bandwidth_settings_10_GBPS = {}
            final_want_bandwidth_settings_10_MBPS = {}
            final_want_bandwidth_settings_1_GBPS = {}
            final_want_bandwidth_settings_1_MBPS = {}

            for speed, want_bandwidth_settings, have_bandwidth_settings, final_want_bandwidth_settings in [
                ("100_GBPS", want_bandwidth_settings_100_GBPS, have_bandwidth_settings_100_GBPS, final_want_bandwidth_settings_100_GBPS),
                ("100_MBPS", want_bandwidth_settings_100_MBPS, have_bandwidth_settings_100_MBPS, final_want_bandwidth_settings_100_MBPS),
                ("10_GBPS", want_bandwidth_settings_10_GBPS, have_bandwidth_settings_10_GBPS, final_want_bandwidth_settings_10_GBPS),
                ("10_MBPS", want_bandwidth_settings_10_MBPS, have_bandwidth_settings_10_MBPS, final_want_bandwidth_settings_10_MBPS),
                ("1_GBPS", want_bandwidth_settings_1_GBPS, have_bandwidth_settings_1_GBPS, final_want_bandwidth_settings_1_GBPS),
                ("1_MBPS", want_bandwidth_settings_1_MBPS, have_bandwidth_settings_1_MBPS, final_want_bandwidth_settings_1_MBPS)
            ]:
                # Compare and merge `want_bandwidth_settings` and `have_bandwidth_settings`
                want_bandwidth_settings = want_bandwidth_settings or {}
                have_bandwidth_settings = have_bandwidth_settings or {}
                for key, value in want_bandwidth_settings.items():
                    normalized_key = key.upper().replace(' ', '_')  # Normalize key to uppercase with underscores
                    if normalized_key in have_bandwidth_settings:
                        if have_bandwidth_settings[normalized_key] != value:
                            final_want_bandwidth_settings[normalized_key] = value
                        else:
                            final_want_bandwidth_settings[normalized_key] = have_bandwidth_settings[normalized_key]
                    else:
                        final_want_bandwidth_settings[normalized_key] = value

                for key, value in have_bandwidth_settings.items():
                    if key not in final_want_bandwidth_settings:
                        final_want_bandwidth_settings[key] = value

            normalized_have = {k.upper(): v for k, v in have_bandwidth_settings.items()}
            normalized_want = {k.upper(): v for k, v in want_bandwidth_settings.items()}

            self.log(want_bandwidth_settings)
            self.log(have_bandwidth_settings)
            instance_id_bandwidth_settings = {
                "HUNDRED_GBPS": {key: instance_id_bandwidth_settings_100_GBPS.get(key, None) for key in final_want_bandwidth_settings_100_GBPS},
                "HUNDRED_MBPS": {key: instance_id_bandwidth_settings_100_MBPS.get(key, None) for key in final_want_bandwidth_settings_100_MBPS},
                "TEN_GBPS": {key: instance_id_bandwidth_settings_10_GBPS.get(key, None) for key in final_want_bandwidth_settings_10_GBPS},
                "TEN_MBPS": {key: instance_id_bandwidth_settings_10_MBPS.get(key, None) for key in final_want_bandwidth_settings_10_MBPS},
                "ONE_GBPS": {key: instance_id_bandwidth_settings_1_GBPS.get(key, None) for key in final_want_bandwidth_settings_1_GBPS},
                "ONE_MBPS": {key: instance_id_bandwidth_settings_1_MBPS.get(key, None) for key in final_want_bandwidth_settings_1_MBPS}
            }

            final_bandwidth_settings = {
                "HUNDRED_GBPS": final_want_bandwidth_settings_100_GBPS,
                "HUNDRED_MBPS": final_want_bandwidth_settings_100_MBPS,
                "TEN_GBPS": final_want_bandwidth_settings_10_GBPS,
                "TEN_MBPS": final_want_bandwidth_settings_10_MBPS,
                "ONE_GBPS": final_want_bandwidth_settings_1_GBPS,
                "ONE_MBPS": final_want_bandwidth_settings_1_MBPS
            }

            want_dscp_settings = {
                key.upper(): value.upper() if isinstance(value, str) else value
                for key, value in required_details.get('dscp_settings', {}).items()
            }

            # Current DSCP settings from the current profiles
            have_dscp_settings = {
                tc['trafficClass']: tc['dscp']
                for profile in current_profiles
                for clause in profile.get('clause', [])
                if 'tcDscpSettings' in clause
                for tc in clause['tcDscpSettings']
            }
            final_want_dscp_dict = {}
            for traffic_class, want_value in want_dscp_settings.items():
                want_value = int(want_value)
                self.log(want_value)
                if traffic_class in have_dscp_settings:
                    have_value = have_dscp_settings[traffic_class]
                    if want_value == have_value:
                        final_want_dscp_dict[traffic_class] = have_value
                    else:
                        final_want_dscp_dict[traffic_class] = want_value
                else:
                    final_want_dscp_dict[traffic_class] = want_value

            if not want_dscp_settings:
                final_want_dscp_dict = have_dscp_settings

            id_dscp_mapping = {}

            for profile in current_profiles:
                for clause in profile.get('clause', []):
                    if clause.get('type') == 'DSCP_CUSTOMIZATION':
                        for dscp_setting in clause.get('tcDscpSettings', []):
                            dscp = dscp_setting.get('dscp')
                            traffic_class = dscp_setting.get('trafficClass')
                            instance_id = dscp_setting.get('instanceId')
                            if dscp and traffic_class and instance_id:
                                id_dscp_mapping[traffic_class] = instance_id

            dscp_update_required = False

            final_want_dscp_dict_normalized = {key: str(value) for key, value in final_want_dscp_dict.items()}
            have_dscp_settings_normalized = {key: str(value) for key, value in have_dscp_settings.items()}

            if not have_dscp_settings:
                dscp_update_required = False
            elif final_want_dscp_dict_normalized != have_dscp_settings_normalized:
                dscp_update_required = True
            else:
                dscp_update_required = False

            bandwidth_update_required = False

            for speed, final_bandwidth in final_bandwidth_settings.items():
                if speed == 'HUNDRED_GBPS':
                    have_bandwidth = have_bandwidth_settings_100_GBPS
                elif speed == 'HUNDRED_MBPS':
                    have_bandwidth = have_bandwidth_settings_100_MBPS
                elif speed == 'TEN_GBPS':
                    have_bandwidth = have_bandwidth_settings_10_GBPS
                elif speed == 'TEN_MBPS':
                    have_bandwidth = have_bandwidth_settings_10_MBPS
                elif speed == 'ONE_GBPS':
                    have_bandwidth = have_bandwidth_settings_1_GBPS
                elif speed == 'ONE_MBPS':
                    have_bandwidth = have_bandwidth_settings_1_MBPS

                for traffic_class, final_value in final_bandwidth.items():
                    have_value = have_bandwidth.get(traffic_class, None)
                    if have_value != final_value:
                        bandwidth_update_required = True

            update_required = False

            if 'new_profile_name' in required_details:
                profile_name = queuing_profile['current_queuing_profile'][0].get("name")
                new_profile_name = required_details['new_profile_name']
                if not (new_profile_name == profile_name):
                    profile_name = required_details['new_profile_name']
                    update_required = True
            else:
                profile_name = queuing_profile['current_queuing_profile'][0].get("name")

            if 'profile_description' in required_details:
                profile_desc = required_details['profile_description']
                if profile_desc != queuing_profile['current_queuing_profile'][0].get("description"):
                    update_required = True
                    profile_desc = required_details['profile_description']
            else:
                profile_desc = queuing_profile['current_queuing_profile'][0].get("description")

            if not dscp_update_required and not bandwidth_update_required and not update_required:
                self.status = "success"
                self.result['changed'] = False
                self.msg = "application queuing profile '{0}' does not need any update".format(profile_name)
                self.result['msg'] = self.msg
                self.result['response'] = self.msg
                self.log(self.msg, "INFO")
                return self

            # Construct the payload for DSCP customization
            instance_ids = {}
            for profile in current_profiles:
                for clause in profile.get('clause', []):
                    if 'type' in clause and clause['type'] == 'DSCP_CUSTOMIZATION':
                        instance_ids['dscp'] = clause.get('instanceId')
                    if 'interfaceSpeedBandwidthClauses' in clause and clause['interfaceSpeedBandwidthClauses']:
                        instance_ids['bandwidth'] = clause.get('instanceId')

            speed_to_instance_id = {}

            # Loop through the current_profiles to extract the instanceId for each speed
            for profile in current_profiles:
                for clause in profile.get('clause', []):
                    if 'interfaceSpeedBandwidthClauses' in clause:
                        for speed_bandwidth_clause in clause['interfaceSpeedBandwidthClauses']:
                            speed = speed_bandwidth_clause.get('interfaceSpeed')
                            instance_id = speed_bandwidth_clause.get('instanceId')

                            # Store the instanceId in the dictionary with interfaceSpeed as the key
                            if speed and instance_id:
                                speed_to_instance_id[speed] = instance_id

            param = {
                "id": current_profiles[0].get("id"),
                "name": profile_name,
                "description": profile_desc,
                "clause": []
            }

            # Loop through the speeds and bandwidth settings to create the clauses dynamically
            for profile in current_profiles:
                for clause in profile.get('clause', []):
                    if 'interfaceSpeedBandwidthClauses' in clause and clause['interfaceSpeedBandwidthClauses']:

                        params = {
                            "instanceId": instance_ids.get("bandwidth"),
                            "type": "BANDWIDTH",
                            "isCommonBetweenAllInterfaceSpeeds": False,
                            "interfaceSpeedBandwidthClauses": []
                        }
                        param["clause"].append(params)

                        # Loop through the speeds and bandwidth settings for this profile
                        for speed, bandwidth_settings in instance_id_bandwidth_settings.items():
                            clause = {
                                "instanceId": speed_to_instance_id.get(speed) ,
                                "interfaceSpeed": speed,
                                "tcBandwidthSettings": []
                            }

                            for traffic_class, instance_id in bandwidth_settings.items():
                                clause["tcBandwidthSettings"].append({
                                    "trafficClass": traffic_class,
                                    "instanceId": instance_id,
                                    "bandwidthPercentage": final_bandwidth_settings[speed].get(traffic_class, 0)
                                })

                            params["interfaceSpeedBandwidthClauses"].append(clause)

                    if 'tcDscpSettings' in clause and clause['tcDscpSettings']:
                        dscp_clause = {
                            "instanceId": instance_ids.get("dscp"),
                            "type": "DSCP_CUSTOMIZATION",
                            "tcDscpSettings": []
                        }

                        for traffic_class, dscp_value in final_want_dscp_dict.items():
                            dscp_clause["tcDscpSettings"].append({
                                "instanceId": id_dscp_mapping[traffic_class],
                                "trafficClass": traffic_class,
                                "dscp": dscp_value
                            })

                        param["clause"].append(dscp_clause)

                    payload = [param]

            self.log(json.dumps(payload, indent=2))

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='update_application_policy_queuing_profile',
                op_modifies=True,
                params={"payload": payload}
            )

            self.log("Received API response from 'update_application_policy_queuing_profile' for update: {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "update_application_policy_queuing_profile")

            if self.status not in ["failed", "exited"]:
                self.log("Application policy queuing profile '{0}' updated successfully.".format(profile_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application policy queuing profile '{0}' updated successfully.".format(profile_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Update of the application policy queuing profile failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "{0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def create_queuing_profile(self):
        """
        Creates an application queuing profile in Cisco Catalyst Center.

        Description:
            This method validates the provided configuration for creating an application queuing profile. It ensures
            mandatory fields are present and verifies the total bandwidth percentage for different interface speeds.
            The method constructs a payload based on the provided bandwidth and DSCP settings, and invokes the
            appropriate API to create the queuing profile. The result is logged and stored in the instance attributes.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self: The current instance of the class, updated with the result of the create operation. Updates include:

        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        new_queuing_profile_details = self.config.get("application_queuing_details", [])[0]
        self.log("Queuing Profile Details: {}".format(new_queuing_profile_details))

        # Check for mandatory fields
        mandatory_fields = ["profile_name"]

        for field in mandatory_fields:
            if not new_queuing_profile_details.get(field):
                self.msg = (
                    "The following parameter(s): {0} could not be found and are mandatory to create application queuing profile."
                ).format(field)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        for detail in self.config.get("application_queuing_details", []):
            self.log(new_queuing_profile_details)
            self.log(detail)
            if detail.get("bandwidth_settings"):
                bandwidth_settings = detail["bandwidth_settings"]

                # if not bandwidth_settings.get("bandwidth_percentages"):
                #     # Check if 'bandwidth_percentages' is missing
                #     self.msg = (
                #         "The following parameter(s): 'bandwidth_percentages' could not be found and are mandatory "
                #         "to create application queuing profile when type is bandwidth."
                #     )
                #     self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                # Check if 'is_common_between_all_interface_speeds' is true
                if bandwidth_settings.get("is_common_between_all_interface_speeds") == True:

                    if bandwidth_settings.get("bandwidth_percentages"):
                        bandwidth_percentages = bandwidth_settings["bandwidth_percentages"]
                        
                        # Define the expected traffic classes
                        required_traffic_classes = [
                            "transactional_data", "best_effort", "voip_telephony", "multimedia_streaming",
                            "real_time_interactive", "multimedia_conferencing", "signaling", "scavenger",
                            "ops_admin_mgmt", "broadcast_video", "network_control", "bulk_data"
                        ]
                        
                        # Check if all required traffic classes are present
                        missing_traffic_classes = [tc for tc in required_traffic_classes if tc not in bandwidth_percentages]
                        
                        if missing_traffic_classes:
                            missing_classes = ", ".join(missing_traffic_classes)
                            self.msg = (
                                "The following traffic class(es) are missing and are required to create application "
                                "policy queuing profile: {0}".format(missing_classes)
                            )
                            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                            
                    else:
                        self.msg = "'bandwidth_percentages' is missing in 'bandwidth_settings'."
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                    # Check if 'interface_speed' is missing
                    if not bandwidth_settings.get("interface_speed"):
                        self.msg = (
                            "The following parameter(s): 'interface_speed' could not be found and are mandatory "
                            "to create application queuing profile when 'is_common_between_all_interface_speeds' is true."
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    # Check if 'interface_speed' is present and not equal to 'ALL'
                    elif bandwidth_settings.get("interface_speed") != "ALL":
                        self.msg = (
                            "When 'is_common_between_all_interface_speeds' is true, 'interface_speed' must be set to 'ALL'."
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                # Check if 'is_common_between_all_interface_speeds' is false
                elif bandwidth_settings.get("is_common_between_all_interface_speeds") == False:
                    if not bandwidth_settings.get("interface_speed_settings"):
                        self.msg = (
                            "The following parameter(s): 'interface_speed_settings' could not be found and are mandatory "
                            "to create application queuing profile when 'is_common_between_all_interface_speeds' is false."
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        if new_queuing_profile_details['bandwidth_settings']['is_common_between_all_interface_speeds'] is False:
            if 'bandwidth_settings' in new_queuing_profile_details:
                for interface in new_queuing_profile_details['bandwidth_settings']['interface_speed_settings']:
                    total_percentage = sum(int(value) for value in interface['bandwidth_percentages'].values())

                    if total_percentage != 100:
                        self.msg = "Validation ERROR at interface speed:{0} (Total:{1}%) Should be total 100%".format(interface['interface_speed'], total_percentage)
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        if (
            new_queuing_profile_details.get('bandwidth_settings', {})
            .get('is_common_between_all_interface_speeds') is True
            or new_queuing_profile_details.get('type') == ['dscp']
        ):
            param = {
                "name": new_queuing_profile_details.get('profile_name', ''),
                "description": new_queuing_profile_details.get('profile_description', ''),
                "clause": []
            }

            if new_queuing_profile_details.get('bandwidth_settings'):
                self.log("As we are passing common traffic class bandwidth percentage for all the interface speeds")
                bandwidth_clause = {
                    "type": "BANDWIDTH",
                    "isCommonBetweenAllInterfaceSpeeds": new_queuing_profile_details['bandwidth_settings'].get(
                        'is_common_between_all_interface_speeds', False
                    ),
                    "interfaceSpeedBandwidthClauses": [
                        {
                            "interfaceSpeed": new_queuing_profile_details['bandwidth_settings'].get('interface_speed', ''),
                            "tcBandwidthSettings": [
                                {
                                    "trafficClass": key.upper(),
                                    "bandwidthPercentage": int(value)
                                }
                                for key, value in new_queuing_profile_details['bandwidth_settings']['bandwidth_percentages'].items()
                            ]
                        }
                    ]
                }
                param['clause'].append(bandwidth_clause)

            if new_queuing_profile_details.get('dscp_settings'):
                dscp_clause = {
                    "type": "DSCP_CUSTOMIZATION",
                    "tcDscpSettings": [
                        {
                            "trafficClass": key.upper(),
                            "dscp": value
                        }
                        for key, value in new_queuing_profile_details['dscp_settings'].items()
                    ]
                }
                param['clause'].append(dscp_clause)

        elif new_queuing_profile_details['bandwidth_settings']['is_common_between_all_interface_speeds'] is False:

            self.log("As we are passing different traffic class bandwidth percentage for six different interface speeds")
            param = {
                "name": new_queuing_profile_details['profile_name'],
                "description": new_queuing_profile_details['profile_description'],
                "clause": [
                    {
                        "isCommonBetweenAllInterfaceSpeeds": new_queuing_profile_details['bandwidth_settings']['is_common_between_all_interface_speeds'],
                        "interfaceSpeedBandwidthClauses": []
                    }
                ]
            }

            for interface in new_queuing_profile_details['bandwidth_settings']['interface_speed_settings']:
                interface_speeds = interface['interface_speed'].split(',')
                for speed in interface_speeds:
                    interface_speed_clause = {
                        "interfaceSpeed": speed.strip(),
                        "tcBandwidthSettings": [
                            {
                                "trafficClass": key.upper(),
                                "bandwidthPercentage": int(value)
                            }
                            for key, value in interface['bandwidth_percentages'].items()
                        ]
                    }
                    param["clause"][0]["interfaceSpeedBandwidthClauses"].append(interface_speed_clause)

            if 'dscp_settings' in new_queuing_profile_details:
                dscp_clause = {
                    "type": "DSCP_CUSTOMIZATION",
                    "tcDscpSettings": [
                        {
                            "trafficClass": key.upper(),
                            "dscp": value
                        }
                        for key, value in new_queuing_profile_details['dscp_settings'].items()
                    ]
                }
                param['clause'].append(dscp_clause)

        self.log("Payload for Queuing Profile: {}".format(json.dumps(param, indent=4)))
        profile_name = new_queuing_profile_details.get('profile_name')


        try:
            response = self.dnac._exec(
                family="application_policy",
                function='create_application_policy_queuing_profile',
                op_modifies=True,
                params={"payload": [param]}
            )

            self.log("Received API response from 'create_application_policy_queuing_profile': {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "create_application_policy_queuing_profile")

            if self.status not in ["failed", "exited"]:
                self.log("Application queuing profile created successfully.", "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application queuing profile '{0}' created successfully.").format(profile_name)
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = (
                    "failed to create application queuing profile reason - {0}").format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "error occured while creating queuing profile: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_diff_deleted(self, config):
        """
        Manages the deletion of an application set based on the provided configuration.

        Description:
            This method checks the provided `config` for `application_set_details`. If the details are found, it triggers
            the `delete_application_set` method to delete the application set and subsequently checks the return status
            of the operation.

        Args:
            config (dict): A dictionary containing the configuration details, including `application_set_details`.

        Returns:
            None: The method performs the operation but does not return any value.

        Raises:
            None: Any errors or unexpected behaviors are handled internally by the called methods.
        """

        self.config = config

        if config.get("application_set_details"):
            self.delete_application_set().check_return_status()

        if config.get("application_queuing_details"):
            self.delete_application_queuing_profile().check_return_status()

        if config.get("application_details"):
            self.delete_application().check_return_status()

        if config.get("application_policy_details"):
            self.delete_application_policy().check_return_status()

        return self

    def delete_application_policy(self):
        """
        Delete an existing application policy in Cisco Catalyst Center.

        Args:
            self (object): An instance of the class for interacting with Cisco Catalyst Center.

        Returns:
            self: The updated instance with 'status', 'msg', and 'result' attributes.

        Description:
            This method deletes an application policy from Cisco Catalyst Center by first checking if the policy exists.
            If the policy is not found, it logs a message and returns. If the policy exists, it retrieves the
            policy ID and sends a delete request to Cisco Catalyst Center via the API. The response is processed,
            and the method logs success or failure. If an error occurs, it is caught and handled appropriately.
        """

        want_application_policy_details = self.config.get("application_policy_details")
        self.log("Queuing Profile Details: {0}".format(want_application_policy_details))
        application_policy_name = want_application_policy_details.get("name")
        application_policy_details = self.have

        if application_policy_details.get("application_policy_exists") is False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "Application policy '{0}' does not present in the cisco catalyst center or its been already deleted".format(application_policy_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        get_ids = self.have
        ids_list = []
        application_set_names = []
        if not want_application_policy_details.get("application_set_name"):
            if "current_application_policy" in get_ids:
                for policy in get_ids["current_application_policy"]:
                    if "id" in policy:
                        ids_list.append(policy["id"])
        else:
            if "current_application_policy" in get_ids:
                for policy in get_ids["current_application_policy"]:
                    application_set_name = want_application_policy_details.get("application_set_name", [])
                    for app_name in application_set_name:
                        if app_name in policy.get('name', ''):
                            application_set_names.append(app_name)
                            ids_list.append(policy.get('id'))
                            break

            application_set_name_not_available = [
                app_name for app_name in application_set_name
                if app_name not in [name.strip() for name in application_set_names]
            ]

        if want_application_policy_details.get("application_set_name"):
            if not application_set_names:
                self.status = "success"
                self.result['changed'] = False
                self.msg = (
                    "Application set(s) '{0}' does not present in the application policy {1} "
                    "or it's been already removed.".format(application_set_name, application_policy_name)
                )
                self.result['msg'] = self.msg
                self.result['response'] = self.msg
                self.log(self.msg, "INFO")
                return self

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='application_policy_intent',
                op_modifies=True,
                params={'deleteList': ids_list, }
            )

            self.log("Received API response from 'application_policy_intent' for deletion: {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "application_policy_intent")

            if not want_application_policy_details.get("application_set_name"):
                if self.status not in ["failed", "exited"]:
                    self.log("Application policy '{0}' deleted successfully.".format(application_policy_name), "INFO")
                    self.status = "success"
                    self.result['changed'] = True
                    self.msg = ("Application policy '{0}' deleted successfully.".format(application_policy_name))
                    self.result['response'] = self.msg
                    return self
            else:
                if self.status not in ["failed", "exited"]:
                    self.log(
                        "Application set '{0}' has been removed from the application policy {1} successfully. "
                        "and application set - {2} are not present in the policy".format(
                            application_set_name, application_policy_name, application_set_name_not_available
                        ),
                        "INFO"
                    )
                    self.status = "success"
                    self.result['changed'] = True
                    if application_set_name_not_available:
                        self.msg = (
                            "Application set '{0}' has been removed from the application policy {1} successfully. "
                            "and application set - {2} are not present in the policy.".format(
                                application_set_names, application_policy_name, application_set_name_not_available))
                    else:
                        self.msg = (
                            "application set '{0}' has been removed from the application policy {1} successfully.".format(
                                application_set_name, application_policy_name))

                    self.result['response'] = self.msg
                    return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Deletion of the application policy failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "{0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def delete_application_queuing_profile(self):
        """
        Deletes an existing application set in Cisco Catalyst Center.

        Description:
            This method checks if the specified application set exists in Cisco Catalyst Center. If the application set does
            not exist or has already been deleted, it logs the status and exits without performing any operations. If the
            application set exists, the method retrieves its ID and triggers the appropriate API call to delete it. The
            method monitors the task's response status and logs the outcome.

        Args:
            None: The method uses the `config` attribute to retrieve application set details, such as `application_set_name`.

        Returns:
            self: The current instance of the class, updated with the result of the delete operation.

        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        application_queuing_profile_details = self.config.get("application_queuing_details", [])[0]
        self.log("Queuing Profile Details: {}".format(application_queuing_profile_details))
        application_queuing_profile_name = application_queuing_profile_details.get("profile_name")
        application_queuing_profile_details = self.have
        self.log(application_queuing_profile_details)

        if application_queuing_profile_details.get("queuing_profile_exists") is False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = (
                "Application queuing profile '{0}' does not present in the Cisco Catalyst Center "
                "or it has already been deleted.".format(application_queuing_profile_name)
            )
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        queuing_profile_id = application_queuing_profile_details.get('current_queuing_profile', [])[0].get('id', None)
        self.log(queuing_profile_id)

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='delete_application_policy_queuing_profile',
                op_modifies=True,
                params={'id': queuing_profile_id, }
            )

            self.log("Received API response from 'delete_application_policy_queuing_profile': {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "delete_application_policy_queuing_profile")

            if self.status not in ["failed", "exited"]:
                self.log("Application policy queuing profile '{0}' deleted successfully.".format(application_queuing_profile_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application policy queuing profile '{0}' deleted successfully.".format(application_queuing_profile_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Deletion of the application policy queuing profile failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "Error occured while deleting queuing profile: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def delete_application_set(self):
        """
        Deletes an existing application set in Cisco Catalyst Center.

        Description:
            This method checks if the specified application set exists in Cisco Catalyst Center. If the application set does
            not exist or has already been deleted, it logs the status and exits without performing any operations. If the
            application set exists, the method retrieves its ID and triggers the appropriate API call to delete it. The
            method monitors the task's response status and logs the outcome.

        Args:
            None: The method uses the `config` attribute to retrieve application set details, such as `application_set_name`.

        Returns:
            self: The current instance of the class, updated with the result of the delete operation.

        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        application_set_detail = self.config.get("application_set_details", [])[0]
        self.log("Application set details : {0}".format(application_set_detail))
        application_set_name = application_set_detail.get("application_set_name")
        application_set_details = self.have

        if application_set_details.get("application_set_exists") is False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "Application set '{0}' does not present in the cisco catalyst center or its been already deleted".format(application_set_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        application_set_id = application_set_details['current_application_set'][0]['id'] if application_set_details['current_application_set'] else None
        self.log(application_set_id)

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='delete_application_set',
                op_modifies=True,
                params={'id': application_set_id, }
            )

            self.log("Received API response from 'delete_application_set': {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "delete_application_set")

            if self.status not in ["failed", "exited"]:
                self.log("Application set '{0}' deleted successfully.".format(application_set_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application set '{0}' deleted successfully.".format(application_set_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Deletion of the application set failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "Error occured while deleting application set: {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def delete_application(self):
        """
        Deletes an existing application in Cisco Catalyst Center.

        Description:
            This method checks if the specified application exists in Cisco Catalyst Center. If the application
            does not exist or has already been deleted, it logs the status and exits without performing any operations.
            If the application exists, the method retrieves its ID and triggers the appropriate API call to delete it.
            The method monitors the task's response status and logs the outcome.

        Args:
            None: The method uses the `config` attribute to retrieve application details, such as `application_name`.

        Returns:
            self: The current instance of the class, updated with the result of the delete operation.

        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        application_details = self.config.get("application_details", [])
        self.log("application Details: {}".format(application_details))
        application_name = application_details.get("name")
        application_deatils = self.have

        if application_deatils.get("application_exists") is False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "Application '{0}' does not present in the cisco catalyst center or its been already deleted".format(application_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        application_id = application_deatils['current_application'][0]['id'] if application_deatils['current_application'] else None
        self.log(application_id)

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='delete_application_set2',
                op_modifies=True,
                params={'id': application_id, }
            )
            self.log("Received API response from 'delete_application': {}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "delete_application")

            if self.status not in ["failed", "exited"]:
                self.log("Application '{0}' deleted successfully.".format(application_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("Application '{0}' deleted successfully.".format(application_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.msg = "Deletion of the application failed due to - {0}".format(fail_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "error - {0}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def verify_diff_merged(self, config):
        """
            Verifies the merged status (Addition/Updation) of application policy in Cisco Catalyst Center.

            Args:
                self (object): An instance of a class used for interacting with Cisco Catalyst Center.
                config (dict): The configuration details to be verified.

            Returns:
                self (object): An instance of the class with the status of the verification process.

            Description:
                This method checks the merged state of a configuration in Cisco Catalyst Center by comparing the current state 
                (have) with the desired state (want). It retrieves, logs, and validates whether the specified configuration 
                aligns with the existing configuration in Cisco Catalyst Center.

                The method performs the following verifications:
                - Validates if the application queuing profile exists and logs the result.
                - Verifies the existence of the application and logs the result.
                - Confirms if the application update was required and successfully executed.
                - Checks the existence of the application policy and logs the result.

                For each of these checks, the method logs the current state, the desired state, and provides status messages 
                indicating whether the operation was successful, or if there are discrepancies that may require further review.
            """
        self.log("Verify starts here verify diff merged")

        if self.want.get("application_queuing_details"):
            self.get_have()
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            application_queuing_profile_exist = self.have.get("queuing_profile_exists")
            application_queuing_profile_name = self.want.get("application_queuing_details", [])[0].get("profile_name")

            if application_queuing_profile_exist:
                self.status = "success"
                self.msg = (
                    "The requested application queuing profile {0} is present in the Cisco Catalyst Center "
                    "and its creation has been verified.".format(application_queuing_profile_name)
                )
                self.log(self.msg, "INFO")
            else:
                self.log("The playbook input for application queuing profile {0} does not align with the Cisco Catalyst Center, indicating that the \
                         merge task may not have executed successfully.".format(application_queuing_profile_name), "INFO")

        if self.want.get("application_details"):
            self.get_have()
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            application_exists = self.have.get("application_exists")
            application_name = self.want.get("application_details").get("name")

            if application_exists:
                self.status = "success"
                self.msg = "The requested application {0} is present in the Cisco Catalyst Center and its creation has been verified.".format(application_name)
                self.log(self.msg, "INFO")
            else:
                self.log("The playbook input for application {0} does not align with the Cisco Catalyst Center, indicating that the \
                         merge task may not have executed successfully.".format(application_name), "INFO")

            is_application_available = self.have.get("application_exists")

            if is_application_available:
                application_updated = self.is_update_required_for_application()

                if application_updated and getattr(self, 'application_updated', False):
                    self.log("The update for application {0} has been successfully verified.".format(application_name), "INFO")
                    self.status = "success"

        if self.want.get("application_policy_details"):
            self.get_have()
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            application_policy_exist = self.have.get("application_policy_exists")
            application_policy_name = self.want.get("application_policy_details").get("name")

            if application_policy_exist:
                self.status = "success"
                self.msg = (
                    "The requested application policy {0} is present in the Cisco Catalyst Center "
                    "and its creation has been verified.".format(application_policy_name)
                )
                self.log(self.msg, "INFO")
            else:
                self.log("The playbook input for application policy {0} does not align with the Cisco Catalyst Center, indicating that the \
                         merge task may not have executed successfully.".format(application_policy_name), "INFO")

        return self

    def verify_diff_deleted(self, config):
        """
            Verifies the deletion status of configurations in Cisco Catalyst Center.

            Args:
                self (object): An instance of the class used for interacting with Cisco Catalyst Center.
                config (dict): The configuration dictionary containing the details to be verified, including application 
                            queuing profiles, applications, and application policies.

            Returns:
                self: The current instance of the class, with updated 'status' and 'msg' attributes based on the verification.

            Description:
                This method checks the deletion status of configurations in Cisco Catalyst Center by comparing the current state
                (have) and desired state (want) of the configuration. It verifies that the configurations, if requested for deletion, 
                are no longer present in the Cisco Catalyst Center.

                The method performs the following verifications:
                - Ensures that the specified application queuing profile has been deleted.
                - Ensures that the specified application has been deleted.
                - Ensures that the specified application policy has been deleted.

                The function logs the success or failure of the deletion verification and updates the status accordingly. If the 
                configuration to be deleted is found to be absent in the current state, the deletion is considered successful, and 
                a success message is logged.
            """
        self.log("Verify starts here verify diff deleted")

        if self.want.get("application_queuing_details"):
            self.get_have()
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            application_queuing_profile_exist = self.have.get("queuing_profile_exists")
            application_queuing_profile_name = self.want.get("application_queuing_details", [])[0].get("profile_name")

            if not application_queuing_profile_exist:
                self.status = "success"
                self.msg = (
                    "The requested application queuing profile {0} is not present in the Cisco Catalyst Center "
                    "and its deletion has been verified.".format(application_queuing_profile_name)
                )
                self.log(self.msg, "INFO")
            else:
                self.log("The playbook input for application queuing profile {0} does not align with the Cisco Catalyst Center, indicating that the \
                         merge task may not have executed successfully.".format(application_queuing_profile_name), "INFO")

        if self.want.get("application_details"):
            self.get_have()
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            application_exists = self.have.get("application_exists")
            application_name = self.want.get("application_details").get("name")

            if not application_exists:
                self.status = "success"
                self.msg = (
                    "The requested application {0} is not present in the Cisco Catalyst Center "
                    "and its deletion has been verified.".format(application_name)
                )
                self.log(self.msg, "INFO")
            else:
                self.log("The playbook input for application {0} does not align with the Cisco Catalyst Center, indicating that the \
                         merge task may not have executed successfully.".format(application_name), "INFO")

        if self.want.get("application_policy_details"):
            self.get_have()
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            application_policy_exist = self.have.get("application_policy_exists")
            application_policy_name = self.want.get("application_policy_details").get("name")

            if not application_policy_exist:
                self.status = "success"
                self.msg = (
                    "The requested application policy {0} is not present in the Cisco Catalyst Center "
                    "and its deletion has been verified.".format(application_policy_name)
                )
                self.log(self.msg, "INFO")
            else:
                self.log("The playbook input for application policy {0} does not align with the Cisco Catalyst Center, indicating that the \
                         merge task may not have executed successfully.".format(application_policy_name), "INFO")
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
                    'config_verify': {'type': 'bool', "default": True},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_application = ApplicationPolicy(module)
    state = ccc_application.params.get("state")

    if state not in ccc_application.supported_states:
        ccc_application.status = "invalid"
        ccc_application.msg = "State {0} is invalid".format(state)
        ccc_application.check_return_status()

    ccc_application.validate_input().check_return_status()
    config_verify = ccc_application.params.get("config_verify")

    for config in ccc_application.validated_config:
        ccc_application.reset_values()
        ccc_application.get_want(config).check_return_status()
        ccc_application.get_have().check_return_status()
        ccc_application.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_application.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_application.result)


if __name__ == '__main__':
    main()
