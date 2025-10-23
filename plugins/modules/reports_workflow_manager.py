#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to manage Report configurations in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = ["Megha Kandari, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: reports_workflow_manager
short_description: Resource module for managing Reports in Cisco Catalyst Center.
description:
  - This module manages Report configurations in Cisco Catalyst Center.
  - It allows you to create and schedule customized reports across wired and
    wireless network entities.
  - Supports configuration of report name, scheduling, entity selection,
    filters, field groups, and output format options.
  - Enables scheduling with immediate, later, or recurring execution patterns.
  - Provides delivery methods including local download, email notification,
    and webhook integration.
  - Reports help monitor network and client health, device behavior,
    compliance status, and utilization trends.
  - Applicable from Cisco Catalyst Center version 2.3.7.9 and later.
version_added: '6.41.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Megha Kandari (@kandarimegha)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description:
      - Set to C(True) to enable configuration verification on Cisco
        Catalyst Center after applying the playbook config.
      - This will ensure that the system validates the configuration state
        after the change is applied.
    type: bool
    default: false
  state:
    description:
      - Specifies the desired state for the configuration.
      - If C(merged), the module will create or schedule new reports.
      - If C(deleted), the module will remove existing scheduled reports.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - A list of configuration settings for generating reports in Cisco
        Catalyst Center.
      - Each configuration defines report metadata, scheduling, delivery
        options, view selections, format, and applicable filters.
      - Supports creating, scheduling, and downloading customized network
        reports across various data categories.
    type: list
    elements: dict
    required: true
    suboptions:
      generate_report:
        description:
          - List of report configurations to be created or scheduled.
          - Each entry represents a single report with its complete
            configuration.
          - Reports are processed sequentially, not in parallel,
            which ensures data consistency.
        type: dict
        required: true
        suboptions:
          name:
            description:
              - The name of the report to be generated.
              - Must be unique within the Catalyst Center instance.
              - If not provided, it will be automatically generated using
                the format "<data_category> - <view_name> - <timestamp>".
              - Example auto-generated name "Network - DeviceView - Jul 20
                2025 08:26 PM".
            type: str
            required: false
          view_group_name:
            description:
              - The name of the view group as defined in Catalyst Center. For example, C(Inventory)
              - Used to identify the viewGroupId via API calls.
              - Determines the category of data included in the report.
            type: str
            required: true
            choices:
              - Compliance
              - Executive Summary
              - Inventory
              - SWIM
              - Access Point
              - Long Term
              - Network Devices
              - Group Pair Communication Analytics
              - Telemetry
              - Group Communication Summary
              - EoX
              - Rogue and aWIPS
              - Licensing
              - AI Endpoint Analytics
              - Audit Log
              - Configuration Archive
              - Client
              - Security Advisories
          tags:
            description:
              - Optional list of tags to filter reports.
              - Tags help categorize and organize reports for easier management.
            type: list
            elements: str
            required: false
          view_group_version:
            description:
              - The version of the view group to be used for the report.
              - Determines which version of the view group schema and available fields to use.
              - Different versions may have different available views, field groups, and filtering options.
              - Defaults to C(2.0.0) if not specified.
            type: str
            required: false
            default: "2.0.0"
          schedule:
            description:
              - Defines when the report should be executed (immediately, later, or
                on a recurring basis).
              - Controls the timing and frequency of report generation.
            type: dict
            required: true
            suboptions:
                schedule_type:
                  description:
                    - The scheduling type for the report execution.
                    - C(SCHEDULE_NOW) executes immediately, C(SCHEDULE_LATER) executes
                      at a specific time, C(SCHEDULE_RECURRENCE) executes repeatedly.
                  choices:
                    - SCHEDULE_NOW
                    - SCHEDULE_LATER
                    - SCHEDULE_RECURRENCE
                  type: str
                  required: true
                date_time:
                  description:
                    - Scheduled time for report execution.
                    - Required if schedule_type is C(SCHEDULE_LATER) or
                      C(SCHEDULE_RECURRENCE).
                    - Must be in 'YYYY-MM-DD HH:MM AM/PM' format.
                    - Example "2025-09-02 07:30 PM".
                    - Only future dates are allowed.
                  type: str
                  required: false
                time_zone:
                  description:
                    - Time zone identifier for the schedule.
                    - Uses standard time zone identifiers like C(Asia/Calcutta),
                      C(America/New_York), etc. For a complete list of supported time zones,
                      please refer to the time_zone field in the Inventory Workflow Manager documentation
                      https://galaxy.ansible.com/ui/repo/published/cisco/dnac/content/module/inventory_workflow_manager.
                  type: str
                  required: true
                recurrence:
                  description:
                    - Recurrence settings for scheduled reports.
                    - Required only when schedule_type is C(SCHEDULE_RECURRENCE).
                    - Defines the pattern and frequency of recurring executions.
                  type: dict
                  required: false
                  suboptions:
                    recurrence_type:
                      description:
                        - Type of recurrence pattern.
                        - C(WEEKLY) for daily execution via weekly pattern with all
                          7 days.
                        - C(MONTHLY) for monthly execution on specific day or last day.
                      choices:
                        - WEEKLY
                        - MONTHLY
                      type: str
                      required: true
                    days:
                      description:
                        - List of days for weekly recurrence.
                        - Required for C(WEEKLY) recurrence_type.
                        - Can specify individual days or use C(DAILY) for all seven days.
                        - Must include all 7 days for daily execution or DAILY.
                          ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"] or ["DAILY"].
                      type: list
                      elements: str
                      required: false
                    last_day_of_month:
                      description:
                        - Whether to run on the last day of the month.
                        - Only applicable for C(MONTHLY) recurrence_type.
                        - When true, ignores day_of_month setting.
                      type: bool
                      required: false
                    day_of_month:
                      description:
                        - Specific day of the month to run the report.
                        - Only applicable for C(MONTHLY) recurrence_type when
                          last_day_of_month is false.
                        - Must be an integer between 1 and 31.
                      type: int
                      required: false
                time:
                  description:
                    - Epoch time in milliseconds for scheduled execution.
                    - Automatically generated from date_time during processing.
                    - Used internally by the API for recurring schedules.
                  type: int
                  required: false
                start_date:
                  description:
                    - Epoch start date in milliseconds for recurring schedules.
                    - Automatically generated from date_time during processing.
                    - Used internally by the API to determine recurrence start point.
                  type: int
                  required: false
          deliveries:
            description:
              - Specifies how the generated report should be delivered.
              - Must be a list containing exactly one delivery configuration.
              - Supports three delivery methods DOWNLOAD, NOTIFICATION (email),
                and WEBHOOK.
            type: dict
            required: true
            suboptions:
              delivery_type:
                description:
                  - Delivery type for the report.
                  - C(DOWNLOAD) saves report to local file system.
                  - C(NOTIFICATION) sends report via email notification.
                  - C(WEBHOOK) triggers a configured webhook endpoint.
                choices:
                  - DOWNLOAD
                  - NOTIFICATION
                  - WEBHOOK
                type: str
                required: true
              file_path:
                description:
                  - Local file system path where the report should be downloaded.
                  - Required only when delivery_type is C(DOWNLOAD).
                  - Must be a valid directory path where the user has write
                    permissions.
                type: str
                required: false
              notification_endpoints:
                description:
                  - Required when delivery_type is C(NOTIFICATION).
                  - Must be a list containing exactly one email endpoint
                    configuration.
                  - Specifies email recipients and notification preferences.
                type: list
                elements: dict
                required: false
                suboptions:
                  email_addresses:
                    description:
                    - List of email recipients for the notification.
                    - Required when delivery_type is C(NOTIFICATION).
                    - Each email address must be in valid email format.
                    type: list
                    elements: str
                    required: false
                  email_attach:
                    description:
                    - Whether the report should be attached in the notification email.
                    type: bool
                    required: false
                  notify:
                    description:
                    - List of report execution statuses that will trigger
                      a notification.
                    - If not specified, notifications are sent for all statuses.
                    - C(IN_QUEUE) notifies when report is queued for execution.
                    - C(IN_PROGRESS) notifies when report execution starts.
                    - C(COMPLETED) notifies when report execution finishes.
                    choices:
                        - C(IN_QUEUE)
                        - C(IN_PROGRESS)
                        - C(COMPLETED)
                    type: list
                    elements: str
                    required: false
              webhook_name:
                description:
                  - The name of the webhook to be triggered for the report.
                  - Required when delivery_type is C(WEBHOOK).
                  - Must reference an existing webhook configured in Catalyst
                    Center.
                  - The webhook will be called when the report is generated.
                type: str
                required: false
          view:
            description:
              - Contains view details such as view selection, field groups, filters,
                and output format for the report.
              - Defines what data to include and how to present it in the final report.
            type: dict
            required: true
            suboptions:
              view_name:
                description:
                  - The view name from which C(viewId) is derived via API calls.
                  - Must match exactly with available views in the specified view group.
                  - Determines the specific data subset and available fields for
                    the report.
                type: str
                required: true
                choices:
                  - Network Device Compliance # viewName in viewGroup Compliance
                  - Network Device Availability # viewName in viewGroup Network Devices
                  - Channel Change Count # viewName in viewGroup Network Devices
                  - Transmit Power Change Count # viewName in viewGroup Network Devices
                  - VLAN # viewName in viewGroup Network Devices
                  - Port Capacity # viewName in viewGroup Network Devices
                  - Energy Management # viewName in viewGroup Network Devices
                  - PoE # viewName in viewGroup Network Devices
                  - Device CPU and Memory Utilization # viewName in viewGroup Network Devices
                  - Network Interface Utilization # viewName in viewGroup Network Devices
                  - Executive Summary # viewName in viewGroup Executive Summary
                  - All Data # viewName in viewGroup Inventory
                  - Port Reclaim View # viewName in viewGroup Inventory
                  - All Data Version 2.0 # viewName in viewGroup Inventory
                  - All Data # viewName in viewGroup SWIM
                  - All Data Version 2.0 # viewName in viewGroup SWIM
                  - AP # viewName in viewGroup Access Point
                  - AP Radio # viewName in viewGroup Access Point
                  - AP - Usage and Client Breakdown # viewName in viewGroup Access Point
                  - Worst Interferers # viewName in viewGroup Access Point
                  - AP RRM Events # viewName in viewGroup Access Point
                  - AP Performance Report # viewName in viewGroup Long Term
                  - Long Term AP Detail # viewName in viewGroup Long Term
                  - Long Term AP Radio # viewName in viewGroup Long Term
                  - Long Term AP Usage and Client Breakdown # viewName in viewGroup Long Term
                  - Long Term Client Detail # viewName in viewGroup Long Term
                  - Long Term Client Session # viewName in viewGroup Long Term
                  - Long Term Network Device Availability # viewName in viewGroup Long Term
                  - Security Group to Security Group # viewName in viewGroup Group Pair Communication Analytics
                  - Security Group to ISE Endpoint Profile Group # viewName in viewGroup Group Pair Communication Analytics
                  - Security Group to Host Group # viewName in viewGroup Group Pair Communication Analytics
                  - ISE Endpoint Profile Group to Security Group # viewName in viewGroup Group Pair Communication Analytics
                  - ISE Endpoint Profile Group to ISE Endpoint Profile Group # viewName in viewGroup Group Pair Communication Analytics
                  - ISE Endpoint Profile Group to Host Group # viewName in viewGroup Group Pair Communication Analytics
                  - Host Group to Security Group # viewName in viewGroup Group Pair Communication Analytics
                  - Host Group to ISE Endpoint Profile Group # viewName in viewGroup Group Pair Communication Analytics
                  - Host Group to Host Group # viewName in viewGroup Group Pair Communication Analytics
                  - Device Lifecycle Information # viewName in viewGroup Telemetry
                  - Security Group to Security Groups # viewName in viewGroup Group Communication Summary
                  - Security Group to ISE Endpoint Profile Groups # viewName in viewGroup Group Communication Summary
                  - Security Group to Host Groups # viewName in viewGroup Group Communication Summary
                  - ISE Endpoint Profile Group to Security Groups # viewName in viewGroup Group Communication Summary
                  - ISE Endpoint Profile Group to ISE Endpoint Profile Groups # viewName in viewGroup Group Communication Summary
                  - ISE Endpoint Profile Group to Host Groups # viewName in viewGroup Group Communication Summary
                  - Host Group to Security Groups # viewName in viewGroup Group Communication Summary
                  - Host Group to ISE Endpoint Profile Group # viewName in viewGroup Group Communication Summary
                  - Host Group to Host Group # viewName in viewGroup Group Communication Summary
                  - EoX Data # viewName in viewGroup EoX
                  - Threat Detail # viewName in viewGroup Rogue and aWIPS
                  - New Threat # viewName in viewGroup Rogue and aWIPS
                  - Rogue Additional Detail # viewName in viewGroup Rogue and aWIPS
                  - Non Compliant Devices # viewName in viewGroup Licensing
                  - Non Compliance Summary # viewName in viewGroup Licensing
                  - AireOS Controllers Licenses # viewName in viewGroup Licensing
                  - License Usage Upload Details # viewName in viewGroup Licensing
                  - License Historical Usage # viewName in viewGroup Licensing
                  - Endpoint Profiling # viewName in viewGroup AI Endpoint Analytics
                  - Audit Log # viewName in viewGroup Audit Log
                  - Configuration Archive # viewName in viewGroup Configuration Archive
                  - Client # viewName in viewGroup Client
                  - Client Summary # viewName in viewGroup Client
                  - Top N Summary # viewName in viewGroup Client
                  - Client Detail # viewName in viewGroup Client
                  - Client Trend # viewName in viewGroup Client
                  - Client Session # viewName in viewGroup Client
                  - Busiest Client # viewName in viewGroup Client
                  - Unique Clients and Users Summary # viewName in viewGroup Client
                  - Security Advisories Data  # viewName in viewGroup Security Advisories
              field_groups:
                description:
                  - Groups of fields to include in the report, as defined in the
                    selected view.
                  - Can be empty list to include all available fields for the view.
                  - Field group availability depends on the selected view_name.
                type: list
                elements: dict
                required: true
                suboptions:
                  name:
                    description:
                      - Name of the field group as defined in the view metadata.
                      - Must match exactly with available field groups for the
                        selected view.
                    type: str
                    required: true
                  fields:
                    description:
                      - List of specific fields to include within the field group.
                      - Can be empty list to include all fields in the group.
                      - Field availability depends on the selected field group.
                    type: list
                    elements: dict
                    required: true
                    suboptions:
                      name:
                        description:
                          - Field identifier as defined in the view metadata.
                          - Must match exactly with available fields in the group.
                        type: str
                        required: true
              format:
                description:
                  - Specifies the output format of the report.
                  - Determines how the report data will be structured and presented.
                type: dict
                required: true
                suboptions:
                  format_type:
                    description:
                      - Type of format to be used for the report output.
                      - C(CSV) for comma-separated values
                      - C(PDF) for document format
                      - C(JSON) for structured data
                      - C(TDE) for Tableau data extract.
                    choices:
                      - CSV
                      - PDF
                      - JSON
                      - TDE
                    type: str
                    required: true
              filters:
                description:
                  - Filters to be applied to narrow down the report data.
                  - Optional parameter to refine report content based on specific
                    criteria.
                  - Filter availability depends on the selected view_name.
                type: list
                elements: dict
                required: false
                suboptions:
                  name:
                    description:
                      - Name of the filter as defined in the view metadata.
                      - Common filters include Location, Time Range, Device Type, etc.
                    type: str
                    required: true
                  filter_type:
                    description:
                      - Type of the filter determining how values are selected.
                      - C(MULTI_SELECT) allows multiple discrete values.
                      - C(MULTI_SELECT_TREE) allows hierarchical multi-selection.
                      - C(SINGLE_SELECT_ARRAY) allows single value from array.
                      - C(TIME_RANGE) allows date/time range specification.
                    choices:
                      - MULTI_SELECT
                      - MULTI_SELECT_TREE
                      - SINGLE_SELECT_ARRAY
                      - TIME_RANGE
                    type: str
                    required: true
                  value:
                    description:
                      - Value(s) to apply in the filter based on filter_type.
                      - For C(TIME_RANGE), this is a dict with time_range_option,
                        start_date_time, end_date_time, and time_zone.
                      - For other types, this is a list of dicts with C(value) and
                        C(display_value) keys.
                      - Location filters are automatically resolved to site hierarchy IDs.
                    type: list
                    elements: dict
                    required: true
requirements:
  - dnacentersdk >= 2.8.6
  - python >= 3.9
notes:
  - SDK Methods used are
    reports.Reports.get_all_view_groups
    reports.Reports.get_views_for_a_given_view_group
    reports.Reports.get_view_details_for_a_given_view_group_and_view
    reports.Reports.create_or_schedule_a_report
    reports.Reports.delete_a_scheduled_report
    reports.Reports.download_report_content
    reports.Reports.get_execution_id_by_report_id
  - Paths used are
    GET /dna/intent/api/v1/data/view-groups
    GET /dna/intent/api/v1/data/view-groups/{viewGroupId}
    GET /dna/intent/api/v1/data/view-groups/{viewGroupId}/views/{viewId}
    POST /dna/intent/api/v1/data/reports
    DELETE /dna/intent/api/v1/data/reports/{reportId}
    GET /dna/intent/api/v1/data/reports/{reportId}/executions/{executionId}
"""
"""
Mapping of View Names to Mandatory Filters and Available Filters:

View Name                                         Mandatory Filters                     Available Filters
---------                                         -----------------                     -----------------
Network Device Compliance                         Location                              Location, Device Type, Collection Status
Network Device Availability                       Location                              Location, Device Type, Time Range
Channel Change Count                              Location                              Location, Device Type, Time Range
Transmit Power Change Count                       Location                              Location, Device Type, Time Range
VLAN                                              Location                              Location, Device Type
Port Capacity                                     Location                              Location, Device Type
Energy Management                                 Location                              Location, Device Type
PoE                                               Location                              Location, Device Type
Device CPU and Memory Utilization                 Location                              Location, Device Type, Time Range
Network Interface Utilization                     Location                              Location, Device Type, Interface Type, Time Range
Executive Summary                                 Location                              Location, Device Type, Time Range
All Data (inventory)                                         N/A                              Location, Device Type, Software Version
Port Reclaim View                                 Location                              Location, Device Type
All Data Version 2.0                              Location                              Location, Device Type, Software Version
All Data (swim)                                         N/A                                   Device Type, Image Name, Software Version
All Data Version 2.0                              N/A                                   Device Type, Image Name, Software Version
AP                                                Location                              Location, AP Name, Model, Controller
AP Radio                                          Location                              Location, AP Name, Radio Band, Controller
AP - Usage and Client Breakdown                   Location, AP Name                       Location, AP Name, Controller, Time Range
Worst Interferers                                 Location                              Location, AP Name, Controller, Time Range
AP RRM Events                                     Location                              Location, AP Name, Controller, Time Range
AP Performance Report                             Location                              Location, AP Name, Controller, Time Range
Long Term AP Detail                               Location                              Location, AP Name, Controller, Time Range
Long Term AP Radio                                Location                              Location, AP Name, Radio Band, Time Range
Long Term AP Usage and Client Breakdown           Location, AP Name                       Location, AP Name, Time Range
Long Term Client Detail                           Location, Time Range                    Location, Client MAC, User Name, Time Range
Long Term Client Session                          Location, Time Range                    Location, Client MAC, Session ID, Time Range
Long Term Network Device Availability             Location                              Location, Device Type, Time Range
Security Group to Security Group                 Source/Destination SGT               SGT, VN, Time Range
Security Group to ISE Endpoint Profile Group     SGT, Endpoint Profile                SGT, Endpoint Profile, VN, Time Range
Security Group to Host Group                     SGT, Host Group                      SGT, Host Group, VN, Time Range
ISE Endpoint Profile Group to Security Group     Endpoint Profile, SGT                Endpoint Profile, SGT, VN, Time Range
ISE Endpoint Profile Group to
    ISE Endpoint Profile Group                    Endpoint Profile                      Endpoint Profile, VN, Time Range
ISE Endpoint Profile Group to Host Group         Endpoint Profile, Host Group         Endpoint Profile, Host Group, VN, Time Range
Host Group to Security Group                     Host Group, SGT                      Host Group, SGT, VN, Time Range
Host Group to ISE Endpoint Profile Group         Host Group, Endpoint Profile         Host Group, Endpoint Profile, VN, Time Range
Host Group to Host Group                          Host Group                           Host Group, VN, Time Range
Device Lifecycle Information                      Location                             Location, Device Type, Hardware Info
Security Group to Security Groups                SGT                                  SGT, VN, Time Range
Security Group to ISE Endpoint Profile Groups    SGT, Endpoint Profile               SGT, Endpoint Profile, VN, Time Range
Security Group to Host Groups                    SGT, Host Group                     SGT, Host Group, VN, Time Range
ISE Endpoint Profile Group to Security Groups    Endpoint Profile, SGT               Endpoint Profile, SGT, VN, Time Range
ISE Endpoint Profile Group to
    ISE Endpoint Profile Groups                   Endpoint Profile                    Endpoint Profile, VN, Time Range
ISE Endpoint Profile Group to Host Groups        Endpoint Profile, Host Group         Endpoint Profile, Host Group, VN, Time Range
Host Group to Security Groups                    Host Group, SGT                      Host Group, SGT, VN, Time Range
Host Group to ISE Endpoint Profile Group         Host Group, Endpoint Profile         Host Group, Endpoint Profile, VN, Time Range
Host Group to Host Group                          Host Group                           Host Group, VN, Time Range
EoX Data                                          N/A                                  Device Type, EoX Type, Bulletin ID
Threat Detail                                     Location                             Location, Threat Type, Severity, Time Range
New Threat                                        Location                             Location, Threat Type, Severity, Time Range
Rogue Additional Detail                           Location                             Location, Threat Type, MAC Address, Time Range
Non Compliant Devices                             Location                             Location, Device Type, License Type
Non Compliance Summary                            Location                             Location, License Type, Compliance Status
AireOS Controllers Licenses                       N/A                                  Controller Name, License Type, Status
License Usage Upload Details                      N/A                                  Upload Date, License Type, Status
License Historical Usage                          N/A                                  License Type, Time Range, Usage Type
Endpoint Profiling                                Location                             Location, Device Type, Profile Name, Time Range
Audit Log                                         N/A                                  Time Range
Configuration Archive                             Device, Time Range                   Device Name, Location, Archive Status, Time Range
Client                                            Location                              Location, Client MAC, Device Type
Client Summary                                    Location                              Location, Device Type, Connection Status
Top N Summary                                     Location                              Location, Metric Type, Time Range
Client Detail                                     Location                              Location, Client MAC, User Name
Client Trend                                      Location, Time Range                  Location, Client MAC, Metric Type, Time Range
Client Session                                    Location, Time Range                  Location, Client MAC, Session ID, Time Range
Busiest Client                                    N/A                                  Location, Client MAC, Traffic Type
Unique Clients and Users Summary                  Location, Client MAC                  Location, Client MAC, Time Range, Device Type
Security Advisories Data                         N/A                                  Device Type, Software Version, Image Name, Time Range
"""

"""Filter types for each filter category in Cisco Catalyst Center Reports:

Filter Name: Location
    Filter Type: MULTI_SELECT_TREE
    Description: Hierarchical selection of network locations/sites

Filter Name: Device Type
    Filter Type: MULTI_SELECT
    Description: Selection of device categories (Switch, Router, AP, etc.)

Filter Name: Time Range
    Filter Type: TIME_RANGE
    Description: Date/time range specification for historical data

Filter Name: Collection Status
    Filter Type: MULTI_SELECT
    Description: Device collection status (Collected, Not Collected, etc.)

Filter Name: Software Version
    Filter Type: MULTI_SELECT
    Description: Device software/firmware versions

Filter Name: Interface Type
    Filter Type: MULTI_SELECT
    Description: Network interface categories (Ethernet, Wireless, etc.)

Filter Name: Image Name
    Filter Type: MULTI_SELECT
    Description: Software image names for SWIM reports

Filter Name: AP Name
    Filter Type: MULTI_SELECT
    Description: Access Point device names

Filter Name: Model
    Filter Type: MULTI_SELECT
    Description: Device hardware model numbers

Filter Name: Controller
    Filter Type: MULTI_SELECT
    Description: Wireless controller names

Filter Name: Radio Band
    Filter Type: MULTI_SELECT
    Description: Wireless radio frequency bands (2.4GHz, 5GHz, 6GHz)

Filter Name: SSID
    Filter Type: MULTI_SELECT
    Description: Wireless network SSID names

Filter Name: SGT (Security Group Tag)
    Filter Type: MULTI_SELECT
    Description: Cisco TrustSec security group tags

Filter Name: Endpoint Profile
    Filter Type: MULTI_SELECT
    Description: ISE endpoint profile groups

Filter Name: Host Group
    Filter Type: MULTI_SELECT
    Description: Host group classifications

Filter Name: VN (Virtual Network)
    Filter Type: MULTI_SELECT
    Description: Virtual network identifiers

Filter Name: Hardware Info
    Filter Type: MULTI_SELECT
    Description: Device hardware information categories

Filter Name: EoX Type
    Filter Type: MULTI_SELECT
    Description: End of Life/Support announcement types

Filter Name: Bulletin ID
    Filter Type: SINGLE_SELECT_ARRAY
    Description: Security bulletin identifiers

Filter Name: Threat Type
    Filter Type: MULTI_SELECT
    Description: Security threat categories

Filter Name: Severity
    Filter Type: MULTI_SELECT
    Description: Threat/alert severity levels

Filter Name: MAC Address
    Filter Type: MULTI_SELECT
    Description: Device MAC addresses

Filter Name: License Type
    Filter Type: MULTI_SELECT
    Description: Software license categories

Filter Name: Compliance Status
    Filter Type: MULTI_SELECT
    Description: License compliance states

Filter Name: Status
    Filter Type: MULTI_SELECT
    Description: General status indicators

Filter Name: Upload Date
    Filter Type: TIME_RANGE
    Description: File upload date ranges

Filter Name: Usage Type
    Filter Type: MULTI_SELECT
    Description: License usage categories

Filter Name: Profile Name
    Filter Type: MULTI_SELECT
    Description: AI Endpoint Analytics profile names

Filter Name: User Name
    Filter Type: MULTI_SELECT
    Description: User account names

Filter Name: Event Category
    Filter Type: MULTI_SELECT
    Description: Audit log event categories

Filter Name: Object Type
    Filter Type: MULTI_SELECT
    Description: Audit log object types

Filter Name: Device Name
    Filter Type: MULTI_SELECT
    Description: Network device names

Filter Name: Archive Status
    Filter Type: MULTI_SELECT
    Description: Configuration archive status

Filter Name: Client MAC
    Filter Type: MULTI_SELECT
    Description: Client device MAC addresses

Filter Name: Connection Status
    Filter Type: MULTI_SELECT
    Description: Client connection states

Filter Name: Metric Type
    Filter Type: MULTI_SELECT
    Description: Performance metric categories

Filter Name: Session ID
    Filter Type: MULTI_SELECT
    Description: Client session identifiers

Filter Name: Traffic Type
    Filter Type: MULTI_SELECT
    Description: Network traffic categories

Note:
- MULTI_SELECT: Allows selection of multiple discrete values
- MULTI_SELECT_TREE: Allows hierarchical multi-selection (like site locations)
- SINGLE_SELECT_ARRAY: Allows single value selection from an array
- TIME_RANGE: Allows date/time range specification with start_date_time, end_date_time, and time_zone
"""

REPORT_TYPES_AND_FORMATS = r'''
Report Types with View Names and Eligible Format Types:

COMPLIANCE REPORTS:
- View Name: "Network Device Compliance"
- View Group: "Compliance"
- Available Formats: CSV, PDF, JSON

EXECUTIVE SUMMARY REPORTS:
- View Name: "Executive Summary"
- View Group: "Executive Summary"
- Available Formats: PDF

INVENTORY REPORTS:
- View Name: "All Data"
- View Group: "Inventory"
- Available Formats: PDF, CSV, TDE

- View Name: "Port Reclaim View"
- View Group: "Inventory"
- Available Formats: CSV, JSON, TDE

- View Name: "All Data Version 2.0"
- View Group: "Inventory"
- Available Formats: CSV, PDF, TDE

SWIM REPORTS:
- View Name: "All Data"
- View Group: "SWIM"
- Available Formats: CSV, PDF, TDE

- View Name: "All Data Version 2.0"
- View Group: "SWIM"
- Available Formats: CSV, JSON, TDE

ACCESS POINT REPORTS:
- View Name: "AP"
- View Group: "Access Point"
- Available Formats: CSV, JSON, TDE

- View Name: "AP Radio"
- View Group: "Access Point"
- Available Formats: CSV, JSON, TDE

- View Name: "AP - Usage and Client Breakdown"
- View Group: "Access Point"
- Available Formats: CSV, PDF, JSON, TDE

- View Name: "Worst Interferers"
- View Group: "Access Point"
- Available Formats: CSV, JSON, TDE

- View Name: "AP RRM Events"
- View Group: "Access Point"
- Available Formats: CSV, JSON, TDE

NETWORK DEVICE REPORTS:
- View Name: "Network Device Availability"
- View Group: "Network Devices"
- Available Formats: CSV, JSON, TDE

- View Name: "Channel Change Count"
- View Group: "Network Devices"
- Available Formats: CSV, JSON, TDE

- View Name: "Transmit Power Change Count"
- View Group: "Network Devices"
- Available Formats: CSV, JSON, TDE

- View Name: "VLAN"
- View Group: "Network Devices"
- Available Formats: CSV, TDE

- View Name: "Port Capacity"
- View Group: "Network Devices"
- Available Formats: CSV, TDE

- View Name: "Energy Management"
- View Group: "Network Devices"
- Available Formats: CSV, JSON, TDE

- View Name: "PoE"
- View Group: "Network Devices"
- Available Formats: CSV, JSON, TDE

- View Name: "Device CPU and Memory Utilization"
- View Group: "Network Devices"
- Available Formats: CSV, JSON, TDE

- View Name: "Network Interface Utilization"
- View Group: "Network Devices"
- Available Formats: CSV, JSON, TDE

LONG TERM REPORTS:
- View Name: "AP Performance Report"
- View Group: "Long Term"
- Available Formats: CSV, JSON, TDE

- View Name: "Long Term AP Detail"
- View Group: "Long Term"
- Available Formats: CSV, JSON, TDE

- View Name: "Long Term AP Radio"
- View Group: "Long Term"
- Available Formats: CSV, JSON, TDE

- View Name: "Long Term AP Usage and Client Breakdown"
- View Group: "Long Term"
- Available Formats: CSV, PDF, JSON, TDE

- View Name: "Long Term Client Detail"
- View Group: "Long Term"
- Available Formats: CSV, JSON, TDE

- View Name: "Long Term Client Session"
- View Group: "Long Term"
- Available Formats: CSV, JSON, TDE

- View Name: "Long Term Network Device Availability"
- View Group: "Long Term"
- Available Formats: CSV, JSON, TDE

GROUP PAIR COMMUNICATION ANALYTICS REPORTS:
- View Name: "Security Group to Security Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "Security Group to ISE Endpoint Profile Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "Security Group to Host Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "ISE Endpoint Profile Group to Security Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "ISE Endpoint Profile Group to ISE Endpoint Profile Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "ISE Endpoint Profile Group to Host Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "Host Group to Security Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "Host Group to ISE Endpoint Profile Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

- View Name: "Host Group to Host Group"
- View Group: "Group Pair Communication Analytics"
- Available Formats: CSV

TELEMETRY REPORTS:
- View Name: "Device Lifecycle Information"
- View Group: "Telemetry"
- Available Formats: JSON

GROUP COMMUNICATION SUMMARY REPORTS:
- View Name: "Security Group to Security Groups"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "Security Group to ISE Endpoint Profile Groups"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "Security Group to Host Groups"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "ISE Endpoint Profile Group to Security Groups"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "ISE Endpoint Profile Group to ISE Endpoint Profile Groups"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "ISE Endpoint Profile Group to Host Groups"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "Host Group to Security Groups"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "Host Group to ISE Endpoint Profile Group"
- View Group: "Group Communication Summary"
- Available Formats: CSV

- View Name: "Host Group to Host Group"
- View Group: "Group Communication Summary"
- Available Formats: CSV

EOX REPORTS:
- View Name: "EoX Data"
- View Group: "EoX"
- Available Formats: CSV, PDF, TDE

ROGUE AND aWIPS REPORTS:
- View Name: "Threat Detail"
- View Group: "Rogue and aWIPS"
- Available Formats: CSV, JSON, TDE

- View Name: "New Threat"
- View Group: "Rogue and aWIPS"
- Available Formats: CSV, JSON, TDE

- View Name: "Rogue Additional Detail"
- View Group: "Rogue and aWIPS"
- Available Formats: CSV, JSON, TDE

LICENSING REPORTS:
- View Name: "Non Compliant Devices"
- View Group: "Licensing"
- Available Formats: CSV, PDF

- View Name: "Non Compliance Summary"
- View Group: "Licensing"
- Available Formats: CSV, PDF

- View Name: "AireOS Controllers Licenses"
- View Group: "Licensing"
- Available Formats: CSV, PDF

- View Name: "License Usage Upload Details"
- View Group: "Licensing"
- Available Formats: CSV, PDF

- View Name: "License Historical Usage"
- View Group: "Licensing"
- Available Formats: CSV

AI ENDPOINT ANALYTICS REPORTS:
- View Name: "Endpoint Profiling"
- View Group: "AI Endpoint Analytics"
- Available Formats: CSV

AUDIT LOG REPORTS:
- View Name: "Audit Log"
- View Group: "Audit Log"
- Available Formats: CSV, JSON

CONFIGURATION ARCHIVE REPORTS:
- View Name: "Configuration Archive"
- View Group: "Configuration Archive"
- Available Formats: CSV, PDF, JSON

CLIENT REPORTS:
- View Name: "Client"
- View Group: "Client"
- Available Formats: CSV, PDF, JSON, TDE

- View Name: "Client Summary"
- View Group: "Client"
- Available Formats: PDF

- View Name: "Top N Summary"
- View Group: "Client"
- Available Formats: PDF

- View Name: "Client Detail"
- View Group: "Client"
- Available Formats: CSV, JSON, TDE

- View Name: "Client Trend"
- View Group: "Client"
- Available Formats: PDF

- View Name: "Client Session"
- View Group: "Client"
- Available Formats: CSV, JSON, TDE

- View Name: "Busiest Client"
- View Group: "Client"
- Available Formats: CSV, JSON, TDE

- View Name: "Unique Clients and Users Summary"
- View Group: "Client"
- Available Formats: PDF

SECURITY ADVISORIES REPORTS:
- View Name: "Security Advisories Data"
- View Group: "Security Advisories"
- Available Formats: CSV, PDF, TDE

FORMAT TYPE DESCRIPTIONS:
- CSV: Comma-Separated Values format, suitable for spreadsheets and data analysis
- PDF: Portable Document Format, ideal for sharing and printing reports
- JSON: JavaScript Object Notation, useful for structured data exchange and integration
- TDE: Tableau Data Extract, optimized for use with Tableau software for data visualization

Note: The available format types are retrieved through the following API endpoints:
- GET /dna/intent/api/v1/data/view-groups (to get all view groups)
- GET /dna/intent/api/v1/data/view-groups/{viewGroupId} (to get views for a view group)
- GET /dna/intent/api/v1/data/view-groups/{viewGroupId}/views/{viewId} (to get view details including format options)
'''

EXAMPLES = r'''
- name: Create/Schedule a compliance report with immediate execution
  cisco.dnac.reports_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: DEBUG
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - generate_report:
          - name: "compliance_report"
            view_group_name: "Compliance"
            deliveries:
              - delivery_type: "DOWNLOAD"
                file_path: "/Users/xyz/Desktop"
            schedule:
              schedule_type: "SCHEDULE_NOW"
              time_zone: "Asia/Calcutta"
            view:
              view_name: "Network Device Compliance"
              field_groups:
                - name: "inventoryAllData"
              format:
                format_type: "CSV"
              filters: []
            tags: ["network", "compliance"]

- name: Create/Schedule an access point report with location filter
  cisco.dnac.reports_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: DEBUG
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - generate_report:
          - name: "Access_point_report1"
            view_group_name: "Access Point"
            deliveries:
              - delivery_type: "DOWNLOAD"
                file_path: "/Users/xyz/Desktop"
            schedule:
              schedule_type: "SCHEDULE_NOW"
              time_zone: "Asia/Calcutta"
            view:
              view_name: "AP"
              field_groups: []
              format:
                format_type: "JSON"
              filters:
                - name: "Location"
                  filter_type: "MULTI_SELECT_TREE"
                  value:
                    - value: "Global/India"

- name: Schedule a report for later execution
  cisco.dnac.reports_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - generate_report:
          - name: "scheduled_inventory_report"
            view_group_name: "Inventory"
            tags: ["inventory", "scheduled"]
            deliveries:
              - delivery_type: "NOTIFICATION"
                notification_endpoints:
                  - email_addresses:
                      - "admin@company.com"
                      - "reports@company.com"
                    email_attach: true
                    notify: ["COMPLETED"]
            schedule:
              schedule_type: "SCHEDULE_LATER"
              date_time: "2025-12-25 09:00 AM"
              time_zone: "America/New_York"
            view:
              view_name: "All Data"
              field_groups: []
              format:
                format_type: "PDF"
              filters: []

- name: Create recurring weekly report with webhook delivery
  cisco.dnac.reports_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - generate_report:
          - name: "weekly_device_report"
            view_group_name: "Network Devices"
            tags: ["weekly", "devices"]
            deliveries:
              - delivery_type: "WEBHOOK"
                webhook_name: "report_webhook"
            schedule:
              schedule_type: "SCHEDULE_RECURRENCE"
              date_time: "2025-09-15 08:00 AM"
              time_zone: "UTC"
              recurrence:
                recurrence_type: "WEEKLY"
                days: ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY",
                       "FRIDAY", "SATURDAY", "SUNDAY"]
            view:
              view_name: "Network Device Availability"
              field_groups:
                - name: "deviceInfo"
                  fields:
                    - name: "hostname"
                    - name: "ipAddress"
              format:
                format_type: "CSV"
              filters:
                - name: "Location"
                  filter_type: "MULTI_SELECT_TREE"
                  value:
                    - value: "Global/US/California"

- name: Create monthly report with time range filter
  cisco.dnac.reports_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - generate_report:
          - name: "monthly_client_report"
            view_group_name: "Client"
            tags: ["monthly", "clients"]
            deliveries:
              - delivery_type: "DOWNLOAD"
                file_path: "/home/reports/monthly"
            schedule:
              schedule_type: "SCHEDULE_RECURRENCE"
              date_time: "2025-09-01 06:00 AM"
              time_zone: "Asia/Calcutta"
              recurrence:
                recurrence_type: "MONTHLY"
                last_day_of_month: true
            view:
              view_name: "Client Detail"
              field_groups: []
              format:
                format_type: "JSON"
              filters:
                - name: "Time Range"
                  filter_type: "TIME_RANGE"
                  value:
                    value: "LAST_30_DAYS"

- name: Delete a report from Catalyst Center
  cisco.dnac.reports_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    state: deleted
    config_verify: true
    config:
      - generate_report:
          - name: "compliance_report"  # The name of the report to be deleted is required
            view_group_name: "Compliance"  # Required for identification
            view:
              view_name: "Network Device Compliance"  # Required for identification
'''

RETURN = r"""
# Case 1: Successful Report Creation/Scheduling
response_create_or_schedule_a_report:
  description: Response returned after successfully creating or scheduling a
    report in Cisco Catalyst Center.
  returned: when state is merged and report creation succeeds
  type: dict
  sample: {
    "response": [
      {
        "create_report": {
          "response": {
            "reportId": "1234567890abcdef12345678",
            "viewGroupId": "network-device-compliance",
            "viewsId": "compliance-view-id"
          },
          "msg": "Successfully created or scheduled report 'compliance_report'."
        }
      }
    ],
  }

# Case 2: Successful Report Deletion
response_delete_a_scheduled_report:
  description: Response returned after successfully deleting a scheduled report
    from Cisco Catalyst Center.
  returned: when state is deleted and report deletion succeeds
  type: dict
  sample: {
    "response": [
      {
        "delete_report": {
          "response": {},
          "msg": "Report 'compliance_report' has been successfully deleted."
        }
      }
    ],
  }

# Case 3: Successful Report Download
response_download_report_content:
  description: Response returned after successfully downloading report content
    to the specified local file path.
  returned: when delivery_type is DOWNLOAD and download succeeds
  type: dict
  sample: {
    "response": [
      {
        "download_report": {
          "response": {
            "reportId": "1234567890abcdef12345678",
            "reportName": "compliance_report",
            "filePath": "/Users/xyz/Desktop"
          },
          "msg": "Successfully downloaded report 'compliance_report' to
            '/Users/xyz/Desktop'."
        }
      }
    ],
  }

# Case 4: Report Already Exists
response_existing_report:
  description: Response returned when a report with the same name already
    exists in Cisco Catalyst Center.
  returned: when state is merged and report already exists
  type: dict
  sample: {
    "response": [
      {
        "create_report": {
          "response": {
            "report_id": "existing1234567890abcdef",
            "view_group_id": "network-device-compliance",
            "view_id": "compliance-view-id"
          },
          "msg": "Report 'compliance_report' already exists."
        }
      }
    ],
    "changed": false,
    "msg": "No changes required - report already exists."
  }

# Case 5: Report Not Found for Deletion
response_report_not_found:
  description: Response returned when attempting to delete a report that does
    not exist in Cisco Catalyst Center.
  returned: when state is deleted and report does not exist
  type: dict
  sample: {
    "response": [
      {
        "delete_report": {
          "response": {},
          "msg": "Report 'nonexistent_report' does not exist."
        }
      }
    ],
    "changed": false,
    "msg": "No changes required - report does not exist."
  }

# Case 6: Verification Success
response_verification_success:
  description: Response returned after successful verification of report
    operations when config_verify is enabled.
  returned: when config_verify is true and verification succeeds
  type: dict
  sample: {
    "response": [
      {
        "create_report": {
          "response": {
            "reportId": "1234567890abcdef12345678",
            "viewGroupId": "network-device-compliance",
            "viewsId": "compliance-view-id"
          },
          "msg": "Successfully created or scheduled report 'compliance_report'.",
          "Validation": "Success"
        }
      }
    ],
    "changed": true,
    "msg": "Report operations completed and verified successfully."
  }

# Case 7: Multiple Reports Processing
response_multiple_reports:
  description: Response returned when processing multiple reports in a single
    playbook execution.
  returned: when config contains multiple report configurations
  type: dict
  sample: {
    "response": [
      {
        "create_report": {
          "response": {
            "reportId": "report1-id",
            "viewGroupId": "compliance",
            "viewsId": "compliance-view"
          },
          "msg": "Successfully created or scheduled report 'compliance_report'."
        }
      },
      {
        "download_report": {
          "response": {
            "reportId": "report1-id",
            "reportName": "compliance_report",
            "filePath": "/Users/xyz/Desktop"
          },
          "msg": "Successfully downloaded report 'compliance_report' to
            '/Users/xyz/Desktop'."
        }
      },
      {
        "create_report": {
          "response": {
            "reportId": "report2-id",
            "viewGroupId": "inventory",
            "viewsId": "inventory-view"
          },
          "msg": "Successfully created or scheduled report 'inventory_report'."
        }
      }
    ],
    "changed": true,
    "msg": "Multiple report operations completed successfully."
  }

# Case 8: Error Response
response_error:
  description: Response returned when an error occurs during report operations.
  returned: when an error occurs during execution
  type: dict
  sample: {
    "response": [],
    "changed": false,
    "failed": true,
    "msg": "Failed to create report: Invalid view_group_name 'InvalidGroup'."
  }
"""

from datetime import datetime
import time
import os
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase
)
from ansible_collections.cisco.dnac.plugins.module_utils.validation import (
    validate_list_of_dicts
)
import json
import re

# common approach when a module relies on optional dependencies that are not available during the validation process.
try:
    import pytz

    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False
    pyzipper = None


class Reports(DnacBase):
    """Class containing member attributes for Report Workflow Manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.state = self.params.get("state")
        self.result["response"] = []

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """
        self.log("Starting playbook configuration validation for reports workflow", "INFO")

        config_spec = {
            "generate_report": {
                "type": "list",
                "elements": "dict",
                "required": True,
                # fields for each generate_report item
                "name": {"type": "str", "required": False},
                "view_group_name": {
                    "type": "str",
                    "required": False,
                    "choices": [
                        "Compliance", "Executive Summary", "Inventory", "SWIM",
                        "Access Point", "Long Term", "Network Devices",
                        "Group Pair Communication Analytics", "Telemetry",
                        "Group Communication Summary", "EoX", "Rogue and aWIPS",
                        "Licensing", "AI Endpoint Analytics", "Audit Log",
                        "Configuration Archive", "Client", "Security Advisories"
                    ]
                },
                "tags": {"type": "list", "elements": "str", "default": []},
                "view_group_version": {"type": "str", "required": False, "default": "2.0.0"},

                "schedule": {
                    "type": "dict",
                    "required": False,
                    "schedule_type": {
                        "type": "str",
                        "element": "str",
                        "required": True,
                        "choices": ["SCHEDULE_NOW", "SCHEDULE_LATER", "SCHEDULE_RECURRENCE"],
                    },
                    "date_time": {"type": "str", "required": False},
                    "time_zone": {"type": "str", "required": True},
                    "recurrence": {
                        "type": "dict",
                        "recurrence_type": {
                            "type": "str",
                            "required": False,
                            # choose appropriate recurrence values for your system
                            "choices": ["WEEKLY", "MONTHLY"],
                        },
                        "days": {"type": "list", "elements": "str", "required": False},
                        "last_day_of_month": {"type": "bool", "required": False},
                        "day_of_month": {"type": "int", "required": False},
                    },
                    "time": {"type": "int", "required": False},
                    "start_date": {"type": "int", "required": False},
                },

                "deliveries": {
                    "type": "list",
                    "elements": "dict",
                    "required": False,
                    "delivery_type": {
                        "type": "str",
                        "required": True,
                        "choices": ["DOWNLOAD", "NOTIFICATION", "WEBHOOK"],
                    },
                    "file_path": {"type": "str", "required": False},
                    "notification_endpoints": {
                        "type": "list",
                        "elements": "dict",
                        "required": False,
                        "email_addresses": {"type": "list", "elements": "str", "required": False},
                        "email_attach": {"type": "bool", "required": False, "default": False},
                        "notify": {
                            "type": "list",
                            "elements": "str",
                            "required": False,
                            "choices": [["IN_QUEUE"],
                                        ["IN_PROGRESS"],
                                        ["COMPLETED"],
                                        ["IN_QUEUE", "IN_PROGRESS"],
                                        ["IN_PROGRESS", "IN_QUEUE"],
                                        ["IN_QUEUE", "COMPLETED"],
                                        ["COMPLETED", "IN_QUEUE"],
                                        ["IN_PROGRESS", "COMPLETED"],
                                        ["COMPLETED", "IN_PROGRESS"],
                                        ["IN_QUEUE", "IN_PROGRESS", "COMPLETED"],
                                        ["IN_QUEUE", "COMPLETED", "IN_PROGRESS"],
                                        ["IN_PROGRESS", "IN_QUEUE", "COMPLETED"],
                                        ["IN_PROGRESS", "COMPLETED", "IN_QUEUE"],
                                        ["COMPLETED", "IN_QUEUE", "IN_PROGRESS"],
                                        ["COMPLETED", "IN_PROGRESS", "IN_QUEUE"]],
                        },
                    },
                    "webhook_name": {"type": "str", "required": False},
                },

                "view": {
                    "type": "dict",
                    "required": False,
                    "view_name": {"type": "str", "required": True},
                    "field_groups": {
                        "type": "list",
                        "elements": "dict",
                        "required": False,
                        "name": {"type": "str", "required": True},
                        "fields": {
                            "type": "list",
                            "elements": "dict",
                            "required": False,
                            "name": {"type": "str", "required": False},
                        },
                    },
                    "format": {
                        "type": "dict",
                        "required": False,
                        "format_type": {
                            "type": "str",
                            "required": True,
                            "choices": ["CSV", "PDF", "JSON", "TDE"]
                        },
                    },
                    "filters": {
                        "type": "list",
                        "elements": "dict",
                        "name": {"type": "str", "required": False},
                        "filter_type": {
                            "type": "str",
                            "required": False,
                            "choices": ["MULTI_SELECT", "MULTI_SELECT_TREE", "SINGLE_SELECT_ARRAY", "TIME_RANGE"],
                        },
                        "value": {
                            "type": "list",
                            "value": {"type": "str", "required": False},
                            "required": False
                        },
                    },
                },
            }
        }

        if not self.config:
            self.msg = "Configuration is not available in the playbook for validation"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.log("Validating configuration structure against specification", "DEBUG")

        valid_config, invalid_params = validate_list_of_dicts(
            self.config, config_spec
        )

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        if not valid_config:
            self.log("Configuration validation failed. No valid config found: {0}".format(valid_config))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        self.log("Configuration validated successfully: {0}".format(self.pprint(valid_config)), "INFO")
        self.validated_config = valid_config
        return self

    def input_data_validation(self, config):
        """
        Validate and transform input data provided in the playbook configuration.

        This method performs comprehensive validation and transformation of report configuration
        data, including schedule validation, delivery validation, filter processing, and
        location resolution for multi-select tree filters.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing report generation details
                            including generate_report list with schedule, deliveries, view, and filter data

        Returns:
            self: The current instance of the class with updated attribute.

        Description:
            - Removes null values from configuration recursively
            - Validates required fields for report generation
            - Transforms schedule configuration based on schedule type
            - Validates and transforms delivery configurations
            - Processes location filters to resolve site hierarchy IDs
            - Converts date/time strings to epoch format for API compatibility
            - Logs all major validation steps and decision points for traceability
        """

        self.log(
            "Starting input data validation for report configuration with {0} entries".format(
                len(config.get("generate_report", []))
            ),
            "INFO"
        )
        # Clean entry in place (remove null fields at all levels)
        self.log("Removing null values from configuration data", "DEBUG")
        cleaned_entry = self.remove_nulls(config)
        config.clear()
        config.update(cleaned_entry)
        self.log("Cleaned input data: {0}".format(self.pprint(config)), "DEBUG")
        generate_report = config.get("generate_report", [])
        if not generate_report:
            self.msg = "The 'generate_report' field is missing or empty in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log("Configuration validation failed - no generate_report entries found", "ERROR")
            return self

        self.log("Validating {0} report entries for required fields and structure".format(
            len(generate_report)), "DEBUG")

        for entry_index, entry in enumerate(generate_report):
            self.log("Processing report entry {0}: {1}".format(
                entry_index + 1, entry.get("name", "unnamed")), "DEBUG")

            if not isinstance(entry, dict):
                self.msg = "Each entry in 'generate_report' must be a dictionary."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            # Validate required fields
            required_fields = ["view_group_name", "view", "schedule", "deliveries"]
            for field in required_fields:
                if field not in entry:
                    self.msg = "Missing required field '{0}' in 'generate_report' entry.".format(field)
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

            # Generate name if missing
            if not entry.get("name"):
                timestamp = datetime.now().strftime("%b %d %Y %I:%M %p")
                entry["name"] = "{0} - {1} - {2}".format(
                    entry.get("data_category", "Report"),
                    entry.get("view", {}).get("view_name", "View"),
                    timestamp
                )
                self.log("Generated report name: {0}".format(entry["name"]), "DEBUG")

            # Validate deliveries
            deliveries = entry.get("deliveries", {})
            if deliveries:
                self.log("Validating delivery configuration for report: {0}".format(
                    entry.get("name")), "DEBUG")
                if not self.validate_deliveries(deliveries):
                    return self

            # Set default values
            entry.setdefault("tags", [])
            entry.setdefault("view_group_version", "2.0.0")
            entry.get("view").setdefault("filters", [])
            entry.get("view").setdefault("field_groups", [])
            entry.get("view").setdefault("format", {"format_type": "CSV"})

            # Validate and transform schedule configuration
            if not self._validate_schedule_configuration(entry):
                return self

            # Validate and transform view configuration
            if not self._validate_view_configuration(entry):
                return self

        self.log("Completed input data validation for all report entries successfully", "INFO")
        return self

    def _validate_schedule_configuration(self, entry):
        """
        Validate and transform schedule configuration for a report entry.

        Parameters:
            entry (dict): The report entry containing schedule configuration.

        Returns:
            bool: True if validation succeeds, False if validation fails.
        """
        self.log("Validating schedule configuration for report: {0}".format(
            entry.get("name")), "DEBUG")

        schedule = entry.get("schedule", {})
        # Validate timezone
        time_zone = schedule.get("time_zone")
        if not time_zone:
            self.msg = "Missing required schedule field: 'time_zone'"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        if time_zone not in pytz.all_timezones:
            self.msg = f"Invalid time_zone '{time_zone}'.\
                        Please provide a valid timezone as per the IANA timezone database (e.g., 'Asia/Calcutta')."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        # Transform schedule_type to type
        if "schedule" in entry and "schedule_type" in entry["schedule"]:
            entry["schedule"]["type"] = entry["schedule"].pop("schedule_type")

        schedule_type = entry.get("schedule", {}).get("type")
        valid_schedule_types = ["SCHEDULE_NOW", "SCHEDULE_LATER", "SCHEDULE_RECURRENCE"]

        if not schedule_type:
            self.msg = "Missing required field 'schedule.type' in 'generate_report' entry."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        if schedule_type not in valid_schedule_types:
            self.msg = "Invalid schedule type '{0}'. Must be one of {1}.".format(
                schedule_type, valid_schedule_types)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        # Handle SCHEDULE_LATER validation
        if schedule_type == "SCHEDULE_LATER":
            return self._validate_schedule_later(entry)

        # Handle SCHEDULE_RECURRENCE validation
        if schedule_type == "SCHEDULE_RECURRENCE":
            return self._validate_schedule_recurrence(entry)

        self.log("Schedule configuration validated successfully for type: {0}".format(
            schedule_type), "DEBUG")
        return True

    def _validate_schedule_later(self, entry):
        """
        Validate and process the 'SCHEDULE_LATER' schedule entry.

        This function checks if the provided schedule entry contains a valid
        `date_time` field under `schedule`. If missing, it logs and sets the
        operation result as failed. If present, it attempts to convert the
        `date_time` string into epoch milliseconds.

        Expected `date_time` format: "YYYY-MM-DD HH:MM AM/PM"

        Parameters:
            entry (dict): The schedule entry containing 'schedule.date_time'.

        Returns:
            bool:
                - True if 'date_time' is valid and successfully converted.
                - False if 'date_time' is missing or invalid.

        Description:
            - Checks for the presence of the required `schedule.date_time` field.
            - Converts the `date_time` string into epoch milliseconds.
            - Updates the `schedule.date_time` field with the converted epoch value.
            - Sets operation result to failed if `date_time` is missing or invalid.
            - Logs all validation and transformation steps for traceability.
        """
        date_time = entry.get("schedule", {}).get("date_time")
        if not date_time:
            self.msg = "Missing required field 'schedule.date_time' for 'SCHEDULE_LATER'."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        epoch_time = self.convert_to_epoch(date_time)
        if epoch_time is None:
            self.msg = "Invalid date_time format. Expected 'YYYY-MM-DD HH:MM AM/PM'."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        # Additional Check: Ensure the scheduled time is not in the past
        current_epoch = int(time.time() * 1000)  # current time in milliseconds
        if epoch_time <= current_epoch:
            self.msg = (
                f"Invalid schedule: The provided date_time '{date_time}' is in the past. "
                "Please provide a future date and time for 'SCHEDULE_LATER' and 'SCHEDULE_RECURRENCE'."
            )
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return False

        entry["schedule"]["date_time"] = epoch_time
        self.log("Converted date_time to epoch for SCHEDULE_LATER: {0}".format(
            epoch_time), "DEBUG")
        return True

    def _validate_schedule_recurrence(self, entry):
        """
        Validate and transform recurrence-based schedule configuration.

        This method validates and transforms the input data provided in the playbook
        configuration for schedules of type `SCHEDULE_RECURRENCE`. It ensures all required
        fields are present, converts the provided date/time string into epoch format,
        and restructures recurrence details to match Catalyst Center API requirements.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            entry (dict): The configuration dictionary containing schedule and recurrence details
                        including date_time, time_zone, and recurrence rules.

        Returns:
            bool:
                - True if validation and transformation are successful.
                - False if required fields are missing or if date_time format is invalid.

        Description:
            - Extracts and validates recurrence configuration from the playbook entry.
            - Converts `date_time` from string ("YYYY-MM-DD HH:MM AM/PM") to epoch milliseconds.
            - Replaces `date_time` with `time` and `start_date` in the schedule.
            - Renames `recurrence_type` to `type` for API compatibility.
            - Ensures required fields (`time_zone`, `time`, `start_date`, `recurrence`, `type`) are present.
            - Performs additional recurrence pattern validation via `_validate_recurrence_pattern`.
            - Logs validation steps and error messages for traceability.
        """

        schedule = entry.get("schedule", {})
        recurrence = schedule.get("recurrence", {})

        # Transform recurrence_type to type
        if "recurrence_type" in recurrence:
            recurrence["type"] = recurrence.pop("recurrence_type")

        # Validate required fields
        date_time = schedule.get("date_time")
        if not date_time:
            self.msg = "Missing required schedule field: 'date_time'"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        # Convert date_time to epoch and set time/start_date
        epoch_time = self.convert_to_epoch(date_time)
        if epoch_time is None:
            self.msg = "Invalid date_time format for SCHEDULE_RECURRENCE."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        # Additional Check: Ensure the scheduled time is not in the past
        current_epoch = int(time.time() * 1000)  # current time in milliseconds
        if epoch_time <= current_epoch:
            self.msg = (
                f"Invalid schedule: The provided date_time '{date_time}' is in the past. "
                "Please provide a future date and time for 'SCHEDULE_LATER' and 'SCHEDULE_RECURRENCE'."
            )
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return False

        schedule.pop("date_time")
        schedule["time"] = epoch_time
        schedule["start_date"] = epoch_time

        # Validate required fields after transformation
        required_fields = ["time_zone", "time", "start_date", "recurrence", "type"]
        for field in required_fields:
            if field not in schedule:
                self.msg = "Missing required schedule field: '{0}'".format(field)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

        return self._validate_recurrence_pattern(recurrence)

    def _validate_recurrence_pattern(self, recurrence):
        """
        Validate recurrence pattern configuration for scheduled reports.

        This method verifies that the recurrence configuration provided in the
        playbook is valid and supported by the module. It checks the recurrence
        type (e.g., WEEKLY, MONTHLY) and delegates to the appropriate validation
        function based on the type.

        Parameters:
            recurrence (dict): The recurrence configuration dictionary containing
                            the recurrence type and associated scheduling details.

        Returns:
            bool:
                - True if the recurrence pattern is valid according to the type-specific rules.
                - False if the recurrence type is unsupported or validation fails.

        Description:
            - Extracts the recurrence type from the provided dictionary.
            - If recurrence type is "WEEKLY", validates using `_validate_weekly_recurrence`.
            - If recurrence type is "MONTHLY", validates using `_validate_monthly_recurrence`.
            - If recurrence type is not supported, logs an error, sets the operation
            result as failed, and returns False.
            - Provides detailed error messages for unsupported recurrence types.
        """
        recurrence_type = recurrence.get("type")

        if recurrence_type == "WEEKLY":
            return self._validate_weekly_recurrence(recurrence)
        elif recurrence_type == "MONTHLY":
            return self._validate_monthly_recurrence(recurrence)
        else:
            self.msg = "Recurrence type '{0}' is not supported in this module.".format(
                recurrence_type)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

    def _validate_weekly_recurrence(self, recurrence):
        """
        Validate weekly recurrence configuration for scheduled reports.

        This method ensures that the recurrence configuration for a weekly schedule
        includes the required `days` field, which specifies the days of the week
        (e.g., MONDAY, TUESDAY) when the report should run.

        Parameters:
            recurrence (dict): The recurrence configuration dictionary containing
                            scheduling details for a weekly recurrence pattern.

        Returns:
            bool:
                - True if the `days` field exists and is valid.
                - False if the `days` field is missing or invalid.

        Description:
            - Extracts the `days` key from the recurrence dictionary.
            - Validates that the `days` field is present.
            - If missing, logs an error and sets the operation result to failed.
            - Used as a sub-validation method for `_validate_recurrence_pattern`.
        """
        recurrence_days = recurrence.get("days", [])
        if "days" not in recurrence:
            self.msg = "Missing required schedule field: 'recurrence_days'"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        expected_days = {"MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY",
                         "FRIDAY", "SATURDAY", "SUNDAY"}

        # Normalize input (uppercase for consistency)
        recurrence_days = [d.upper() for d in recurrence_days]

        # If DAILY is provided, expand it to all days
        if "DAILY" in recurrence_days:
            recurrence["days"] = list(expected_days)
        else:
            # Validate input
            if not set(recurrence_days).issubset(expected_days):
                self.msg = "Invalid recurrence days. Must be DAILY or any of: MONDAY–SUNDAY."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

        self.log("Weekly recurrence validated with all 7 days", "DEBUG")
        return True

    def _validate_monthly_recurrence(self, recurrence):
        """
        Validate monthly recurrence configuration for scheduled reports.

        This method ensures that the recurrence configuration for a monthly
        schedule is correctly defined based on either `last_day_of_month` or
        `day_of_month`.

        Parameters:
            recurrence (dict): The recurrence configuration dictionary containing
                            scheduling details for a monthly recurrence pattern.

        Returns:
            bool:
                - True if the monthly recurrence is valid.
                - False if required fields are missing or invalid.

        Description:
            - Checks whether the recurrence specifies `last_day_of_month` or `day_of_month`.
            - If `last_day_of_month` is False, validates that `day_of_month` is an integer
            between 1 and 31.
            - If `last_day_of_month` is True, removes `day_of_month` (if present) since
            it becomes redundant.
            - Logs debug information for traceability.
            - Sets the operation result to failed if validation fails.
        """
        last_day_of_month = recurrence.get("last_day_of_month", False)
        day_of_month = recurrence.get("day_of_month")

        if not last_day_of_month:
            if not isinstance(day_of_month, int) or not (1 <= day_of_month <= 31):
                self.msg = (
                    "For MONTHLY recurrence, 'dayOfMonth' must be an integer between 1 and 31 "
                    "when 'lastDayOfMonth' is false."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False
        else:
            if "dayOfMonth" in recurrence:
                self.log("'dayOfMonth' ignored because 'lastDayOfMonth' is true.", "DEBUG")
                recurrence.pop("dayOfMonth")

        self.log("Monthly recurrence validated successfully", "DEBUG")
        return True

    def convert_to_epoch(self, date_str):
        """
        Convert a date string in the format 'YYYY-MM-DD HH:MM AM/PM' to epoch time in milliseconds.

        Parameters:
            date_str (str): Date and time string to be converted.
                Expected format: "YYYY-MM-DD HH:MM AM/PM"
                (e.g., "2025-09-02 07:30 PM").

        Returns:
            int | None: Epoch time in milliseconds if conversion succeeds,
            otherwise None if the input string is invalid or cannot be parsed.

        """
        try:
            time_struct = time.strptime(date_str, "%Y-%m-%d %I:%M %p")
            return int(time.mktime(time_struct) * 1000)
        except ValueError:
            self.log(f"exception occurred while converting date string to epoch time: {ValueError}", "ERROR")
            return None

    def validate_deliveries(self, deliveries):
        """
        Validate deliveries field according to rules:
        1. Must be a list with exactly one object.
        2. Type can be DOWNLOAD, NOTIFICATION (Email), or WEBHOOK.
        3. Enforce field-specific requirements for each type.

        Parameters:
            deliveries (list): User-provided delivery configuration.
                            Expected format varies by delivery type.

        Returns:
            bool: True if the input passes validation and normalization.
                False if the input is invalid, with error messages set
                in self.msg and logged via self.set_operation_result.

        Description:
            - Validates delivery configuration structure and count
            - Transforms delivery_type to type for API compatibility
            - Validates type-specific requirements for each delivery method
            - Normalizes NOTIFICATION delivery format for API calls
            - Logs all major validation steps and decision points for traceability
        """
        self.log(
            "Starting delivery configuration validation for {0} delivery entries".format(len(deliveries) if isinstance(deliveries, list) else "invalid"),
            "INFO"
        )
        # 1. Check it's a list with exactly one object
        if not isinstance(deliveries, list) or len(deliveries) != 1:
            self.msg = (
                "'deliveries' must be a list containing exactly one delivery type object."
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        delivery = deliveries[0]
        if not isinstance(delivery, dict):
            self.msg = "Each delivery entry must be a dictionary."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        delivery["type"] = delivery.pop("delivery_type", None)
        delivery_type = delivery.get("type")
        self.log("Validating delivery type: {0}".format(delivery_type), "DEBUG")
        if delivery_type not in ["DOWNLOAD", "NOTIFICATION", "WEBHOOK"]:
            self.msg = (
                f"Invalid delivery type '{delivery_type}'. Allowed types are: "
                "DOWNLOAD, NOTIFICATION (Email), WEBHOOK."
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        # 2. Type-specific validations
        if delivery_type == "DOWNLOAD":
            self.log("Processing DOWNLOAD delivery type - no additional validation required", "DEBUG")
            # No extra validation needed; default case
            pass

        elif delivery_type == "NOTIFICATION":
            self.log("Processing NOTIFICATION delivery type with email validation", "DEBUG")
            # Must have notification_endpoints with EMAIL type
            endpoints = delivery.get("notification_endpoints", [])
            if not isinstance(endpoints, list) or len(endpoints) != 1:
                self.msg = "'notification_endpoints' must be a list containing exactly one endpoint."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            endpoint = endpoints[0]
            # Default type to EMAIL if not provided
            endpoint_type = endpoint.get("type", "EMAIL")
            if endpoint_type != "EMAIL":
                self.msg = "'notification_endpoints[0].type' must be 'EMAIL'."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            email_addresses = endpoint.get("email_addresses", [])
            if not isinstance(email_addresses, list) or not all(isinstance(e, str) for e in email_addresses):
                self.msg = "'email_addresses' must be a list of valid email strings."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            self.log("Validated {0} email addresses for notification".format(len(email_addresses)), "DEBUG")

            # Map to API format
            api_endpoint = {
                "type": "EMAIL",
                "emailAddresses": email_addresses
            }

            # Optional email_attach
            email_attach = delivery.get("email_attach", False)
            if not isinstance(email_attach, bool):
                self.msg = "'email_attach' must be a boolean value."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            # Optional notify array
            notify_values = ["IN_QUEUE", "IN_PROGRESS", "COMPLETED"]
            notify = delivery.get("notify", [])
            if notify and (not isinstance(notify, list) or not all(n in notify_values for n in notify)):
                self.msg = f"'notify' must be a list containing only: {notify_values}."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            # Final normalized structure
            normalized_delivery = {
                "type": "NOTIFICATION",
                "notificationEndpoints": [api_endpoint],
                "emailAttach": email_attach,
                "notify": notify
            }

            # Replace original delivery with normalized one
            delivery.clear()
            delivery.update(normalized_delivery)
            self.log("Successfully normalized NOTIFICATION delivery configuration", "DEBUG")

        elif delivery_type == "WEBHOOK":
            self.log("Processing WEBHOOK delivery type with webhook name validation", "DEBUG")
            webhook_name = delivery.get("webhook_name")
            if not webhook_name or not isinstance(webhook_name, str):
                self.msg = "'webhook_name' is required for WEBHOOK delivery type."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False
            self.log("Validated webhook name: {0}".format(webhook_name), "DEBUG")

        self.log(
            "Completed delivery configuration validation successfully for type: {0}".format(delivery_type),
            "INFO"
        )
        return True

    def _validate_view_configuration(self, entry):
        """Validate and transform the view configuration including filters.

        This method ensures that the `view` section of a report configuration
        is valid, properly structured, and transformed where necessary. It
        validates the existence of the view, checks the filters list, and
        processes specific filters such as Location filters.

        Parameters:
            entry (dict): The report configuration entry containing the view
                        definition with optional filters.

        Returns:
            bool:
                - True if the view configuration and its filters are valid.
                - False if validation fails due to invalid structure or data.

        Description:
            - Ensures `view` is a dictionary, otherwise fails validation.
            - Ensures `filters`, if present, is a list of dictionaries.
            - Transforms the key `filter_type` into `type` for consistency.
            - Processes Location filters by delegating to `_process_location_filter`.
            - Logs all significant validation steps and outcomes for traceability.
            - Updates the operation result with error messages if validation fails.
        """
        view = entry.get("view", {})
        if not isinstance(view, dict):
            self.msg = "'view' must be a dictionary."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        filters = view.get("filters", [])
        if not filters:
            return True

        if not isinstance(filters, list):
            self.msg = "'filters' must be a list."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        self.log("Processing {0} filter(s) for view configuration".format(
            len(filters)), "DEBUG")

        for filter_index, filter_entry in enumerate(filters):
            if not isinstance(filter_entry, dict):
                self.msg = "Each filter entry must be a dictionary."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            # Transform filter_type to type
            if "filter_type" in filter_entry:
                filter_entry["type"] = filter_entry.pop("filter_type")

            # Process location filters
            if filter_entry.get("name") == "Location":
                if not self._process_location_filter(filter_entry, filter_index):
                    return False

        self.log("View configuration validation completed successfully", "DEBUG")
        return True

    def _process_location_filter(self, filter_entry, filter_index):
        """Process and validate the 'Location' filter by resolving site hierarchy IDs.

        This method validates the structure of the 'Location' filter, ensures
        its values are properly formatted, and replaces each location string
        with the corresponding site hierarchy ID retrieved from the site
        database. If validation or resolution fails, the operation result is
        marked as failed.

        Parameters:
            filter_entry (dict): The filter configuration dictionary that
                                must contain a 'value' list of locations.
            filter_index (int): The index of the filter being processed,
                                used for logging purposes.

        Returns:
            bool:
                - True if the location filter is valid and successfully
                resolved to site hierarchy IDs.
                - False if validation fails or site resolution is unsuccessful.

        Description:
            - Ensures `value` exists in the filter; initializes empty list if missing.
            - Validates that `value` is a list of dictionaries, each containing
            a `value` key (location string).
            - Uses `display_value` if provided, otherwise defaults to the location string.
            - Calls `get_site()` to resolve each location to its corresponding
            site hierarchy ID.
            - Replaces the original filter `value` with a list of resolved
            site hierarchy IDs and display values.
            - Logs detailed debug information at each step for traceability.
            - Updates the operation result with clear error messages when validation fails.
        """
        self.log("Processing location filter {0} with filter entry as {1}".format(filter_index + 1, self.pprint(filter_entry)), "DEBUG")

        filter_value = filter_entry.get("value")
        self.log("Current location filter value: {0}".format(filter_value), "DEBUG")
        if not filter_entry.get("display_value"):
            filter_entry["display_value"] = filter_entry["name"]

        if not filter_value:
            self.log("No locations provided in filter; initializing empty list", "DEBUG")
            filter_entry["value"] = []
            return True

        updated_values = []
        for item_index, item in enumerate(filter_value):
            if not isinstance(item, dict) or "value" not in item:
                self.msg = "Each item in 'Location' filter value must contain 'value'."
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            display_value = item.get("display_value", item["value"])

            # Resolve site hierarchy ID
            self.log("Resolving site hierarchy for location: {0}".format(
                item["value"]), "DEBUG")

            site_exist, site_id = self.get_site_id(item["value"])
            if not site_exist:
                self.msg = "Failed to retrieve site information for location as site doesn't exist: {0}".format(
                    item["value"])
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            updated_values.append({
                "value": site_id,
                "display_value": display_value
            })

            self.log("Resolved location '{0}' to site ID: {1}".format(
                item["value"], site_id), "DEBUG")

        filter_entry["value"] = updated_values
        self.log("Successfully processed location filter with {0} locations".format(
            len(updated_values)), "DEBUG")
        return True

    def get_webhook_destination_in_ccc(self, name):
        """
        Retrieve details of Rest Webhook destinations present in Cisco Catalyst Center.

        This method searches for a specific webhook destination by name using pagination
        to handle large numbers of webhook destinations efficiently.
        Parameters:
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

        self.log(
            "Starting webhook destination retrieval for name='{0}'".format(name),
            "INFO"
        )
        try:
            offset = 0
            limit = 10
            max_retries = 10  # Prevent infinite loops
            retry_count = 0

            while retry_count < max_retries:
                self.log(
                    "Fetching webhook destinations with offset={0}, limit={1}, attempt={2}".format(
                        offset * limit, limit, retry_count + 1
                    ),
                    "DEBUG"
                )
                try:
                    response = self.dnac._exec(
                        family="event_management",
                        function="get_webhook_destination",
                        params={"offset": offset * limit, "limit": limit},
                    )
                    offset = offset + 1
                    self.log(
                        "Received API response from 'get_webhook_destination': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    response = response.get("statusMessage", [])

                    if not response:
                        self.log(
                            "There is no Rest Webhook destination present in Cisco Catalyst Center",
                            "INFO",
                        )
                        return response

                    for destination in response:
                        if destination.get("name") == name:
                            self.log(
                                "Webhook Destination '{0}' present in Cisco Catalyst Center".format(
                                    name
                                ),
                                "INFO",
                            )
                            return destination

                    self.log(
                        "Webhook Destination '{0}' not found in Cisco Catalyst Center. Retrying after 1 second...".format(name),
                        "WARNING",
                    )
                    offset += 1
                    retry_count += 1

                    time.sleep(1)
                except Exception as e:
                    expected_exception_msgs = [
                        "Expecting value: line 1 column 1",
                        "not iterable",
                        "has no attribute",
                    ]
                    for msg in expected_exception_msgs:
                        if msg in str(e):
                            self.log(
                                "An exception occurred while checking for the Webhook destination with the name '{0}'. "
                                "It was not found in Cisco Catalyst Center.".format(
                                    name
                                ),
                                "WARNING",
                            )
                            return None
            self.log(
                "Webhook destination '{0}' not found after checking all available destinations".format(name),
                "WARNING"
            )
            self.log(
                "Completed webhook destination retrieval for name='{0}' - not found after exhaustive search".format(name),
                "INFO"
            )
            return None

        except Exception as e:
            self.status = "failed"
            self.msg = "Error while getting the details of Webhook destination(s) present in Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_want(self, config):
        """
        This method processes the playbook configuration to extract and validate report
        generation requirements, storing them in the instance's 'want' attribute for
        further processing during state comparison and execution.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.

        Returns:
            self: The current instance of the class with updated 'want' attributes.

        Description:
            - Extracts generate_report configuration from playbook input
            - Validates presence of required report generation configuration
            - Stores desired configuration state for comparison with current state
            - Logs all major decision points and validation steps for traceability
            - Provides foundation for state-based configuration management
        """
        self.log("Retrieving 'want' attributes from configuration: {0}".format(self.pprint(config)), "DEBUG")

        want = {"generate_report": config.get("generate_report", [])}
        if not want["generate_report"]:
            self.msg = "The 'generate_report' field is missing or empty in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.want = want
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")
        return self

    def get_all_view_groups(self, view_group_name):
        """
        Retrieve all view groups from Cisco Catalyst Center and find matching view group.

        This method retrieves all available view groups from Cisco Catalyst Center and
        searches for a specific view group by name to extract its ID and data category.


        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            view_group_name (str): The name of the view group to retrieve.

        Returns:
            tuple[str, str] | object:
                - (view_group_id, data_category): When a matching view group is found.
                - self: If no view group is found or an error occurs, with error details
                logged and `self.msg` populated.

        Description:
            - Retrieves all view groups using the reports API
            - Searches through view groups to find exact name match
            - Extracts view group ID and data category for matched view group
            - Logs all major decision points and API interactions for traceability
            - Returns structured data for further report configuration processing
        """
        self.log("Retrieving all view groups for view_group_name: {0}".format(self.pprint(view_group_name)), "DEBUG")
        try:
            response = self.dnac._exec(
                family="reports",
                function="get_all_view_groups",
            )
            self.log("Response from get_all_view_groups: {0}".format(self.pprint(response)), "DEBUG")
            if not response:
                self.msg = "Failed to retrieve view groups from Cisco Catalyst Center."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Processing {0} view groups to find match for '{1}'".format(
                    len(response), view_group_name
                ),
                "DEBUG"
            )

            view_group_id = None
            data_category = None
            for view_group_detail in response:
                if view_group_detail.get("name") == view_group_name:
                    self.log("Found data_category '{0}' in view groups.".format(view_group_name), "DEBUG")
                    view_group_id = view_group_detail.get("viewGroupId")
                    data_category = view_group_detail.get("category")
                    self.log("View group ID and data_category for view_group_name '{0}': {1}, {2}"
                             .format(view_group_name, view_group_id, data_category), "DEBUG")
                    break

            if not view_group_id:
                self.msg = "No view group found for view_group_name '{0}'.".format(view_group_name)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return self

            self.log(
                "Successfully retrieved view group details for '{0}' - ID: {1}, category: {2}".format(
                    view_group_name, view_group_id, data_category
                ),
                "INFO"
            )
            self.log(
                "Completed view groups retrieval and search for view_group_name='{0}'".format(
                    view_group_name
                ),
                "INFO"
            )
            return view_group_id, data_category
        except Exception as e:
            self.msg = "An error occurred while retrieving all view groups: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

    def get_views_for_a_given_view_group(self, view_group_id, view_name):
        """
        Retrieve all views for a given view group from Cisco Catalyst Center and find matching view.

        This method retrieves all available views for a specific view group and searches for a
        particular view by name to extract its ID for report configuration.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            view_group_id (str): The ID of the view group for which to retrieve views.
            view_name (str): The name of the view to retrieve. If not provided, all views will be returned.

        Returns:
            str | object:
                - If a matching view is found: returns the view ID (str).
                - If no matching view is found or an error occurs: returns `self` with the operation
                result set to "failed".

        Description:
            - Retrieves views for a specific view group using the reports API
            - Searches through views to find exact name match
            - Extracts view ID for matched view name
            - Logs all major decision points and API interactions for traceability
            - Returns view ID for further report configuration processing
        """
        self.log(
            "Starting view retrieval for view_group_id='{0}', view_name='{1}'".format(
                view_group_id, view_name
            ),
            "INFO"
        )
        try:
            self.log("Fetching views from Cisco Catalyst Center for view group ID: {0}".format(
                     view_group_id), "DEBUG")
            response = self.dnac._exec(
                family="reports",
                function="get_views_for_a_given_view_group",
                params={"view_group_id": view_group_id},
            )
            self.log("Response from get_views_for_a_given_view_group: {0}".format(self.pprint(response)), "DEBUG")
            if not response:
                self.msg = "Failed to retrieve views for view group ID '{0}'.".format(view_group_id)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            all_views_detail = response.get("views")
            self.log("All views detail for view group ID '{0}': {1}".format(view_group_id, self.pprint(all_views_detail)), "DEBUG")
            if not all_views_detail:
                self.msg = "No views found for view group ID '{0}'.".format(view_group_id)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            # Match the desired view by name
            if view_name:
                views_detail = None
                for view in all_views_detail:
                    if view.get("viewName") == view_name:
                        views_detail = view
                        self.log("Found matching view '{0}' with ID='{1}' in view group '{2}'".format(
                                 view_name, views_detail.get("viewId"), view_group_id
                                 ),
                                 "DEBUG"
                                 )
                        break
                if not views_detail:
                    self.msg = "No views found with name '{0}' in view group ID '{1}'.".format(view_name, view_group_id)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    return self

                view_id = views_detail.get("viewId")
                if not view_id:
                    self.msg = "No views found with name '{0}' in view group ID '{1}'.".format(
                        view_name, view_group_id
                    )
                    self.log(
                        "View search failed - '{0}' not found in view group ID '{1}'".format(
                            view_name, view_group_id
                        ),
                        "ERROR"
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    return self

                self.log(
                    "Successfully retrieved view ID '{0}' for view_name '{1}' in view group '{2}'".format(
                        view_id, view_name, view_group_id
                    ),
                    "INFO"
                )
                self.log(
                    "Completed view retrieval for view_group_id='{0}', view_name='{1}'".format(
                        view_group_id, view_name
                    ),
                    "INFO"
                )
                return view_id
        except Exception as e:
            self.msg = "An error occurred while retrieving views for view group ID '{0}': {1}".format(view_group_id, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

    def fetch_view_details(self, view_group_id, view_id):
        """
        Fetch view details for a given view group and view ID from Cisco Catalyst Center.

        This method retrieves comprehensive view metadata including field groups, filters,
        format options, and other configuration details for a specific view within a view group.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            view_group_id (str): The ID of the view group.
            view_id (str): The ID of the view.

        Returns:
            self: The current instance of the class with updated 'view_details' attribute.

        Description:
            - Retrieves detailed view metadata using the reports API
            - Stores view configuration including field groups, filters, and format options
            - Validates API response structure and content
            - Logs all major decision points and API interactions for traceability
            - Provides view metadata for report configuration validation and processing
        """
        self.log("Fetching view details for view group ID: {0}, view ID: {1}".format(view_group_id, view_id), "DEBUG")
        try:
            response = self.dnac._exec(
                family="reports",
                function="get_view_details_for_a_given_view_group_and_view",
                params={"view_group_id": view_group_id, "view_id": view_id},
            )
            self.log("Response from get_view_details_for_a_given_view_group_and_view: {0}".format(self.pprint(response)), "DEBUG")
            if not response:
                self.msg = "Failed to fetch view details for view group ID '{0}' and view ID '{1}'.".format(view_group_id, view_id)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            # Validate response structure
            self.log("Validating response structure and extracting view metadata", "DEBUG")

            # Log key view details for debugging
            view_name = response.get("name", "unknown")
            field_groups_count = len(response.get("fieldGroups", []))
            filters_count = len(response.get("filters", []))
            format_info = response.get("format", {})

            self.log(
                "View details retrieved - name: '{0}', field_groups: {1}, filters: {2}, format: {3}".format(
                    view_name, field_groups_count, filters_count, format_info.get("name", "unknown")
                ),
                "DEBUG"
            )

            # Store view details for further processing
            self.view_details = response

            self.log(
                "Successfully stored view details for view_group_id='{0}', view_id='{1}'".format(
                    view_group_id, view_id
                ),
                "INFO"
            )
            self.log(
                "Completed view details retrieval for view_group_id='{0}', view_id='{1}'".format(
                    view_group_id, view_id
                ),
                "INFO"
            )

        except Exception as e:
            self.msg = "An error occurred while fetching view details: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_have(self, config):
        """
        Retrieve and store the current state of reports from Cisco Catalyst Center.

        This method processes report configurations to determine their current state in
        Catalyst Center, including existence verification, webhook validation, and
        metadata retrieval for comparison with desired state.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing report details.

        Returns:
            self: The current instance of the class with updated 'have' attributes.

        Description:
            - Validates webhook destinations for WEBHOOK delivery types
            - Resolves view group names to IDs and data categories
            - Maps view names to view IDs within view groups
            - Checks for existing scheduled reports by name
            - Fetches detailed view metadata for non-deleted states
            - Logs all major decision points and API interactions for traceability
        """
        self.log("Retrieving 'have' attributes from configuration: {0}".format(self.pprint(config)), "DEBUG")
        generate_report = config.get("generate_report", [])

        if not generate_report:
            self.msg = "The 'generate_report' field is missing or empty in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log("Current state retrieval failed - no generate_report entries found", "ERROR")
            return self

        for entry_index, report_entry in enumerate(generate_report):
            report_name = report_entry.get("name", "unnamed")
            self.log(
                "Processing current state for report entry {0}: '{1}'".format(entry_index + 1, report_name),
                "DEBUG"
            )

            # Validate webhook destinations for WEBHOOK delivery type
            if not self._validate_webhook_destinations(report_entry):
                return self

            # Resolve view group information
            if not self._resolve_view_group_details(report_entry):
                return self

            # Check for existing scheduled reports
            if not self._check_existing_scheduled_reports(report_entry):
                return self

        # Fetch view details for non-deleted states
        if self.state != "deleted":
            self.log("Fetching detailed view metadata for report configuration validation", "DEBUG")
            for report_entry in generate_report:
                view_group_id = report_entry.get("view_group_id")
                view_id = report_entry.get("view", {}).get("view_id")
                if view_group_id and view_id:
                    self.fetch_view_details(view_group_id, view_id)

        # Store current state
        have = {"generate_report": generate_report}
        self.have = have
        self.msg = "Successfully retrieved the details from the Cisco Catalyst Center"

        self.log("Current State (have): {0}".format(str(self.pprint(self.have))), "INFO")
        self.log(
            "Completed current state retrieval from Catalyst Center successfully",
            "INFO"
        )
        return self

    def _validate_webhook_destinations(self, report_entry):
        """
        Validate webhook destinations for WEBHOOK delivery type.

        Parameters:
            report_entry (dict): The report entry to validate.

        Returns:
            bool: True if validation succeeds, False if validation fails.
        """
        deliveries = report_entry.get("deliveries", [])
        if not deliveries:
            return True

        for delivery in deliveries:
            if delivery.get("type") == "WEBHOOK" and self.state != "deleted":
                webhook_name = delivery.get("webhook_name")
                if not webhook_name:
                    self.msg = "webhook_name is required for WEBHOOK delivery type."
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return False

                self.log("Validating webhook destination: {0}".format(webhook_name), "DEBUG")

                webhook_destinations = self.get_webhook_destination_in_ccc(webhook_name)
                if not webhook_destinations:
                    self.msg = "No Webhook destination found in Cisco Catalyst Center for '{0}'.".format(
                        webhook_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return False

                webhook_id = webhook_destinations.get("webhookId")
                delivery["webhook_id"] = webhook_id

                self.log("Successfully validated webhook destination '{0}' with ID: {1}".format(
                    webhook_name, webhook_id), "DEBUG")

        return True

    def _resolve_view_group_details(self, report_entry):
        """
        Resolve view group name to ID and data category.

        Parameters:
            report_entry (dict): The report entry to process.

        Returns:
            bool: True if resolution succeeds, False if resolution fails.
        """
        view_group_name = report_entry.get("view_group_name")
        if not view_group_name:
            self.msg = "Mandatory parameter 'view_group_name' not found in report entry."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        self.log("Resolving view group details for: {0}".format(view_group_name), "DEBUG")

        view_group_id, data_category = self.get_all_view_groups(view_group_name)
        if not view_group_id:
            return False

        report_entry["view_group_id"] = view_group_id
        report_entry["data_category"] = data_category

        self.log("Resolved view group '{0}' to ID: {1}, category: {2}".format(
            view_group_name, view_group_id, data_category), "DEBUG")

        # Resolve view ID within the view group
        view_name = report_entry.get("view", {}).get("view_name")
        if not view_name:
            self.msg = "view_name is required in view configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        view_id = self.get_views_for_a_given_view_group(view_group_id, view_name)
        if not view_id:
            return False

        report_entry["view"]["view_id"] = view_id

        self.log("Resolved view '{0}' to ID: {1} in view group '{2}'".format(
            view_name, view_id, view_group_name), "DEBUG")

        return True

    def _check_existing_scheduled_reports(self, report_entry):
        """
        Check for existing scheduled reports by name.

        Parameters:
            report_entry (dict): The report entry to check.

        Returns:
            bool: True if check succeeds, False if check fails.
        """
        view_group_id = report_entry.get("view_group_id")
        view_id = report_entry.get("view", {}).get("view_id")
        report_name = report_entry.get("name")

        if not report_name:
            self.msg = "The 'name' field is mandatory in the 'generate_report' configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        self.log("Checking for existing scheduled reports for: {0}".format(report_name), "DEBUG")

        try:
            response = self.dnac._exec(
                family="reports",
                function="get_list_of_scheduled_reports",
                params={"viewGroupId": view_group_id, "viewId": view_id}
            )
            self.log("Response from get_list_of_scheduled_reports: {0}".format(
                self.pprint(response)), "DEBUG")

        except Exception as e:
            error_str = str(e)
            if "status_code: 404" in error_str or "\"status\":404" in error_str:
                self.log("No existing reports found (404 response) for report: {0}".format(
                    report_name), "DEBUG")
                report_entry["exists"] = False
                return True
            else:
                self.msg = "An error occurred while checking for existing reports: {0}".format(str(e))
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

        if not response:
            self.log("No scheduled reports found for view group/view combination", "DEBUG")
            report_entry["exists"] = False
            return True

        # Search for report by name
        get_list_of_scheduled_reports = response or []
        report_found = False

        for report in get_list_of_scheduled_reports:
            if report.get("name") == report_name:
                self.log("Found existing report '{0}' with ID: {1}".format(
                    report_name, report.get("reportId")), "DEBUG")

                report_entry["report_id"] = report.get("reportId")
                report_entry["view_group_id"] = report.get("viewGroupId")
                report_entry["view"]["view_id"] = report.get("view", {}).get("viewId")
                report_entry["exists"] = True
                report_found = True
                break

        if not report_found:
            self.log("Report '{0}' does not exist in current state".format(report_name), "DEBUG")
            report_entry["exists"] = False

        return True

    def create_n_schedule_reports(self, generate_report):
        """
        Create or schedule reports based on the provided configuration.

        This method processes a list of report configurations and creates or schedules each
        report in Cisco Catalyst Center. It handles existing report detection, payload
        preparation, API calls, and automatic report downloading for DOWNLOAD delivery types.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            generate_report (list): A list of report configurations to be created or scheduled.

        Returns:
            self: The current instance of the class with updated 'result' attribute.

        Description:
            - Validates required fields for each report configuration
            - Checks for existing reports to avoid duplicates
            - Transforms configuration to API-compatible format
            - Creates or schedules reports via Catalyst Center API
            - Automatically downloads reports for DOWNLOAD delivery types
            - Logs all major decision points and API interactions for traceability
        """
        self.log("Creating or scheduling reports with configuration: {0}".format(self.pprint(generate_report)), "DEBUG")
        if not generate_report:
            self.msg = "The 'generate_report' field is missing or empty in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        try:
            for report_index, report_entry in enumerate(generate_report):
                report_name = report_entry.get("name", "unnamed")
                self.log(
                    "Processing report {0}/{1}: '{2}'".format(
                        report_index + 1, len(generate_report), report_name
                    ),
                    "DEBUG"
                )

                # Validate required fields
                if not self._validate_report_entry_fields(report_entry):
                    return self

                # Handle existing reports
                if report_entry.get("exists"):
                    if not self._handle_existing_report(report_entry):
                        return self
                    continue

                # Create new report
                if not self._create_new_report(report_entry):
                    return self

            self.log(
                "Completed report creation and scheduling workflow successfully for {0} reports".format(
                    len(generate_report)
                ),
                "INFO"
            )

        except Exception as e:
            self.msg = "An error occurred while creating or scheduling reports: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log(
                "Exception during report creation workflow: {0}".format(str(e)),
                "ERROR"
            )

        return self

    def _validate_report_entry_fields(self, report_entry):
        """
        Validate required fields for a report entry.

        Parameters:
            report_entry (dict): The report entry to validate.

        Returns:
            bool: True if validation succeeds, False if validation fails.
        """
        required_fields = {
            "name": "The 'name' field is mandatory in the 'generate_report' configuration.",
            "view_group_id": "The 'view_group_id' field is mandatory in the 'generate_report' configuration.",
        }

        for field, error_msg in required_fields.items():
            if not report_entry.get(field):
                self.msg = error_msg
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

        if not report_entry.get("view", {}).get("view_id"):
            self.msg = "The 'view_id' field is mandatory in the 'view' configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

        return True

    def _create_new_report(self, report_entry):
        """
        Create a new report via API call.

        Parameters:
            report_entry (dict): The report entry to create.

        Returns:
            bool: True if creation succeeds, False if creation fails.
        """
        report_name = report_entry.get("name")
        self.log("Creating new report: '{0}'".format(report_name), "DEBUG")

        # Prepare API payload
        report_payload = self._prepare_report_payload(report_entry)
        if not report_payload:
            return False

        try:
            self.log("Sending report creation request to Catalyst Center API with payload: {0}".format(self.pprint(report_payload)), "DEBUG")
            response = self.dnac._exec(
                family="reports",
                function="create_or_schedule_a_report",
                params=report_payload
            )
            self.log(
                "Received response from create_or_schedule_a_report: {0}".format(
                    self.pprint(response)
                ),
                "DEBUG"
            )

            if not response:
                self.msg = "Failed to create or schedule report '{0}'.".format(report_name)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return False

            # Process successful response
            return self._process_creation_response(report_entry, response)

        except Exception as e:
            self.msg = "API call failed for report '{0}': {1}".format(report_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

    def _handle_existing_report(self, report_entry):
        """
        Handle processing for existing reports.

        Parameters:
            report_entry (dict): The report entry for an existing report.

        Returns:
            bool: True if handling succeeds, False if handling fails.
        """
        report_name = report_entry.get("name")
        report_id = report_entry.get("report_id")

        self.log(
            "Report '{0}' with ID '{1}' already exists - skipping creation".format(
                report_name, report_id
            ),
            "DEBUG"
        )

        result = {
            "response": {
                "report_id": report_id,
                "view_group_id": report_entry.get("view_group_id"),
                "view_id": report_entry.get("view", {}).get("view_id"),
            },
            "msg": "Report '{0}' already exists.".format(report_name),
        }
        self.result["response"].append({"create_report": result})

        # Handle download for existing reports if requested
        if self._is_download_requested(report_entry) and self._should_download_immediately(report_entry):
            self.log(
                "Download requested for existing report '{0}' - proceeding to download".format(
                    report_name
                ),
                "DEBUG"
            )
            return self._download_report_if_needed(report_entry, report_id)

        return True

    def _prepare_report_payload(self, report_entry):
        """
        Prepare API payload for report creation.

        Parameters:
            report_entry (dict): The report entry to transform.

        Returns:
            dict: API-compatible payload or None if preparation fails.
        """
        try:
            # Convert to camelCase for API compatibility
            report_payload = self.convert_keys_to_camel_case(report_entry)

            # Transform specific fields for API requirements
            if "schedule" in report_payload and "timeZone" in report_payload["schedule"]:
                report_payload["schedule"]["timeZoneId"] = report_payload["schedule"].pop("timeZone")

            if "view" in report_payload and "format" in report_payload["view"]:
                format_dict = report_payload["view"]["format"]
                if "name" not in format_dict:
                    format_dict["name"] = format_dict.get("formatType", "CSV")

                view_data = report_payload["view"]
                if "viewName" in view_data:
                    view_data["name"] = view_data.pop("viewName")

            self.log(
                "Prepared API payload for report '{0}'".format(report_entry.get("name")),
                "DEBUG"
            )
            return report_payload

        except Exception as e:
            self.msg = "Failed to prepare payload for report '{0}': {1}".format(
                report_entry.get("name"), str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

    def _process_creation_response(self, report_entry, response):
        """
        Process successful report creation response.

        Parameters:
            report_entry (dict): The original report entry.
            response (dict): The API response from report creation.

        Returns:
            bool: True if processing succeeds, False if processing fails.
        """
        report_name = report_entry.get("name")
        report_id = response.get("reportId")

        result = {
            "response": {
                "reportId": report_id,
                "viewGroupId": response.get("viewGroupId"),
                "viewsId": response.get("view", {}).get("viewId"),
            },
            "msg": "Successfully created or scheduled report '{0}'.".format(report_name)
        }

        self.result["response"].append({"create_report": result})
        self.log("Successfully created report '{0}' with ID: {1}".format(
            report_name, report_id), "INFO")

        self.status = "success"
        self.result["changed"] = True

        # Handle download for immediate execution reports
        if self._should_download_immediately(report_entry):
            self.log(
                "Download requested for new report '{0}' - proceeding to download".format(
                    report_name
                ),
                "DEBUG"
            )
            return self._download_report_if_needed(report_entry, report_id)

        return True

    def _is_download_requested(self, report_entry):
        """Check if download is requested for the report."""
        return any(
            d.get("type", "").upper() == "DOWNLOAD"
            for d in report_entry.get("deliveries", [])
        )

    def _should_download_immediately(self, report_entry):
        """Check if report should be downloaded immediately."""
        return (
            self._is_download_requested(report_entry) and
            report_entry.get("schedule", {}).get("type") == "SCHEDULE_NOW"
        )

    def _download_report_if_needed(self, report_entry, report_id):
        """
        Download report if needed and handle any errors.

        Parameters:
            report_entry (dict): The report entry.
            report_id (str): The report ID.

        Returns:
            bool: True if download succeeds or is not needed, False if download fails.
        """
        try:
            self.report_download(report_entry, report_id)
            return True
        except Exception as e:
            self.msg = "Failed to download report '{0}': {1}".format(
                report_entry.get("name"), str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return False

    def get_diff_merged(self, config):
        """
        Generate and apply configuration differences for merged state operations.

        This method processes the configuration to identify differences between desired
        and current states, then applies the necessary changes to create or scheduleg2763

        reports in Cisco Catalyst Center for the merged state.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing report details.

        Returns:
            self: The current instance of the class with updated 'diff' attributes.

        Description:
            - Validates presence of report generation configuration
            - Identifies differences between desired and current states
            - Creates or schedules new reports as needed
            - Updates existing reports if configuration changes are detected
            - Logs all major decision points and processing steps for traceability
            - Ensures idempotent behavior for merged state operations
        """
        self.log(
            "Starting merged state difference generation and application for {0} report entries".format(
                len(config.get("generate_report", []))
            ),
            "INFO"
        )
        generate_report = config.get("generate_report", [])
        if not generate_report:
            self.msg = "The 'generate_report' field is missing or empty in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.log(
            "Processing {0} report configurations for merged state operations".format(
                len(generate_report)
            ),
            "DEBUG"
        )

        # Log summary of reports to be processed
        for report_index, report_entry in enumerate(generate_report):
            report_name = report_entry.get("name", "unnamed")
            exists = report_entry.get("exists", False)
            action = "update/verify" if exists else "create"

            self.log(
                "Report {0}/{1}: '{2}' - action: {3}".format(
                    report_index + 1, len(generate_report), report_name, action
                ),
                "DEBUG"
            )

        # Delegate to report creation and scheduling method
        self.log("Delegating to report creation and scheduling workflow", "DEBUG")
        self.create_n_schedule_reports(generate_report).check_return_status()

        self.log(
            "Completed merged state difference generation and application successfully",
            "INFO"
        )
        return self

    def get_execution_id_for_report(self, report_id):
        """
        Retrieve the execution ID for a given report ID from Cisco Catalyst Center,
        retrying until the execution status is 'SUCCESS' or timeout is reached.

        Parameters:
            report_id (str): The ID of the report for which to retrieve the execution ID.

        Returns:
            str: The execution ID associated with the specified report ID if successful.
            None: If no successful execution is found within the timeout period.
        """
        self.log(
            "Fetching execution ID for report ID: {0}".format(report_id),
            "INFO",
        )

        start_time = time.time()
        retry_interval = int(self.payload.get("dnac_task_poll_interval", 5))
        timeout = int(self.payload.get("dnac_api_task_timeout", 100))

        while True:
            try:
                response = self.dnac._exec(
                    family="reports",
                    function="get_all_execution_details_for_a_given_report",
                    params={"report_id": report_id},
                )
                self.log(
                    "Response from get_execution_id_for_report: {0}".format(
                        self.pprint(response)
                    ),
                    "DEBUG",
                )

                executions = response.get("executions", []) if response else []
                if not executions:
                    self.log(
                        "No executions found yet for report ID '{0}'.".format(report_id),
                        "WARNING",
                    )
                else:
                    # Iterate through executions to check status
                    for execution in executions:
                        execution_id = execution.get("executionId")
                        status = execution.get("processStatus")

                        self.log(
                            "Execution ID: {0}, Status: {1}".format(execution_id, status),
                            "DEBUG",
                        )

                        if status and status.upper() == "SUCCESS":
                            self.log(
                                "Found successful execution for report ID '{0}': {1}".format(
                                    report_id, execution_id
                                ),
                                "INFO",
                            )
                            return execution_id

            except Exception as e:
                self.log(
                    "Error while fetching execution ID for report ID {0}: {1}".format(
                        report_id, str(e)
                    ),
                    "ERROR",
                )

            # Timeout check
            if time.time() - start_time >= timeout:
                self.log(
                    "Timeout reached while waiting for successful execution of report ID: {0}".format(
                        report_id
                    ),
                    "ERROR",
                )
                return None

            # Sleep before retrying
            self.log(
                "Waiting {0} seconds before retrying execution status for report ID: {1}".format(
                    retry_interval, report_id
                ),
                "DEBUG",
            )
            time.sleep(retry_interval)

    def download_report_with_retry(self, report_id, execution_id):
        """
        Download report content with retry mechanism for handling transient failures.

        This method attempts to download report content from Cisco Catalyst Center with
        built-in retry logic to handle temporary network issues or API unavailability.
        It provides robust download functionality with proper error handling and logging.

        Parameters:
            report_id (str): Unique identifier for a report definition/configuration.
            execution_id (str): Unique identifier for a specific execution/run of a report.

        Returns:
            download_data: The downloaded report content if successfully downloaded.
        """

        self.log(
            f"Attempting to download report with report_id={report_id}, execution_id={execution_id}",
            "INFO"
        )

        start_time = time.time()
        retry_interval = int(self.payload.get("dnac_task_poll_interval", 5))
        resync_retry_count = int(self.payload.get("dnac_api_task_timeout", 100))

        while True:
            try:
                download_response = self.dnac._exec(
                    family="reports",
                    function="download_report_content",
                    params={"report_id": report_id, "execution_id": execution_id}
                )

                download_data = download_response.data
                self.log(
                    "Response from download_report_content: {0}".format(download_data),
                    "DEBUG"
                )

                # If data is present and not error, return it
                if download_data and not isinstance(download_data, dict):
                    return download_data

            except Exception as e:
                err_str = str(e)
                error_code = None
                error_msg = None

                # Try to extract JSON part from exception
                match = re.search(r'(\{.*\})', err_str)
                if match:
                    try:
                        err_json = json.loads(match.group(1))
                        if "error" in err_json:
                            error_code = err_json["error"][0].get("errorCode")
                            error_msg = err_json["error"][0].get("errorMessage")
                    except json.JSONDecodeError:
                        pass

                if error_code == 4002:
                    self.log(
                        f"Report not ready yet (error {error_code}: {error_msg}), retrying...",
                        "WARNING"
                    )
                else:
                    self.msg = f"Exception during report download with retry: {err_str}"
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            # Timeout check
            if time.time() - start_time >= resync_retry_count:
                self.msg = f"Max retries reached. Report file not available (report_id={report_id}, execution_id={execution_id})."
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            # Wait before retry
            self.log(
                f"Waiting {retry_interval} seconds before retrying report download (report_id={report_id}, execution_id={execution_id})",
                "DEBUG"
            )
            time.sleep(retry_interval)

    def report_download(self, report_entry, report_id):
        """
        Download the report content after it has been created or scheduled.

        This method manages the complete report download workflow including execution ID retrieval,
        content download with retry mechanism, and local file storage. It handles both immediate
        and scheduled report downloads with proper validation and error recovery.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            report_entry (dict): The report entry containing details for downloading the report.
            report_id (str): The unique identifier of the report to download from Catalyst Center.

        Returns:
            self: The current instance of the class with updated 'result' attribute.

        Description:
            - Validates report configuration and download requirements
            - Retrieves execution ID for completed report instances
            - Downloads report content using retry mechanism for reliability
            - Saves report content to local file system with proper naming
            - Handles various download scenarios including immediate and scheduled reports
            - Logs all major decision points and download progress for traceability
            - Updates operation results with success or failure status
        """
        self.log("Downloading report content for report entry: {0}".format(self.pprint(report_entry)), "DEBUG")

        if not report_entry:
            self.msg = "Report entry configuration is required for download operation."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log("Report download failed - no report_entry provided", "ERROR")
            return self

        if not report_id:
            self.msg = "Report ID is required for download operation."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log("Report download failed - no report_id provided", "ERROR")
            return self

        report_name = report_entry.get("name", "unnamed")

        self.log(
            "Starting report download workflow for report_id='{0}', report_name='{1}'".format(
                report_id, report_name
            ),
            "INFO"
        )

        try:
            file_path = report_entry.get("file_path", "./")
            if not file_path:
                self.msg = "File path is required for downloading the report."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            execution_id = self.get_execution_id_for_report(report_id)
            if not execution_id:
                self.msg = "Failed to retrieve execution ID for report '{0}'.".format(report_entry.get("name"))
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            download_data = self.download_report_with_retry(report_id, execution_id)

            # Validate file_path
            deliveries = report_entry.get("deliveries", [])
            view = report_entry.get("view", {})
            file_format = view.get("format", {}).get("format_type")
            default_format = ".csv"  # Default file format if not specified

            for delivery in deliveries:
                if delivery.get("type", "").upper() == "DOWNLOAD" and "file_path" in delivery:
                    file_path = delivery["file_path"]
                    break  # Found it, no need to continue

            if not file_path:
                self.log("No 'file_path' provided. Cannot save the downloaded file.", "WARNING")
                self.msg = "File path is required for saving the downloaded report."
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            # Determine file format
            if not file_format.startswith("."):
                file_format = "." + file_format  # Ensure it starts with "."

            # Determine file name (download_id or default name)
            report_name = report_entry.get("name", "report")

            # Construct full path
            full_path = os.path.join(file_path, f"{report_name}{file_format}")

            # Save the file
            try:
                os.makedirs(file_path, exist_ok=True)
                with open(full_path, "wb") as f:
                    f.write(download_data)
                self.log(f"File saved successfully at {full_path}", "INFO")
            except Exception as e:
                self.msg = "Failed to save the downloaded file: {0}".format(str(e))
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return self

            result = {
                "response": {
                    "reportId": report_id,
                    "reportName": report_entry.get("name"),
                    "filePath": file_path
                },
                "msg": "Successfully downloaded report '{0}' to '{1}'.".format(report_entry.get("name"), file_path),
            }
            self.result["response"].append({"download_report": result})
            self.log("Successfully downloaded report: {0}".format(report_entry.get("name")), "INFO")
            self.status = "success"
            self.result["changed"] = True
        except Exception as e:
            self.msg = "An error occurred while downloading the report: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        return self

    def get_diff_deleted(self, config):
        """
        Generate and apply configuration differences for deleted state operations.

        This method processes the configuration to identify and remove existing reports
        from Cisco Catalyst Center that are marked for deletion. It handles the complete
        deletion workflow including validation, existence checking, and cleanup operations.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing report details.

        Returns:
            self: The current instance of the class with updated 'diff' attributes.

        Description:
            - Validates presence of report deletion configuration
            - Identifies existing reports that need to be deleted
            - Removes scheduled reports and their associated configurations
            - Cleans up related resources and execution histories
            - Logs all major decision points and deletion steps for traceability
            - Ensures complete cleanup for deleted state operations
        """
        self.log("Starting deletion from configuration: {0}".format(self.pprint(config)), "DEBUG")
        generate_report = config.get("generate_report", [])
        if not generate_report:
            self.msg = "The 'generate_report' field is missing or empty in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.log(
            "Processing {0} report configurations for deletion state operations".format(
                len(generate_report)
            ),
            "DEBUG"
        )

        try:
            deletion_candidates = 0
            for report_index, report_entry in enumerate(generate_report):
                report_name = report_entry.get("name", "unnamed")
            for report_entry in generate_report:
                report_name = report_entry.get("name")
                self.log("Attempting to delete report: {0}".format(report_name), "DEBUG")
                if not report_entry.get("exists", False):
                    self.log("Report '{0}' does not exist, skipping deletion.".format(report_name), "DEBUG")
                    result = {
                        "response": {},
                        "msg": "Report '{0}' does not exist.".format(report_name),
                    }
                    self.result["response"].append({"delete_report": result})
                    self.msg = "Report '{0}' does not exist.".format(report_name)
                    self.log("Report '{0}' does not exist, skipping deletion.".format(report_name), "DEBUG")
                    continue
                if not report_entry.get("report_id"):
                    self.msg = "The 'report_id' field is mandatory in the 'generate_report' configuration for deletion."
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                response = self.dnac._exec(
                    family="reports",
                    function="delete_a_scheduled_report",
                    params={"report_id": report_entry.get("report_id")},
                )
                self.log("Response from delete_a_scheduled_report: {0}".format(self.pprint(response)), "DEBUG")
                if not response.get("status") == 200:
                    self.msg = "Failed to delete report with ID '{0}'.".format(report_entry.get("report_id"))
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                result = {
                    "response": {"report_id": report_entry.get("report_id")},
                    "msg": "Report '{0}' has been successfully deleted.".format(report_entry.get("name")),
                }
                self.result["response"].append({"delete_report": result})
                self.msg = "Successfully deleted report with ID: {0}".format(report_entry.get("report_id"))
                self.log(self.msg, "INFO")
                self.status = "success"
                self.result["changed"] = True
        except Exception as e:
            self.msg = "An error occurred while deleting the report: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        self.log(
            "Completed deleted state difference generation and processing successfully",
            "INFO"
        )
        return self

    def verify_diff_merged(self, config):
        """
        Verify merged state configuration against current state in Cisco Catalyst Center.

        This method validates that the desired report configurations match the current
        state in Catalyst Center, ensuring idempotency and confirming successful
        deployment of report generation workflows.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco
                Catalyst Center.
            config (dict): The configuration dictionary containing report generation
                details including generate_report list with all report specifications
                that need to be verified against current state.

        Returns:
            self: The current instance of the class with updated 'result' attributes
                containing the verification outcomes and any discrepancies found.

        Description:
            - Validates presence of report generation configuration
            - Compares desired state against current state in Catalyst Center
            - Verifies report existence, configuration accuracy, and operational status
            - Identifies configuration drift or deployment issues
            - Validates webhook destinations, view groups, and delivery configurations
            - Logs all major decision points and verification steps for traceability
            - Ensures configuration compliance and operational readiness
        """
        self.log(
            "Starting merged state verification for {0} report entries against Catalyst Center".format(
                len(config.get("generate_report", []))
            ),
            "INFO"
        )
        getattr(self, "get_have")(self.validated_config[0])
        generate_report = self.have.get("generate_report", [])

        if not generate_report:
            self.msg = "No reports found in the current state after creation."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.log(
            "Processing {0} report configurations for merged state verification".format(
                len(generate_report)
            ),
            "DEBUG"
        )

        # Log summary of reports to be verified
        verification_summary = {
            "total_reports": len(generate_report),
            "existing_reports": 0,
            "new_reports": 0,
            "webhook_deliveries": 0,
            "notification_deliveries": 0,
            "download_deliveries": 0
        }
        for report_index, report_entry in enumerate(generate_report):
            report_name = report_entry.get("name", "unnamed")
            exists = report_entry.get("exists", False)

            if exists:
                verification_summary["existing_reports"] += 1
                status = "verify existing configuration"
            else:
                verification_summary["new_reports"] += 1
                status = "verify new deployment"

            # Count delivery types for verification complexity assessment
            deliveries = report_entry.get("deliveries", [])
            for delivery in deliveries:
                delivery_type = delivery.get("type", "").upper()
                if delivery_type == "WEBHOOK":
                    verification_summary["webhook_deliveries"] += 1
                elif delivery_type == "NOTIFICATION":
                    verification_summary["notification_deliveries"] += 1
                elif delivery_type == "DOWNLOAD":
                    verification_summary["download_deliveries"] += 1

            self.log(
                "Report {0}/{1}: '{2}' - {3}".format(
                    report_index + 1, len(generate_report), report_name, status
                ),
                "DEBUG"
            )

        self.log(
            "Verification summary - Total: {0}, Existing: {1}, New: {2}, Webhook: {3}, Notification: {4}, Download: {5}".format(
                verification_summary["total_reports"],
                verification_summary["existing_reports"],
                verification_summary["new_reports"],
                verification_summary["webhook_deliveries"],
                verification_summary["notification_deliveries"],
                verification_summary["download_deliveries"]
            ),
            "INFO"
        )

        # Validate configuration integrity before verification
        self.log("Validating configuration integrity before state verification", "DEBUG")

        validation_errors = []
        for report_entry in generate_report:
            report_name = report_entry.get("name", "unnamed")

            # Validate required fields for verification
            if not report_entry.get("view_group_name"):
                validation_errors.append("Report '{0}' missing view_group_name".format(report_name))

            if not report_entry.get("view", {}).get("view_name"):
                validation_errors.append("Report '{0}' missing view.view_name".format(report_name))

            if not report_entry.get("deliveries"):
                validation_errors.append("Report '{0}' missing deliveries configuration".format(report_name))

        if validation_errors:
            self.msg = "Configuration validation failed: {0}".format("; ".join(validation_errors))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log(
                "Merged state verification failed - configuration validation errors: {0}".format(
                    "; ".join(validation_errors)
                ),
                "ERROR"
            )
            return self

        self.log("Configuration integrity validation passed successfully", "DEBUG")

        # Delegate to report verification workflow
        self.log("Delegating to report verification workflow for detailed state comparison", "DEBUG")

        try:
            self.log(
                "Report verification workflow completed - checking operation status",
                "DEBUG"
            )

            # Log verification results summary
            if hasattr(self, 'result') and self.result.get("response"):
                verification_results = len(self.result["response"])
                self.log(
                    "Verification completed with {0} result entries processed".format(
                        verification_results
                    ),
                    "INFO"
                )

        except Exception as e:
            self.msg = "Error during report verification workflow: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log(
                "Exception during report verification workflow: {0}".format(str(e)),
                "ERROR"
            )
            return self

        self.log(
            "Completed merged state verification for {0} report entries successfully".format(
                len(generate_report)
            ),
            "INFO"
        )
        return self

    def verify_diff_deleted(self, config):
        """ Verify deleted state configuration against current state in Cisco Catalyst Center.

        This method validates that reports marked for deletion have been successfully
        removed from Catalyst Center, ensuring complete cleanup and confirming the
        absence of scheduled reports and their associated configurations.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco
                Catalyst Center.
            config (dict): The configuration dictionary containing report generation
                details including generate_report list with reports that should be
                verified as deleted from the system.

        Returns:
            self: The current instance of the class with updated 'result' attributes
                containing the deletion verification outcomes and any cleanup issues found.

        Description:
            - Validates presence of report deletion configuration
            - Verifies complete removal of reports from Catalyst Center
            - Confirms cleanup of scheduled reports, executions, and related resources
            - Identifies incomplete deletions or orphaned configurations
            - Validates webhook destinations cleanup and delivery configuration removal
            - Logs all major decision points and verification steps for traceability
            - Ensures complete state cleanup and deletion compliance
        """
        self.log(
            "Starting deleted state verification for {0} report entries against Catalyst Center".format(
                len(config.get("generate_report", []))
            ),
            "INFO"
        )

        generate_report = config.get("generate_report", [])
        if not generate_report:
            self.msg = "The 'generate_report' field is missing or empty in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log("Deleted state verification failed - no generate_report entries found", "ERROR")
            return self

        self.log(
            "Processing {0} report configurations for deleted state verification".format(
                len(generate_report)
            ),
            "DEBUG"
        )

        # Log summary of reports to be verified for deletion
        verification_summary = {
            "total_reports": len(generate_report),
            "should_be_deleted": 0,
            "already_absent": 0,
            "webhook_deliveries": 0,
            "notification_deliveries": 0,
            "download_deliveries": 0
        }

        for report_index, report_entry in enumerate(generate_report):
            report_name = report_entry.get("name", "unnamed")
            exists = report_entry.get("exists", False)

            if exists:
                verification_summary["should_be_deleted"] += 1
                status = "verify successful deletion"
            else:
                verification_summary["already_absent"] += 1
                status = "confirm already deleted"

            # Count delivery types for verification complexity assessment
            deliveries = report_entry.get("deliveries", [])
            if deliveries:
                for delivery in deliveries:
                    delivery_type = delivery.get("type", "").upper()
                    if delivery_type == "WEBHOOK":
                        verification_summary["webhook_deliveries"] += 1
                    elif delivery_type == "NOTIFICATION":
                        verification_summary["notification_deliveries"] += 1
                    elif delivery_type == "DOWNLOAD":
                        verification_summary["download_deliveries"] += 1

            self.log(
                "Report {0}/{1}: '{2}' - {3}".format(
                    report_index + 1, len(generate_report), report_name, status
                ),
                "DEBUG"
            )

        self.log(
            "Deletion verification summary - Total: {0}, Should be deleted: {1}, Already absent: {2}, Webhook: {3}, Notification: {4}, Download: {5}".format(
                verification_summary["total_reports"],
                verification_summary["should_be_deleted"],
                verification_summary["already_absent"],
                verification_summary["webhook_deliveries"],
                verification_summary["notification_deliveries"],
                verification_summary["download_deliveries"]
            ),
            "INFO"
        )

        # Validate configuration integrity before deletion verification
        self.log("Validating configuration integrity before deletion state verification", "DEBUG")

        validation_errors = []
        for report_entry in generate_report:
            report_name = report_entry.get("name", "unnamed")

        # Validate required fields for deletion verification
        if not report_name or report_name == "unnamed":
            validation_errors.append("Report entry missing valid name for deletion verification")

        if validation_errors:
            self.msg = "Configuration validation failed for deletion verification: {0}".format("; ".join(validation_errors))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log(
                "Deleted state verification failed - configuration validation errors: {0}".format(
                    "; ".join(validation_errors)
                ),
                "ERROR"
            )
            return self

        self.log("Configuration integrity validation passed for deletion verification", "DEBUG")

        # Verify current state to confirm deletions
        self.log("Checking current state in Catalyst Center to verify report deletions", "DEBUG")

        try:
            # Get current state to verify deletions
            current_state_config = {"generate_report": generate_report}
            self.get_have(current_state_config)

            self.log("Current state retrieval completed for deletion verification", "DEBUG")

            # Analyze deletion verification results
            deletion_verification_results = []
            for report_entry in generate_report:
                report_name = report_entry.get("name", "unnamed")
                currently_exists = report_entry.get("exists", False)

                if currently_exists:
                    deletion_verification_results.append(
                        "Report '{0}' still exists - deletion not completed".format(report_name)
                    )
                else:
                    deletion_verification_results.append(
                        "Report '{0}' successfully deleted or already absent".format(report_name)
                    )

            # Log deletion verification results
            for result in deletion_verification_results:
                if "still exists" in result:
                    self.log(result, "WARNING")
                else:
                    self.log(result, "DEBUG")

            # Check if any reports still exist that shouldn't
            remaining_reports = [
                entry.get("name", "unnamed") for entry in generate_report
                if entry.get("exists", False)
            ]

            if remaining_reports:
                self.log(
                    "Deletion verification found {0} reports still existing: {1}".format(
                        len(remaining_reports), ", ".join(remaining_reports)
                    ),
                    "WARNING"
                )
            else:
                self.log(
                    "Deletion verification confirmed all {0} reports are successfully deleted or absent".format(
                        len(generate_report)
                    ),
                    "INFO"
                )

        except Exception as e:
            self.msg = "Error during deletion verification state check: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log(
                "Exception during deletion verification state check: {0}".format(str(e)),
                "ERROR"
            )
            return self

        # Update result with verification summary
        if hasattr(self, 'result') and 'response' in self.result:
            verification_result = {
                "verification_type": "deleted_state",
                "total_reports_checked": len(generate_report),
                "reports_verified_deleted": len([r for r in generate_report if not r.get("exists", False)]),
                "reports_still_existing": len([r for r in generate_report if r.get("exists", False)])
            }
            self.result["response"].append({"deletion_verification": verification_result})

        self.log(
            "Completed deleted state verification for {0} report entries successfully".format(
                len(generate_report)
            ),
            "INFO"
        )
        return self


def main():
    """main entry point for module execution"""
    element_spec = {
        "dnac_host": {"type": "str", "required": True},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": True},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"], "type": "str"},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    ccc_report = Reports(module)
    state = ccc_report.params.get("state")

    if state not in ccc_report.supported_states:
        ccc_report.status = "invalid"
        ccc_report.msg = "State '{0}' is invalid. Supported states: {1}".format(
            state, ", ".join(ccc_report.supported_states)
        )
        ccc_report.check_return_status()

    ccc_version = ccc_report.get_ccc_version()
    if ccc_report.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
        ccc_report.msg = (
            "The specified version '{0}' does not support the Flexible Report features. "
            "Supported versions start from '2.3.7.9' onwards.".format(ccc_version)
        )
        ccc_report.status = "failed"
        ccc_report.check_return_status()
    ccc_report.validate_input().check_return_status()
    config_verify = ccc_report.params.get("config_verify")

    for config in ccc_report.validated_config:
        if state != "deleted":
            ccc_report.input_data_validation(config).check_return_status()
        ccc_report.get_want(config).check_return_status()
        ccc_report.get_have(config).check_return_status()
        ccc_report.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_report.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_report.result)


if __name__ == "__main__":
    main()
