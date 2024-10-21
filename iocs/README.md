# AWS Honey Credential IOC Feed

## Overview
This repository contains Indicators of Compromise (IOCs) extracted from AWS honey credentials. These IOCs are part of a broader effort to monitor malicious activity that simulates AWS credentials being abused. The data collected includes source IP addresses, user agents, and event names associated with suspicious activity detected via the honey creds.

## How It Works
This repository is regularly updated with new IOCs collected from the AWS honey credentials. These honey tokens are designed to look like real AWS credentials but are purely for tracking and collecting intelligence on malicious actors who attempt to exploit them.

## IOC Files

### `iocs/cloud_iocs_ips_only.txt`
- **Description**: This file contains a list of unique IP addresses associated with interactions targeting AWS honey credentials. These IP addresses represent potential attackers or malicious actors that have triggered the honey token.
- **Format**: Plain text, with one IP address per line.

### `iocs/cloud_iocs.csv`
- **Description**: This CSV file provides more detailed context for each interaction with the AWS honey credentials, including:
  - **Source IP**: The IP address of the entity triggering the honey token.
  - **User Agent**: The user agent string associated with the request, which can provide information about the client used.
  - **Event Name**: The AWS event associated with the activity, e.g., `AttachUserPolicy`, `GetCallerIdentity`, etc.
- **Format**: Comma-separated values (CSV) with columns: `src_ip`, `user_agent`, and `event_name`.

## Disclaimer
This feed is intended for use in threat detection and research. **BLOCK AT YOUR OWN RISK**
