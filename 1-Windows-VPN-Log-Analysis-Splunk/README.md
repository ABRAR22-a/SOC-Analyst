# Windows and VPN Log Analysis Using Splunk

## 1. Project Overview

A hands-on cybersecurity training project completed using Splunk in a TryHackMe lab environment.

The objective was to practice searching, filtering, and analyzing Windows event logs and VPN authentication records using Search Processing Language (SPL).

## 2. Tools Used

- Splunk Enterprise
- Search Processing Language (SPL)
- TryHackMe

## 3. Investigation Objectives

The main objectives of this project were to:

- Search and filter Windows event logs.
- Investigate successful Windows authentication events.
- Analyze process-related events and command-line activity.
- Examine source and destination IP addresses.
- Identify frequently occurring processes and event values.
- Enrich event data using IP geolocation and lookup tables.
- Detect unusual VPN login locations and login times using statistical analysis.

## 4. Windows Event Log Analysis

### 4.1. Searching Windows Logs

**Query:**

```spl
index=windowslogs
```

**Purpose:**

Retrieve events from the `windowslogs` index to understand the available data and identify relevant fields for further investigation.

**Analysis:**

The initial search provides an overview of the available Windows event data. Reviewing the total event count and available fields helps establish a starting point for the investigation.

**Security Relevance:**

Understanding the available log sources and fields is an important first step before investigating authentication activity, process execution, or potentially suspicious behavior.

### 4.2. Investigating Successful Logons

**Query:**

```spl
index=windowslogs EventID=4624
```

**Purpose:**

Filter Windows events to identify successful logon events.

**Analysis:**

Windows Security Event ID 4624 indicates that a logon session was successfully created.

The event can provide useful context about authentication activity, including account information and logon details, depending on the event fields available.

**Security Relevance:**

Successful logon events can help an analyst investigate account activity and correlate authentication events with other security records.

A successful logon is not inherently suspicious. Its significance depends on the account, time, source, and surrounding activity.

### 4.3. Filtering Events by Destination IP and Port

**Query:**

```spl
index=windowslogs DestinationIp=172.18.39.6 DestinationPort=135
```

**Purpose:**

Identify events matching a specific destination IP address and destination port.

**Analysis:**

The query narrows the search to events where `DestinationIp` equals `172.18.39.6` and `DestinationPort` equals `135`.

**Security Relevance:**

Filtering by network-related fields can help investigate communication patterns and identify events associated with a particular destination.

Port 135 is commonly associated with Microsoft RPC endpoint mapping. Its presence alone does not indicate malicious activity.

### 4.4. Investigating Host-Related Activity

**Query:**

```spl
index=windowslogs Hostname=Salena.Adam DestinationIp=172.18.38.5
```

**Purpose:**

Filter events using a specific hostname and destination IP address.

**Analysis:**

This query narrows the results to events matching both conditions. The resulting source IP values can then be examined to understand which sources appear most frequently in the filtered dataset.

**Security Relevance:**

Combining host and network fields helps an analyst focus on a specific subset of events instead of reviewing the entire dataset.

## 5. SPL Filtering and Data Organization

### 5.1. Selecting Relevant Fields

**Query:**

```spl
index=windowslogs
| fields Domain SourceProcessId TargetProcessId
```

**Purpose:**

Focus the results on domain and process identifier fields.

**Analysis:**

The `fields` command controls which fields are retained in the search results. This can make relevant information easier to review.

**Security Relevance:**

Process identifiers and domain information may help an analyst investigate process activity and correlate related events.

### 5.2. Filtering with Regular Expressions

**Query:**

```spl
index=windowslogs
| regex TargetObject="Manager$"
```

**Purpose:**

Filter events whose `TargetObject` value ends with the text `Manager`.

**Analysis:**

The `regex` command applies a regular expression to a field. The `$` character matches the end of a string.

**Security Relevance:**

Regular expressions allow analysts to search for specific naming patterns in event fields. The meaning of a matching value depends on the event type and surrounding context.

### 5.3. Building a Structured Event Table

**Query:**

```spl
index=windowslogs
| table EventID AccountName AccountType
```

**Purpose:**

Display selected event and account fields in a structured table.

**Analysis:**

The `table` command presents the specified fields, making it easier to compare account-related information across events.

**Security Relevance:**

Structured output helps analysts review relevant information and communicate findings clearly.

### 5.4. Reversing Result Order

**Query:**

```spl
index=windowslogs
| table EventID AccountName AccountType
| reverse
```

**Purpose:**

Reverse the order of the results returned by the preceding search pipeline.

**Analysis:**

The `reverse` command reverses the current result order. It does not independently guarantee chronological ordering.

**Security Relevance:**

Controlling result order can help when reviewing events, provided the analyst understands how the results were originally ordered.

## 6. Process Activity Analysis

### 6.1. Reviewing Process Creation Events

**Query:**

```spl
index=windowslogs EventID=1
| table _time ParentProcessId ProcessId ParentCommandLine CommandLine
| reverse
```

**Purpose:**

Review process-related events and examine their timestamps, process identifiers, parent process identifiers, and command-line information.

**Analysis:**

The selected fields can help an analyst understand how a process was launched and which parent process initiated it.

The meaning of Event ID 1 depends on the event source. In Sysmon, Event ID 1 represents process creation.

**Security Relevance:**

Process creation records can support investigations into suspicious command execution, unexpected parent-child process relationships, and unusual application behavior.

Command-line arguments should be reviewed in context rather than treated as evidence of malicious activity on their own.

## 7. Identifying Frequent Processes

### 7.1. Finding the Most Common Image Values

**Query:**

```spl
index=windowslogs
| top Image
```

**Purpose:**

Identify the most frequently occurring values in the `Image` field.

**Analysis:**

The `top` command returns the most common field values and their counts.

**Security Relevance:**

Frequency analysis can help establish which process image paths occur most often in the dataset. Less common processes may warrant review when supported by other suspicious indicators.

Frequency alone does not establish whether a process is benign or malicious.

## 8. IP Address Enrichment

### 8.1. Identifying Geographic Information

**Query:**

```spl
index=windowslogs
| iplocation SourceIp
```

**Purpose:**

Enrich events with available geographic information associated with the `SourceIp` field.

**Analysis:**

The `iplocation` command can add fields such as country, region, and city when geographic information is available for an IP address.

Private IP addresses generally cannot be mapped to a public geographic location using this method.

**Security Relevance:**

Geographic enrichment can provide context when investigating authentication or network activity. IP geolocation is approximate and does not prove the physical location of a user or device.

## 9. Risk-Based Process Analysis Using Lookup Data

### 9.1. Enriching Image Values with Risk Scores

**Query:**

```spl
index=windowslogs
| lookup image_riskscore Image OUTPUT RiskScore
| stats count by Image RiskScore
| sort - RiskScore
```

**Purpose:**

Enrich process image values with risk scores from a lookup table and summarize the resulting data.

**Analysis:**

- `lookup` retrieves matching risk information from the `image_riskscore` lookup table.
- `stats count by Image RiskScore` counts events for each image and risk-score combination.
- `sort - RiskScore` sorts the results in descending order of risk score.

**Security Relevance:**

Risk-based enrichment can help prioritize events for review. The usefulness of the result depends on the quality and meaning of the underlying lookup data.

A high risk score should be treated as an investigative lead rather than definitive proof of malicious activity.

## 10. VPN Authentication Anomaly Detection

### 10.1. Detecting Unusual Login Countries

**Query:**

```spl
index=vpnlogs
| eventstats count as logins_by_user by user
| eventstats count as logins_by_user_country by user src_country
| eval country_freq=logins_by_user_country/logins_by_user
| where country_freq < 0.1
| table _time user src_ip src_country country_freq
```

**Purpose:**

Identify VPN login events originating from countries that account for less than 10% of a user's recorded login events.

**Analysis:**

1. `eventstats count as logins_by_user by user` calculates the total number of login events for each user while retaining the individual events.
2. `eventstats count as logins_by_user_country by user src_country` calculates login counts for each user-country combination.
3. `eval country_freq=logins_by_user_country/logins_by_user` calculates the proportion of each user's login events associated with that country.
4. `where country_freq < 0.1` filters events where the calculated proportion is below 10%.
5. `table` displays the selected investigation fields.

**Security Relevance:**

A login from a country that rarely appears in a user's historical activity may warrant further investigation.

However, an unusual country alone does not prove account compromise. Legitimate travel, VPN routing, proxies, and geolocation inaccuracies may explain the observation.

### 10.2. Detecting Unusual Login Times

**Query:**

```spl
index=vpnlogs
| eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
| eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
| eval zscore=abs(hour - typical_hour) / stdev_hour
| where zscore > 3
| eval hour=round(hour, 2), typical_hour=round(typical_hour, 2)
| eval stdev_hour=round(stdev_hour, 2), zscore=round(zscore, 2)
| table _time user src_ip src_country hour typical_hour stdev_hour zscore
| sort - zscore
```

**Purpose:**

Identify login events whose recorded times differ substantially from each user's average login hour.

**Analysis:**

- `strftime` extracts the hour and minute from the event timestamp.
- `tonumber` converts the extracted values into numbers.
- `eval` converts the time into a decimal-hour representation.
- `eventstats avg(hour)` calculates the average login hour for each user.
- `eventstats stdev(hour)` calculates the standard deviation of login hours.
- `zscore` measures the absolute distance between an event's login hour and the user's average, expressed in standard deviations.
- `where zscore > 3` selects events whose calculated scores exceed three.
- `round` improves readability by rounding numeric values.
- `sort - zscore` sorts the results by descending z-score.

**Security Relevance:**

An unusually timed login may indicate activity that differs from a user's historical pattern. This can help analysts prioritize events for further review.

**Limitations:**

- The analysis depends on the quality and volume of historical data.
- The timestamp's timezone must be understood.
- Login times near midnight can require special handling because time is cyclical.
- A zero standard deviation can cause division-by-zero problems.
- Users may legitimately log in at unusual hours.

The threshold is a statistical indicator, not a definitive verdict on whether an event is malicious.

## 11. Key Findings

The training exercises included identifying unusual VPN login patterns associated with specific users and countries, as well as a login recorded at approximately 3 AM.

The lab questions identified the following values:

- An outlier user: `jsmith`
- An anomalous country: `JP`
- A user with a suspicious login time: `njackson`

These values reflect the answers recorded during the training exercises. They should be supported by actual Splunk results before being presented as independently verified findings.

Additional findings from the Windows log exercises can be documented here after confirming the exact query outputs.

## 12. Investigation Limitations

This project was conducted in a controlled training environment using provided datasets.

The analysis was limited to the available logs, fields, lookup data, and statistical methods.

Anomalies and risk scores were treated as indicators for further investigation rather than proof of compromise.

No claims are made about a real-world security incident or production environment.

## 13. Skills Practiced

- SPL search and filtering
- Windows event log analysis
- Authentication event investigation
- Process activity review
- IP address analysis and enrichment
- Statistical event aggregation
- Lookup-based data enrichment
- Behavioral anomaly detection
- Security finding documentation

## 14. Conclusion

This project provided hands-on practice with Splunk and SPL for investigating Windows event logs and VPN authentication records.

It reinforced the importance of combining log searches, field analysis, statistical methods, and contextual investigation to identify potentially suspicious behavior.

The exercises also highlighted that unusual events require validation and additional context before being classified as security incidents.


