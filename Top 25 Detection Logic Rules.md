DETECTION 01: PASSWORD SPRAYING

OBJECTIVE:
Detect a single source attempting authentication against multiple distinct user accounts within a defined time period.

MITRE ATT&CK
* T1110.003 - Brute Force: Password Spraying
* T1078 - Valid Accounts - if a successful authentication follows the spray

DETECTION LOGIC

Failed authentication
    |
Grouped by source
    |
Multiple distinct destination users
    |
Within a defined time window
    |
Potential password spray

REQUIRED TELEMETRY
At minimum, the selected log source needs fields representing:

* Source IP or source asset
* Target/destination user
* Authentication result
* Timestamp

INVESTIGATION QUERY

QUERY 1 - BASIC IDENTIFICATION

where("result" ICONTAINS-ANY ["FAILED_BAD_PASSWORD", "FAILED_BAD_LOGIN"] AND "user") groupby(source_ip) calculate(UNIQUE:user)

This query groups any "Failed/Bad Passwords" or "Failed/Bad Logins" by the Source IP address, visualizing into a bar graph and 
ranked by the number of individual users attempted from this source IP.

QUERY 2 - TARGETED SOURCE INVESTIGATION

where(source_ip="SUSPICIOUS_IP" AND result ICONTAINS-ANY ["FAILED_BAD_PASSWORD", "FAILED_BAD_LOGIN"]) groupby(user) calculate(count)

This follow-up query replaced "SUSPICOUS_IP" with the IP from the previous query that is prompting investigation. The results will 
show the user and the number of attempts made from this specific IP address.

DETECTION #2 Brute Force Followed by Successful Authentication

OBJECTIVE:
Detect repeated failed authentication attepts against a user account followed by a successful authentication from the same source. This
detection is intended to identify potential credential compromise where an attacker repeatedly attempts authentication against a specific
account and subsequently authenticates successfully.

MITRE ATT&CK
* T1110.001 - Brute Force: Password Guessing
* T1078 - Valid Accounts - successful authentication using potentially compromised credentials

DETECTION LOGIC

Repeated failed authentication attempts
    |
Grouped by source and targeted user
    |
Multiple failed authentication attempts
    |
Successful authentication from same source
    |
Potential account compromise

REQUIRED TELEMETRY
* Source IP or source asset
* Target/destination user
* Authentication result
* Timestamp

Ideally, the log source also includes:
* Authentication servcie/appliction
* Destination host or system
* Authentication method
* Failure reason
* Geographic information
* Device or endpoint information

INVESTIGATION QUERY

QUERY 1 - BASIC INVESTIGATION

where("result" ICONTAINS-ANY ["FAILED_BAD_PASSWORD", "FAILED_BAD_LOGIN"] AND "user") groupby(source_ip, user) calculate(count)

QUERY 2 - TARGETED SOURCE AND USER INVESTIGATION

where(source_ip="SUSPICIOUS_IP" AND user="SUSPICIOUS_USER" AND result ICONTAINS-ANY ["FAILED_BAD_PASSWORD", "FAILED_BAD_LOGIN"]) groupby(result) calculate(count)

QUERY 3 - SEARCH FOR SUCCESSFUL AUTHENTICATON

where(source_ip="SUSPICIOUS_IP" AND user="SUSPICIOUS_USER") groupby(result) calculate(count)

DETECTION 03 - IMPOSSIBLE TRAVEL

OBJECTIVE:
Detect a user authenticating successfully from geographically distant locations within a time period that would make 
physical travel between those locations impossible.

MITRE ATT&CK:
* T1078 - Valid Accounts
* T1078.004 - Valid Accounts: Cloud Accounts

DETECTION LOGIC

Successful authentication
    |
Grouped by user
    |
Multiple geographic locations
    |
Short time interval between authentications
    |
Travel distance exceeds realistic travel capability
    |
Potential compromised account

REQUIRED TELEMETRY

At minimum, the selected log source needs fields representing:

* User/account
* Source IP
* Gepgraphic location or country
* Timestamp
* Authentication result

Ideally, the log source also should include:
* City/region
* Application/service
* Device information
* Authentication method
* VPN/proxy information
* Conditional Access result

INVESTIGATION QUERY

QUERY 1 - BASIC IDENTIFICATION

where("result" INCONTAINS-ANY ["SUCCESS", "SUCCESSFUL", "AUTHENTICATED"] AND "user") groupby(geoip_country_name)

Query revels any successful user login, listing the country the account authenticated from. This is not an automatic 
determination of Impossible Travel, as VPNs can cause issues with geographic policies.

QUERY 2 - TARGETED USER INVESTIGATION

where(user="SUSPICIOUS_USER" AND result ICONTAINS-ANY ["SUCCESS", "SUCCESSFUL", "AUTHENTICATED"]) groupby(geoip_country_name) calculate(count)

DETECTION #4 - NEW MFA METHOD ADDED

OBJECTIVE:
Detect when a new multi-factor authentication method is added to a user account, particularly when the account is already 
compromised or the change is made by an unauthoritzed user. An attacker who gains access to an account may add their own 
MFA method to maintain persistence and prevent the legitimate user from regaining control of the account.

MITRE ATT&CK
* T1098 - Account Manipulation
* T1098.005 - Account Manipulation: Device Registration
* T1078.004 - Valid Accounts: Cloud Accounts

DETECTION LOGIC

MFA method added or registered
    |
Grouped by user
    |
New authentication method or device
    |
Previously unseen MFA method
    |
Potnential account persistence or account takeover

REQUIRED TELEMETRY

Minimum Telemetry
* User/account
* MFA or authentication method
* Action/event type
* Event result
* Timestamp

Ideally, should include:
* Source IP
* Source geographic location
* Device information
* Device name
* MFA method type
* Application/service
* Authentication details

INVESTIGATION QUERY

QUERY 1 - BASIC IDENTIFATION



QUERY 2 - MFA METHOD AND USER INVESTIGATION

QUERY 3 - SOURCE INVESTIGATION
