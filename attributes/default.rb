# Default Attributes

# CIS Levels
default['cb_cis_windows_2016']['cis_level_1'] = 'false'
default['cb_cis_windows_2016']['cis_level_2'] = 'true'

# Server Roles
default['cb_cis_windows_2016']['is_member_server'] = 'true'
default['cb_cis_windows_2016']['is_domain_controller'] = 'false'

# SecEdit values
default['cb_cis_windows_2016']['secedit_template']['location'] = 'C:\Windows\security\templates'
default['cb_cis_windows_2016']['secedit_database']['location'] = 'C:\Windows\security\database'
default['cb_cis_windows_2016']['secedit_database']['name'] = 'cis.sdb'

# Password Policy settings
# 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
default['cb_cis_windows_2016']['password_policy']['PasswordHistorySize'] = 24
# 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
default['cb_cis_windows_2016']['password_policy']['MaximumPasswordAge'] = 60
# 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
default['cb_cis_windows_2016']['password_policy']['MinimumPasswordAge'] = 1
# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
default['cb_cis_windows_2016']['password_policy']['MinimumPasswordLength'] = 15
# 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
default['cb_cis_windows_2016']['password_policy']['PasswordComplexity'] = 1
# 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
default['cb_cis_windows_2016']['password_policy']['ClearTextPassword'] = 0

# User Rights Assignment

# 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
default['security_policy']['rights']['SeTrustedCredManAccessPrivilege'] = ''

# 2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'
# for DCs - Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS
# default['security_policy']['rights']['SeNetworkLogonRight'] = '*S-1-5-32-544,*S-1-5-32-555'

# 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
default['security_policy']['rights']['SeTcbPrivilege'] = ''

# 2.2.4 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
# default['security_policy']['rights']['?'] = '?'

# 2.2.5 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
default['security_policy']['rights']['SeIncreaseQuotaPrivilege'] = '*S-1-5-32-544,*S-1-5-19,*S-1-5-20'

# 2.2.6 (L1) Ensure 'Allow log on locally' is set to 'Administrators'
# default['security_policy']['rights']['SeInteractiveLogonRight'] = '*S-1-5-32-544,*S-1-5-32-545'
# for DCs Administrators, ENTERPRISE DOMAIN CONTROLLERS

# 2.2.7 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
# default['security_policy']['rights']['SeRemoteInteractiveLogonRight'] = '*S-1-5-32-544,*S-1-5-32-555'
# for DCs, just administrators

# 2.2.8 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
default['security_policy']['rights']['SeBackupPrivilege'] = '*S-1-5-32-544'

# 2.2.9 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
default['security_policy']['rights']['SeSystemTimePrivilege'] = '*S-1-5-32-544,*S-1-5-19'

# 2.2.10 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
default['security_policy']['rights']['SeTimeZonePrivilege'] = '*S-1-5-32-544,*S-1-5-19'

# 2.2.11 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
default['security_policy']['rights']['SeCreatePagefilePrivilege'] = '*S-1-5-32-544'

# 2.2.12 (L1) Ensure 'Create a token object' is set to 'No One'
default['security_policy']['rights']['SeCreateTokenPrivilege'] = ''

# 2.2.13(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
default['security_policy']['rights']['SeCreateGlobalPrivilege'] = '*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6'

# 2.2.14 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
default['security_policy']['rights']['SeCreatePermanentPrivilege'] = ''

# 2.2.15 (L1) Configure 'Create symbolic links'
# default['security_policy']['rights']['SeCreateSymbolicLinkPrivilege'] = '*S-1-5-32-544'
# For DCs, Administrators

# 2.2.16 (L1) Ensure 'Debug programs' is set to 'Administrators'
default['security_policy']['rights']['SeDebugPrivilege'] = '*S-1-5-32-544'

# 2.2.17 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'
# default['security_policy']['rights']['SeDenyNetworkLogonRight'] = '*S-1-5-32-546,*S-1-5-113'
# Editing this from the default value to allow chef to work by removing local accounts
# default['security_policy']['rights']['SeDenyNetworkLogonRight'] = '*S-1-5-32-546'
# For member servers, Guests, Local account and member of Administrators group
# For DCs, Guests, Local account

# 2.2.18 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
default['security_policy']['rights']['SeDenyBatchLogonRight'] = '*S-1-5-32-546'

# 2.2.19 (L1) Ensure 'Deny log on as a service' to include 'Guests'
default['security_policy']['rights']['SeDenyServiceLogonRight'] = '*S-1-5-32-546'

# 2.2.20 (L1) Ensure 'Deny log on locally' to include 'Guests'
default['security_policy']['rights']['SeDenyInteractiveLogonRight'] = '*S-1-5-32-546'

# 2.2.21 (L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'
default['security_policy']['rights']['SeDenyRemoteInteractiveLogonRight'] = '*S-1-5-32-546,*S-1-5-113'

# 2.2.22 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
# default['security_policy']['rights']['SeEnableDelegationPrivilege'] = ''
# For DCs, Administrators

# 2.2.23 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
default['security_policy']['rights']['SeRemoteShutdownPrivilege'] = '*S-1-5-32-544'

# 2.2.24 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
default['security_policy']['rights']['SeAuditPrivilege'] = '*S-1-5-19,*S-1-5-20'

# 2.2.25 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
# default['security_policy']['rights']['SeImpersonatePrivilege'] = '*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6'
# DC - Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
# Member server - Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE

# 2.2.26 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
default['security_policy']['rights']['SeIncreaseBasePriorityPrivilege'] = '*S-1-5-32-544'

# 2.2.27 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
default['security_policy']['rights']['SeLoadDriverPrivilege'] = '*S-1-5-32-544'

# 2.2.28 (L1) Ensure 'Lock pages in memory' is set to 'No One'
default['security_policy']['rights']['SeLockMemoryPrivilege'] = ''

# 2.2.29 (L2) Ensure 'Log on as a batch job' is set to 'Administrators'
# default['security_policy']['rights']['SeBatchLogonRight'] = '*S-1-5-32-544'
# DC only

# 2.2.30 (L2) Ensure 'Log on as a service' is set to 'No One'
# default['security_policy']['rights']['SeServiceLogonRight'] = ''
# Not listed?

# 2.2.30 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'
default['security_policy']['rights']['SeSecurityPrivilege'] = '*S-1-5-32-544'

# 2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One'
default['security_policy']['rights']['SeRelabelPrivilege'] = ''

# 2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
default['security_policy']['rights']['SeSystemEnvironmentPrivilege'] = '*S-1-5-32-544'

# 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
default['security_policy']['rights']['SeManageVolumePrivilege'] = '*S-1-5-32-544'

# 2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators'
default['security_policy']['rights']['SeProfileSingleProcessPrivilege'] = '*S-1-5-32-544'

# 2.2.35 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
default['security_policy']['rights']['SeSystemProfilePrivilege'] = '*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'

# 2.2.36 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
default['security_policy']['rights']['SeAssignPrimaryTokenPrivilege'] = '*S-1-5-19,*S-1-5-20'

# 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
default['security_policy']['rights']['SeRestorePrivilege'] = '*S-1-5-32-544'

# 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators, Users'
default['security_policy']['rights']['SeShutdownPrivilege'] = '*S-1-5-32-544,*S-1-5-32-545'

# 2.2.39 (L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)
# DC only

# 2.2.40 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
default['security_policy']['rights']['SeTakeOwnershipPrivilege'] = '*S-1-5-32-544'

# 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
default['security_policy']['access']['LSAAnonymousNameLookup'] = 0
