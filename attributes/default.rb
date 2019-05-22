# Default Attributes

############################
# BEHAVIOUR CONTROL SETTINGS
############################
#
# These items will control how certain settings are applied in the cookbook

# CIS Level Controls
# Specify whether to execute level 1 or level 2 controls
default['cb_cis_windows_2016']['cis_level_1'] = true
default['cb_cis_windows_2016']['cis_level_2'] = false

# Server Roles
# Controls whether member server only or domain controller only settings are run
default['cb_cis_windows_2016']['is_member_server'] = false
default['cb_cis_windows_2016']['is_domain_controller'] = false

# MSS Templates
# Whether to copy MSS template files to node
default['cb_cis_windows_2016']['copy_mss'] = true

# Auditpol data
require 'mixlib/shellout'
auditpol_cmd = Mixlib::ShellOut.new('auditpol /get /category:*')
auditpol_cmd.run_command
default['cb_cis_windows_2016']['auditpol_data'] = auditpol_cmd.stdout

# Windows-Security-Policy/SecEdit values
default['security_policy']['template']['location'] = 'C:\Windows\security\templates'
default['security_policy']['database']['location'] = 'C:\Windows\security\database'
default['security_policy']['database']['name'] = 'cis.sdb'

# Windows-Security-Policy/SecEdit values
default['cb_cis_windows_2016']['secedit_template']['location'] = 'C:\Windows\security\templates'
default['cb_cis_windows_2016']['secedit_database']['location'] = 'C:\Windows\security\database'
default['cb_cis_windows_2016']['secedit_database']['name'] = 'cis.sdb'

# New names for Administrator and Guest
default['cb_cis_windows_2016']['new_name_administrator'] = 'TotallyNotAdmin'
default['cb_cis_windows_2016']['new_name_guest'] = 'TotallyNotGuest'

# Password Policy settings
# 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
default['security_policy']['access']['PasswordHistorySize'] = 24
# 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
default['security_policy']['access']['MaximumPasswordAge'] = 60
# 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
default['security_policy']['access']['MinimumPasswordAge'] = 1
# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
default['security_policy']['access']['MinimumPasswordLength'] = 14
# 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
default['security_policy']['access']['PasswordComplexity'] = 1
# 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
default['security_policy']['access']['ClearTextPassword'] = 0

# Account Lockout Policy Settings
# 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
default['security_policy']['access']['LockoutDuration'] = 15

# 1.2.2 (L1)  Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
default['security_policy']['access']['LockoutBadCount'] = 10

# 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
default['security_policy']['access']['ResetLockoutCount'] = 15

# User Rights Assignment

# 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
default['security_policy']['rights']['SeTrustedCredManAccessPrivilege'] = ''

# 2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'
# for DCs - Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS
default['security_policy']['rights']['SeNetworkLogonRight'] = if default['cb_cis_windows_2016']['is_domain_controller'] == true
                                                                '*S-1-5-32-544,*S-1-5-11,*S-1-5-9'
                                                              else
                                                                '*S-1-5-32-544,*S-1-5-11'
                                                              end

# if default['cb_cis_windows_2016']['is_domain_controller'] == true
# Chef::Log.warn('is_domain_controller is set to True.  Setting SeNetworkLogonRight to Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS')
#   default['security_policy']['rights']['SeNetworkLogonRight'] = '*S-1-5-32-544,*S-1-5-11,*S-1-5-9'
# else
# Chef::Log.warn('is_domain_controller is set to False.  Setting SeNetworkLogonRight to Administrators, Authenticated Users')
#  default['security_policy']['rights']['SeNetworkLogonRight'] = '*S-1-5-32-544,*S-1-5-11'
# end

# 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
default['security_policy']['rights']['SeTcbPrivilege'] = ''

# 2.2.4 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
if default['cb_cis_windows_2016']['is_domain_controller'] == true
  # Chef::Log.warn('is_domain_controller is set to True.  Setting SeMachineAccountPrivilege to Administrators')
  default['security_policy']['rights']['SeMachineAccountPrivilege'] = '*S-1-5-32-544'
end

# 2.2.5 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
default['security_policy']['rights']['SeIncreaseQuotaPrivilege'] = '*S-1-5-32-544,*S-1-5-19,*S-1-5-20'

# 2.2.6 (L1) Ensure 'Allow log on locally' is set to 'Administrators'
# default['security_policy']['rights']['SeInteractiveLogonRight'] = '*S-1-5-32-544,*S-1-5-32-545'
# for DCs Administrators, ENTERPRISE DOMAIN CONTROLLERS
if default['cb_cis_windows_2016']['is_domain_controller'] == true
  # Chef::Log.warn('is_domain_controller is set to True.  Setting SeInteractiveLogonRight to Administrators, ENTERPRISE DOMAIN CONTROLLERS')
  default['security_policy']['rights']['SeInteractiveLogonRight'] = '*S-1-5-32-544,S-1-5-9'
else
  # Chef::Log.warn('is_domain_controller is set to False.  Setting SeInteractiveLogonRight to Administrators')
  default['security_policy']['rights']['SeInteractiveLogonRight'] = '*S-1-5-32-544'
end

# 2.2.7 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
# default['security_policy']['rights']['SeRemoteInteractiveLogonRight'] = '*S-1-5-32-544,*S-1-5-32-555'
# for DCs, just administrators
if default['cb_cis_windows_2016']['is_domain_controller'] == true
  # Chef::Log.warn('is_domain_controller is set to True. Setting SeRemoteInteractiveLogonRight to Administrators')
  default['security_policy']['rights']['SeRemoteInteractiveLogonRight'] = '*S-1-5-32-544'
else
  # Chef::Log.warn('is_domain_controller is set to False. Setting SeRemoteInteractiveLogonRight to Administrators, Remote Desktop Users')
  default['security_policy']['rights']['SeRemoteInteractiveLogonRight'] = '*S-1-5-32-544,*S-1-5-32-555'
end

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
default['security_policy']['rights']['SeCreateSymbolicLinkPrivilege'] = '*S-1-5-32-544'

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
# For DCs, Administrators
if default['cb_cis_windows_2016']['is_domain_controller'] == true
  # Chef::Log.warn('is_domain_controller is set to True. Setting SeEnableDelegationPrivilege to Administrators')
  default['security_policy']['rights']['SeEnableDelegationPrivilege'] = '*S-1-5-32-544'
else
  # Chef::Log.warn('is_domain_controller is set to False. Setting SeEnableDelegationPrivilege to Noone')
  default['security_policy']['rights']['SeEnableDelegationPrivilege'] = ''
end

# 2.2.23 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
default['security_policy']['rights']['SeRemoteShutdownPrivilege'] = '*S-1-5-32-544'

# 2.2.24 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
default['security_policy']['rights']['SeAuditPrivilege'] = '*S-1-5-19,*S-1-5-20'

# 2.2.25 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
default['security_policy']['rights']['SeImpersonatePrivilege'] = '*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6'

# 2.2.26 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
default['security_policy']['rights']['SeIncreaseBasePriorityPrivilege'] = '*S-1-5-32-544'

# 2.2.27 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
default['security_policy']['rights']['SeLoadDriverPrivilege'] = '*S-1-5-32-544'

# 2.2.28 (L1) Ensure 'Lock pages in memory' is set to 'No One'
default['security_policy']['rights']['SeLockMemoryPrivilege'] = ''

# 2.2.29 (L2) Ensure 'Log on as a batch job' is set to 'Administrators'
# default['security_policy']['rights']['SeBatchLogonRight'] = '*S-1-5-32-544'
# DC only
if default['cb_cis_windows_2016']['is_domain_controller'] == true
  # Chef::Log.warn('is_domain_controller is set to True. Setting SeBatchLogonRight to Administrators')
  default['security_policy']['rights']['SeBatchLogonRight'] = '*S-1-5-32-544'
end

# 2.2.30 (L2) Ensure 'Log on as a service' is set to 'No One'
default['security_policy']['rights']['SeServiceLogonRight'] = ''

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

# 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators'
default['security_policy']['rights']['SeShutdownPrivilege'] = '*S-1-5-32-544'

# 2.2.39 (L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)
# DC only
if default['cb_cis_windows_2016']['is_domain_controller'] == true
  # Chef::Log.warn('is_domain_controller is set to True. Setting SeSyncAgentPrivilege to Noone')
  default['security_policy']['rights']['SeSyncAgentPrivilege'] = ''
end

# 2.2.40 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
default['security_policy']['rights']['SeTakeOwnershipPrivilege'] = '*S-1-5-32-544'

# 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
# default['security_policy']['access']['LSAAnonymousNameLookup'] = 0
