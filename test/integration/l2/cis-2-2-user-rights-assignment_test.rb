#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-2-user-rights-assignment

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
control '2.2.1' do
  impact 1.0
  title 'Ensure Access Credential Manager as a trusted caller is set to No One'
  desc 'Ensure Access Credential Manager as a trusted caller is set to No One'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end

# 2.2.2 (L1) Configure 'Access this computer from the network'
# Member Server = Administrators, Authenticated Users
# Domain Controller = Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS
control '2.2.2' do
  impact 1.0
  title 'Configure Access this computer from the network'
  desc 'Configure Access this computer from the network'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  only_if { ENV['TEST_KITCHEN'].to_i == 0 }
  describe security_policy do
    its('SeNetworkLogonRight') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-32-555'] }
  end
end

# 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
control '2.2.3' do
  impact 1.0
  title 'Ensure Act as part of the operating system is set to No One'
  desc 'Ensure Act as part of the operating system is set to No One'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeTcbPrivilege') { should eq [] }
  end
end

# 2.2.4 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
# Administrators

# 2.2.5 (L1)  Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
# If IIS is installed, IIS App pools should be added
# If SQL Server is installed, then extra rights are required
control '2.2.5' do
  impact 1.0
  title ' Ensure Adjust memory quotas for a process is set to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc ' Ensure Adjust memory quotas for a process is set to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20'] }
  end
end

# 2.2.6 (L1) Configure 'Allow log on locally'
# Member Servers = Administrators
# Domain Controllers = Administrators, ENTERPRISE DOMAIN CONTROLLERS
control '2.2.6' do
  impact 1.0
  title 'Configure Allow log on locally'
  desc 'Configure Allow log on locally'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.7 (L1) Configure 'Allow log on through Remote Desktop Services'
# Member Server = Administrators, Remote Desktop Users
# Domain Controller = Administrators
# If Remote Desktop Connection Broker role is installed, then Authenticated Users too
control '2.2.7' do
  impact 1.0
  title 'Configure Allow log on through Remote Desktop Services'
  desc 'Configure Allow log on through Remote Desktop Services'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-32-555'] }
  end
end

# 2.2.8 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
control '2.2.8' do
  impact 1.0
  title 'Ensure Back up files and directories is set to Administrators'
  desc 'Ensure Back up files and directories is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeBackupPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.9 (L1)  Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
control '2.2.9' do
  impact 1.0
  title ' Ensure Change the system time is set to Administrators, LOCAL SERVICE'
  desc ' Ensure Change the system time is set to Administrators, LOCAL SERVICE'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeSystemtimePrivilege') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 2.2.10 (L1)  Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
control '2.2.10' do
  impact 1.0
  title ' Ensure Change the time zone is set to Administrators, LOCAL SERVICE'
  desc ' Ensure Change the time zone is set to Administrators, LOCAL SERVICE'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.10'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeTimeZonePrivilege') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-19'] }
  end
end

# 2.2.11 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
control '2.2.11' do
  impact 1.0
  title 'Ensure Create a pagefile is set to Administrators'
  desc 'Ensure Create a pagefile is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.11'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeCreatePagefilePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.12 (L1) Ensure 'Create a token object' is set to 'No One'
control '2.2.12' do
  impact 1.0
  title 'Ensure Create a token object is set to No One'
  desc 'Ensure Create a token object is set to No One'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.12'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq [] }
  end
end

# 2.2.13 (L1)  Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
# If running SQL Server AND Integration Services, need an exception
control '2.2.13' do
  impact 1.0
  title ' Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
  desc ' Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.13'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeCreateGlobalPrivilege') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
  end
end

# 2.2.14 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
control '2.2.14' do
  impact 1.0
  title 'Ensure Create permanent shared objects is set to No One'
  desc 'Ensure Create permanent shared objects is set to No One'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.14'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq [] }
  end
end

# 2.2.15 (L1) Configure 'Create symbolic links'
# Member Servers = Administrators
# Domain Controllers = Administrators
# If Hyper-V role is installed, add NT VIRTUAL MACHINE\Virtual Machines
control '2.2.15' do
  impact 1.0
  title 'Configure Create symbolic links'
  desc 'Configure Create symbolic links'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.15'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.16 (L1) Ensure 'Debug programs' is set to 'Administrators'
control '2.2.16' do
  impact 1.0
  title 'Ensure Debug programs is set to Administrators'
  desc 'Ensure Debug programs is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.16'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.17 (L1) Configure 'Deny access to this computer from the network'
# Member Server = Guests, Local account and member of Administrators group
# Domain Controller = Guests, Local account
# This item breaks Test Kitchen?
control '2.2.17' do
  impact 1.0
  title 'Configure Deny access to this computer from the network'
  desc 'Configure Deny access to this computer from the network'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.17'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  only_if { ENV['TEST_KITCHEN'].to_i == 0 }
  describe security_policy do
    its('SeDenyNetworkLogonRight') { is_expected.to match_array ['S-1-5-32-546', 'S-1-5-114'] }
  end
end

# 2.2.18 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
control '2.2.18' do
  impact 1.0
  title 'Ensure Deny log on as a batch job to include Guests'
  desc 'Ensure Deny log on as a batch job to include Guests'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.18'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeDenyBatchLogonRight') { should eq ['S-1-5-32-546'] }
  end
end

# 2.2.19 (L1) Ensure 'Deny log on as a service' to include 'Guests'
control '2.2.19' do
  impact 1.0
  title 'Ensure Deny log on as a service to include Guests'
  desc 'Ensure Deny log on as a service to include Guests'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.19'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeDenyServiceLogonRight') { should eq ['S-1-5-32-546'] }
  end
end

# 2.2.20 (L1) Ensure 'Deny log on locally' to include 'Guests'
control '2.2.20' do
  impact 1.0
  title 'Ensure Deny log on locally to include Guests'
  desc 'Ensure Deny log on locally to include Guests'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.20'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
  end
end

# 2.2.21 (L1)  Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'
control '2.2.21' do
  impact 1.0
  title ' Ensure Deny log on through Remote Desktop Services to include Guests, Local account'
  desc ' Ensure Deny log on through Remote Desktop Services to include Guests, Local account'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.21'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { is_expected.to match_array ['S-1-5-32-546', 'S-1-5-113'] }
  end
end

# 2.2.22 (L1) Configure 'Enable computer and user accounts to be trusted for delegation'
# Domain Controllers = Administrators
control '2.2.22' do
  impact 1.0
  title 'Configure Enable computer and user accounts to be trusted for delegation'
  desc 'Configure Enable computer and user accounts to be trusted for delegation'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.22'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq [] }
  end
end

# 2.2.23 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
control '2.2.23' do
  impact 1.0
  title 'Ensure Force shutdown from a remote system is set to Administrators'
  desc 'Ensure Force shutdown from a remote system is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.23'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.24 (L1)  Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
# If running IIS, need exception for App Pools
# If running ADFS, need exception for NT SERVICE\ADFSsrv and DRS services, and service account
control '2.2.24' do
  impact 1.0
  title ' Ensure Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE'
  desc ' Ensure Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.24'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeAuditPrivilege') { is_expected.to match_array ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 2.2.25 (L1) Configure 'Impersonate a client after authentication'
# Member server = Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
# Domain Controller = Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
# If running IIS, IIS_IUSRS too
# If running SQL Server AND Integration Services, need exception
control '2.2.25' do
  impact 1.0
  title 'Configure Impersonate a client after authentication'
  desc 'Configure Impersonate a client after authentication'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.25'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeImpersonatePrivilege') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
  end
end

# 2.2.26 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
control '2.2.26' do
  impact 1.0
  title 'Ensure Increase scheduling priority is set to Administrators'
  desc 'Ensure Increase scheduling priority is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.26'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.27 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
control '2.2.27' do
  impact 1.0
  title 'Ensure Load and unload device drivers is set to Administrators'
  desc 'Ensure Load and unload device drivers is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.27'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeLoadDriverPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.28 (L1) Ensure 'Lock pages in memory' is set to 'No One'
control '2.2.28' do
  impact 1.0
  title 'Ensure Lock pages in memory is set to No One'
  desc 'Ensure Lock pages in memory is set to No One'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.28'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end

# 2.2.29 (L2) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)
# Domain Controller = Administrators
control '2.2.29' do
  impact 1.0
  title '(L2) Ensure Log on as a batch job is set to Administrators (DC Only)'
  desc '(L2) Ensure Log on as a batch job is set to Administrators (DC Only)'
  tag cissection: '2-2'
  tag cislevel: '2'
  tag cisitem: 'cis-2.2.29'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  only_if { node['cb_cis_windows_2016']['is_domain_controller'] }
  describe security_policy do
    its('SeBatchLogonRight') { should eq [] }
  end
end

# 2.2.30 (L1) Configure 'Manage auditing and security log'
# Member Servers = Administrators
# Domain Controllers = Administrators (and Exchange Servers if Exchange is in the environment)
control '2.2.30' do
  impact 1.0
  title 'Configure Manage auditing and security log'
  desc 'Configure Manage auditing and security log'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.30'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeSecurityPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One'
control '2.2.31' do
  impact 1.0
  title 'Ensure Modify an object label is set to No One'
  desc 'Ensure Modify an object label is set to No One'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.31'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeRelabelPrivilege') { should eq [] }
  end
end

# 2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
control '2.2.32' do
  impact 1.0
  title 'Ensure Modify firmware environment values is set to Administrators'
  desc 'Ensure Modify firmware environment values is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.32'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
control '2.2.33' do
  impact 1.0
  title 'Ensure Perform volume maintenance tasks is set to Administrators'
  desc 'Ensure Perform volume maintenance tasks is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.33'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeManageVolumePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators'
control '2.2.34' do
  impact 1.0
  title 'Ensure Profile single process is set to Administrators'
  desc 'Ensure Profile single process is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.34'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.35 (L1)  Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
control '2.2.35' do
  impact 1.0
  title ' Ensure Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost'
  desc ' Ensure Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.35'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeSystemProfilePrivilege') { is_expected.to match_array ['S-1-5-32-544', 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'] }
  end
end

# 2.2.36 (L1)  Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
# If IIS is installed, need IIS app pols too
# If running SQL, need exception too
control '2.2.36' do
  impact 1.0
  title ' Ensure Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE'
  desc ' Ensure Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.36'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { is_expected.to match_array ['S-1-5-19', 'S-1-5-20'] }
  end
end

# 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
control '2.2.37' do
  impact 1.0
  title 'Ensure Restore files and directories is set to Administrators'
  desc 'Ensure Restore files and directories is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.37'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeRestorePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators'
control '2.2.38' do
  impact 1.0
  title 'Ensure Shut down the system is set to Administrators'
  desc 'Ensure Shut down the system is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.38'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

# 2.2.39 (L1) Ensure Synchronize directory service data is set to No One (DC only)
control '2.2.39' do
  impact 1.0
  title 'Ensure Synchronize directory service data is set to No One (DC only)'
  desc 'Ensure Synchronize directory service data is set to No One (DC only)'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.39'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeSyncAgentPrivilege') { should eq [] }
  end
end

# 2.2.40 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
control '2.2.40' do
  impact 1.0
  title 'Ensure Take ownership of files or other objects is set to Administrators'
  desc 'Ensure Take ownership of files or other objects is set to Administrators'
  tag cissection: '2-2'
  tag cislevel: '1'
  tag cisitem: 'cis-2.2.40'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should eq ['S-1-5-32-544'] }
    its('SeTakeOwnershipPrivilege') { is_expected.to match_array ['S-1-5-32-544'] }
  end
end
