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
  tag 'cis-level-1', 'cis-2.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.2 (L1) Configure 'Access this computer from the network'
control '2.2.2' do
  impact 1.0
  title 'Configure Access this computer from the network'
  desc 'Configure Access this computer from the network'
  tag 'cis-level-1', 'cis-2.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
control '2.2.3' do
  impact 1.0
  title 'Ensure Act as part of the operating system is set to No One'
  desc 'Ensure Act as part of the operating system is set to No One'
  tag 'cis-level-1', 'cis-2.2.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.5 (L1)  Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
control '2.2.5' do
  impact 1.0
  title ' Ensure Adjust memory quotas for a process is set to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc ' Ensure Adjust memory quotas for a process is set to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  tag 'cis-level-1', 'cis-2.2.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.6 (L1) Configure 'Allow log on locally'
control '2.2.6' do
  impact 1.0
  title 'Configure Allow log on locally'
  desc 'Configure Allow log on locally'
  tag 'cis-level-1', 'cis-2.2.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.7 (L1) Configure 'Allow log on through Remote Desktop Services'
control '2.2.7' do
  impact 1.0
  title 'Configure Allow log on through Remote Desktop Services'
  desc 'Configure Allow log on through Remote Desktop Services'
  tag 'cis-level-1', 'cis-2.2.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.8 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
control '2.2.8' do
  impact 1.0
  title 'Ensure Back up files and directories is set to Administrators'
  desc 'Ensure Back up files and directories is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.9 (L1)  Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
control '2.2.9' do
  impact 1.0
  title ' Ensure Change the system time is set to Administrators, LOCAL SERVICE'
  desc ' Ensure Change the system time is set to Administrators, LOCAL SERVICE'
  tag 'cis-level-1', 'cis-2.2.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.10 (L1)  Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
control '2.2.10' do
  impact 1.0
  title ' Ensure Change the time zone is set to Administrators, LOCAL SERVICE'
  desc ' Ensure Change the time zone is set to Administrators, LOCAL SERVICE'
  tag 'cis-level-1', 'cis-2.2.10'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.11 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
control '2.2.11' do
  impact 1.0
  title 'Ensure Create a pagefile is set to Administrators'
  desc 'Ensure Create a pagefile is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.11'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.12 (L1) Ensure 'Create a token object' is set to 'No One'
control '2.2.12' do
  impact 1.0
  title 'Ensure Create a token object is set to No One'
  desc 'Ensure Create a token object is set to No One'
  tag 'cis-level-1', 'cis-2.2.12'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.13 (L1)  Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
control '2.2.13' do
  impact 1.0
  title ' Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
  desc ' Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
  tag 'cis-level-1', 'cis-2.2.13'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.14 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
control '2.2.14' do
  impact 1.0
  title 'Ensure Create permanent shared objects is set to No One'
  desc 'Ensure Create permanent shared objects is set to No One'
  tag 'cis-level-1', 'cis-2.2.14'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.15 (L1) Configure 'Create symbolic links'
control '2.2.15' do
  impact 1.0
  title 'Configure Create symbolic links'
  desc 'Configure Create symbolic links'
  tag 'cis-level-1', 'cis-2.2.15'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.16 (L1) Ensure 'Debug programs' is set to 'Administrators'
control '2.2.16' do
  impact 1.0
  title 'Ensure Debug programs is set to Administrators'
  desc 'Ensure Debug programs is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.16'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.17 (L1) Configure 'Deny access to this computer from the network'
control '2.2.17' do
  impact 1.0
  title 'Configure Deny access to this computer from the network'
  desc 'Configure Deny access to this computer from the network'
  tag 'cis-level-1', 'cis-2.2.17'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.18 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
control '2.2.18' do
  impact 1.0
  title 'Ensure Deny log on as a batch job to include Guests'
  desc 'Ensure Deny log on as a batch job to include Guests'
  tag 'cis-level-1', 'cis-2.2.18'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.19 (L1) Ensure 'Deny log on as a service' to include 'Guests'
control '2.2.19' do
  impact 1.0
  title 'Ensure Deny log on as a service to include Guests'
  desc 'Ensure Deny log on as a service to include Guests'
  tag 'cis-level-1', 'cis-2.2.19'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.20 (L1) Ensure 'Deny log on locally' to include 'Guests'
control '2.2.20' do
  impact 1.0
  title 'Ensure Deny log on locally to include Guests'
  desc 'Ensure Deny log on locally to include Guests'
  tag 'cis-level-1', 'cis-2.2.20'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.21 (L1)  Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'
control '2.2.21' do
  impact 1.0
  title ' Ensure Deny log on through Remote Desktop Services to include Guests, Local account'
  desc ' Ensure Deny log on through Remote Desktop Services to include Guests, Local account'
  tag 'cis-level-1', 'cis-2.2.21'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.22 (L1) Configure 'Enable computer and user accounts to be trusted for delegation'
control '2.2.22' do
  impact 1.0
  title 'Configure Enable computer and user accounts to be trusted for delegation'
  desc 'Configure Enable computer and user accounts to be trusted for delegation'
  tag 'cis-level-1', 'cis-2.2.22'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.23 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
control '2.2.23' do
  impact 1.0
  title 'Ensure Force shutdown from a remote system is set to Administrators'
  desc 'Ensure Force shutdown from a remote system is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.23'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.24 (L1)  Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control '2.2.24' do
  impact 1.0
  title ' Ensure Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE'
  desc ' Ensure Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE'
  tag 'cis-level-1', 'cis-2.2.24'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.25 (L1) Configure 'Impersonate a client after authentication'
control '2.2.25' do
  impact 1.0
  title 'Configure Impersonate a client after authentication'
  desc 'Configure Impersonate a client after authentication'
  tag 'cis-level-1', 'cis-2.2.25'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.26 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
control '2.2.26' do
  impact 1.0
  title 'Ensure Increase scheduling priority is set to Administrators'
  desc 'Ensure Increase scheduling priority is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.26'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.27 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
control '2.2.27' do
  impact 1.0
  title 'Ensure Load and unload device drivers is set to Administrators'
  desc 'Ensure Load and unload device drivers is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.27'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.28 (L1) Ensure 'Lock pages in memory' is set to 'No One'
control '2.2.28' do
  impact 1.0
  title 'Ensure Lock pages in memory is set to No One'
  desc 'Ensure Lock pages in memory is set to No One'
  tag 'cis-level-1', 'cis-2.2.28'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.30 (L1) Configure 'Manage auditing and security log'
control '2.2.30' do
  impact 1.0
  title 'Configure Manage auditing and security log'
  desc 'Configure Manage auditing and security log'
  tag 'cis-level-1', 'cis-2.2.30'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One'
control '2.2.31' do
  impact 1.0
  title 'Ensure Modify an object label is set to No One'
  desc 'Ensure Modify an object label is set to No One'
  tag 'cis-level-1', 'cis-2.2.31'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
control '2.2.32' do
  impact 1.0
  title 'Ensure Modify firmware environment values is set to Administrators'
  desc 'Ensure Modify firmware environment values is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.32'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
control '2.2.33' do
  impact 1.0
  title 'Ensure Perform volume maintenance tasks is set to Administrators'
  desc 'Ensure Perform volume maintenance tasks is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.33'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators'
control '2.2.34' do
  impact 1.0
  title 'Ensure Profile single process is set to Administrators'
  desc 'Ensure Profile single process is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.34'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.35 (L1)  Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
control '2.2.35' do
  impact 1.0
  title ' Ensure Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost'
  desc ' Ensure Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost'
  tag 'cis-level-1', 'cis-2.2.35'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.36 (L1)  Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
control '2.2.36' do
  impact 1.0
  title ' Ensure Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE'
  desc ' Ensure Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE'
  tag 'cis-level-1', 'cis-2.2.36'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
control '2.2.37' do
  impact 1.0
  title 'Ensure Restore files and directories is set to Administrators'
  desc 'Ensure Restore files and directories is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.37'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators'
control '2.2.38' do
  impact 1.0
  title 'Ensure Shut down the system is set to Administrators'
  desc 'Ensure Shut down the system is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.38'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.2.40 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
control '2.2.40' do
  impact 1.0
  title 'Ensure Take ownership of files or other objects is set to Administrators'
  desc 'Ensure Take ownership of files or other objects is set to Administrators'
  tag 'cis-level-1', 'cis-2.2.40'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end
