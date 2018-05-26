#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-9-1-domain-profile

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
control '9.1.1' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Firewall state is set to On (recommended)'
  desc 'Ensure Windows Firewall: Domain: Firewall state is set to On (recommended)'
  tag 'cis-level-1', 'cis-9.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    it { should exist }
    it { should have_property_value('EnableFirewall', :type_dword, 1) }
  end
end

# 9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
control '9.1.2' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Inbound connections is set to Block (default)'
  desc 'Ensure Windows Firewall: Domain: Inbound connections is set to Block (default)'
  tag 'cis-level-1', 'cis-9.1.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    it { should exist }
    it { should have_property_value('DefaultInboundAction', :type_dword, 1) }
  end
end

# 9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
control '9.1.3' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Outbound connections is set to Allow (default)'
  desc 'Ensure Windows Firewall: Domain: Outbound connections is set to Allow (default)'
  tag 'cis-level-1', 'cis-9.1.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    it { should exist }
    it { should have_property_value('DefaultOutboundAction', :type_dword, 0) }
  end
end

# 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
control '9.1.4' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Settings: Display a notification is set to No'
  desc 'Ensure Windows Firewall: Domain: Settings: Display a notification is set to No'
  tag 'cis-level-1', 'cis-9.1.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    it { should exist }
    it { should have_property_value('DisableNotifications', :type_dword, 1) }
  end
end

# 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
control '9.1.5' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Settings: Apply local firewall rules is set to Yes (default)'
  desc 'Ensure Windows Firewall: Domain: Settings: Apply local firewall rules is set to Yes (default)'
  tag 'cis-level-1', 'cis-9.1.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    it { should exist }
    it { should have_property_value('AllowLocalPolicyMerge', :type_dword, 1) }
  end
end

# 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
control '9.1.6' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Settings: Apply local connection security rules is set to Yes (default)'
  desc 'Ensure Windows Firewall: Domain: Settings: Apply local connection security rules is set to Yes (default)'
  tag 'cis-level-1', 'cis-9.1.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    it { should exist }
    it { should have_property_value('AllowLocalIPsecPolicyMerge', :type_dword, 1) }
  end
end

# 9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
control '9.1.7' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Logging: Name is set to %SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
  desc 'Ensure Windows Firewall: Domain: Logging: Name is set to %SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
  tag 'cis-level-1', 'cis-9.1.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogFilePath', :type_string, '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log') }
  end
end

# 9.1.8 (L1)  Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
control '9.1.8' do
  impact 1.0
  title ' Ensure Windows Firewall: Domain: Logging: Size limit (KB) is set to 16,384 KB or greater'
  desc ' Ensure Windows Firewall: Domain: Logging: Size limit (KB) is set to 16,384 KB or greater'
  tag 'cis-level-1', 'cis-9.1.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogFileSize', :type_dword, 32767) }
  end
end

# 9.1.9 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
control '9.1.9' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Logging: Log dropped packets is set to Yes'
  desc 'Ensure Windows Firewall: Domain: Logging: Log dropped packets is set to Yes'
  tag 'cis-level-1', 'cis-9.1.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogDroppedPackets', :type_dword, 1) }
  end
end

# 9.1.10 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
control '9.1.10' do
  impact 1.0
  title 'Ensure Windows Firewall: Domain: Logging: Log successful connections is set to Yes'
  desc 'Ensure Windows Firewall: Domain: Logging: Log successful connections is set to Yes'
  tag 'cis-level-1', 'cis-9.1.10'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogSuccessfulConnections', :type_dword, 1) }
  end
end
