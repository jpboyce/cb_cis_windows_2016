#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-9-3-public-profile

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
control '9.3.1' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Firewall state is set to On (recommended)'
  desc 'Ensure Windows Firewall: Public: Firewall state is set to On (recommended)'
  tag 'cis-level-1', 'cis-9.3.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    it { should exist }
    it { should have_property_value('EnableFirewall', :type_dword, 1) }
  end
end

# 9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
control '9.3.2' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Inbound connections is set to Block (default)'
  desc 'Ensure Windows Firewall: Public: Inbound connections is set to Block (default)'
  tag 'cis-level-1', 'cis-9.3.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    it { should exist }
    it { should have_property_value('DefaultInboundAction', :type_dword, 1) }
  end
end

# 9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
control '9.3.3' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Outbound connections is set to Allow (default)'
  desc 'Ensure Windows Firewall: Public: Outbound connections is set to Allow (default)'
  tag 'cis-level-1', 'cis-9.3.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    it { should exist }
    it { should have_property_value('DefaultOutboundAction', :type_dword, 1) }
  end
end

# 9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'
control '9.3.4' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Settings: Display a notification is set to Yes'
  desc 'Ensure Windows Firewall: Public: Settings: Display a notification is set to Yes'
  tag 'cis-level-1', 'cis-9.3.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    it { should exist }
    it { should have_property_value('DisableNotifications', :type_dword, 1) }
  end
end

# 9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
control '9.3.5' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Settings: Apply local firewall rules is set to No'
  desc 'Ensure Windows Firewall: Public: Settings: Apply local firewall rules is set to No'
  tag 'cis-level-1', 'cis-9.3.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    it { should exist }
    it { should have_property_value('AllowLocalPolicyMerge', :type_dword, 0) }
  end
end

# 9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
control '9.3.6' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Settings: Apply local connection security rules is set to No'
  desc 'Ensure Windows Firewall: Public: Settings: Apply local connection security rules is set to No'
  tag 'cis-level-1', 'cis-9.3.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    it { should exist }
    it { should have_property_value('AllowLocalIPsecPolicyMerge', :type_dword, 0) }
  end
end

# 9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
control '9.3.7' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Logging: Name is set to %SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
  desc 'Ensure Windows Firewall: Public: Logging: Name is set to %SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
  tag 'cis-level-1', 'cis-9.3.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogFilePath', :type_string, '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log') }
  end
end

# 9.3.8 (L1)  Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
control '9.3.8' do
  impact 1.0
  title ' Ensure Windows Firewall: Public: Logging: Size limit (KB) is set to 16,384 KB or greater'
  desc ' Ensure Windows Firewall: Public: Logging: Size limit (KB) is set to 16,384 KB or greater'
  tag 'cis-level-1', 'cis-9.3.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogFileSize', :type_dword, 16384) }
  end
end

# 9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
control '9.3.9' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Logging: Log dropped packets is set to Yes'
  desc 'Ensure Windows Firewall: Public: Logging: Log dropped packets is set to Yes'
  tag 'cis-level-1', 'cis-9.3.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogDroppedPackets', :type_dword, 1) }
  end
end

# 9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
control '9.3.10' do
  impact 1.0
  title 'Ensure Windows Firewall: Public: Logging: Log successful connections is set to Yes'
  desc 'Ensure Windows Firewall: Public: Logging: Log successful connections is set to Yes'
  tag 'cis-level-1', 'cis-9.3.10'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    it { should exist }
    it { should have_property_value('LogSuccessfulConnections', :type_dword, 1) }
  end
end
