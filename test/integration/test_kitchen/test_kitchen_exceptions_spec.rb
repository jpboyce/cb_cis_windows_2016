# Tests for exceptions under Test Kitchen
# 18.6.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to Disabled (CIS Value: Enabled)
control 'TKE-18.6.1' do
  impact 1.0
  title 'Test Kitchen Exception - Ensure Apply UAC restrictions to local accounts on network logons is set to Disabled (CIS Value: Enabled)'
  desc 'Test Kitchen Exception - Ensure Apply UAC restrictions to local accounts on network logons is set to Disabled (CIS Value: Enabled)'
  tag 'cis-level-1', 'cis-18.6.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('LocalAccountTokenFilterPolicy', :type_dword, 1) }
  end
end

# 18.9.86.2.2 (L2) Ensure Allow remote server management through WinRM is set to Enabled (CIS Value: Disabled)
control 'TKE-18.9.86.2.2' do
  impact 1.0
  title 'Test Kitchen Exception - (L2) Ensure Allow remote server management through WinRM is set to Enabled (CIS Value: Disabled)'
  desc 'Test Kitchen Exception - (L2) Ensure Allow remote server management through WinRM is set to Enabled (CIS Value: Disabled)'
  tag 'cis-level-2', 'cis-18.9.86.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') do
    it { should exist }
    it { should have_property_value('AllowAutoConfig', :type_dword, 1) }
  end
end

# 18.9.87.1 (L2) Ensure Allow Remote Shell Access is set to Enabled (CIS Value: Disabled)
control 'TKE-18.9.87.1' do
  impact 1.0
  title 'Test Kitchen Exception - (L2) Ensure Allow Remote Shell Access is set to Enabled (CIS Value: Disabled)'
  desc 'Test Kitchen Exception - (L2) Ensure Allow Remote Shell Access is set to Enabled (CIS Value: Disabled)'
  tag 'cis-level-2', 'cis-18.9.87.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS') do
    it { should exist }
    it { should have_property_value('AllowRemoteShellAccess', :type_dword, 0) }
  end
end
