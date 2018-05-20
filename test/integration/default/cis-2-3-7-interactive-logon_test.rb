#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-7-interactive-logon

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.7.1 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
control '2.3.7.1' do
  impact 1.0
  title 'Ensure Interactive logon: Do not display last user name is set to Enabled'
  desc 'Ensure Interactive logon: Do not display last user name is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.7.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('DontDisplayLastUserName', :type_dword, '1') }
  end
end

# 2.3.7.2 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
control '2.3.7.2' do
  impact 1.0
  title 'Ensure Interactive logon: Do not require CTRL+ALT+DEL is set to Disabled'
  desc 'Ensure Interactive logon: Do not require CTRL+ALT+DEL is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.7.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('DisableCAD', :type_dword, '0') }
  end
end

# 2.3.7.3 (L1)  Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
control '2.3.7.3' do
  impact 1.0
  title ' Ensure Interactive logon: Machine inactivity limit is set to 900 or fewer second(s), but not 0'
  desc ' Ensure Interactive logon: Machine inactivity limit is set to 900 or fewer second(s), but not 0'
  tag 'cis-level-1', 'cis-2.3.7.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('InactivityTimeoutSecs', :type_dword, 900) }
  end
end

# 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'
control '2.3.7.4' do
  impact 1.0
  title 'Configure Interactive logon: Message text for users attempting to log on'
  desc 'Configure Interactive logon: Message text for users attempting to log on'
  tag 'cis-level-1', 'cis-2.3.7.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('LegalNoticeText', :type_string, 'Legal Notice Text') }
  end
end

# 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
control '2.3.7.5' do
  impact 1.0
  title 'Configure Interactive logon: Message title for users attempting to log on'
  desc 'Configure Interactive logon: Message title for users attempting to log on'
  tag 'cis-level-1', 'cis-2.3.7.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('LegalNoticeCaption', :type_string, 'Legal Notice Caption') }
  end
end

# 2.3.7.6 (L2) Ensure Interactive logon: Number of previous logons to cache (in case domain controller is not available) is set to 4 or fewer logon(s) (MS only)
control '2.3.7.6' do
  impact 1.0
  title 'Ensure Interactive logon: Number of previous logons to cache (in case domain controller is not available) is set to 4 or fewer logon(s)'
  desc 'Ensure Interactive logon: Number of previous logons to cache (in case domain controller is not available) is set to 4 or fewer logon(s)'
  tag 'cis-level-2', 'cis-2.3.7.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    it { should have_property_value('CachedLogonsCount', :type_string, '4') }
  end
end

# 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
control '2.3.7.7' do
  impact 1.0
  title 'Ensure Interactive logon: Prompt user to change password before expiration is set to between 5 and 14 days'
  desc 'Ensure Interactive logon: Prompt user to change password before expiration is set to between 5 and 14 days'
  tag 'cis-level-1', 'cis-2.3.7.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    it { should have_property_value('PasswordExpiryWarning', :type_dword, 14) }
  end
end

# 2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
control '2.3.7.8' do
  impact 1.0
  title 'Ensure Interactive logon: Require Domain Controller Authentication to unlock workstation is set to Enabled (MS only)'
  desc 'Ensure Interactive logon: Require Domain Controller Authentication to unlock workstation is set to Enabled (MS only)'
  tag 'cis-level-1', 'cis-2.3.7.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    it { should have_property_value('ForceUnlockLogon', :type_dword, 0) }
  end
end

# 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
control '2.3.7.9' do
  impact 1.0
  title 'Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher'
  desc 'Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher'
  tag 'cis-level-1', 'cis-2.3.7.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    it { should have_property_value('ScRemoveOption', :type_string, '1') }
  end
end
