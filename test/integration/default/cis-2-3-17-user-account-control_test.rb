#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-17-user-account-control

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
control '2.3.17.1' do
  impact 1.0
  title 'Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled'
  desc 'Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.17.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('FilterAdministratorToken ', :type_dword, '1') }
  end
end

# 2.3.17.2 (L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
control '2.3.17.2' do
  impact 1.0
  title 'Ensure User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop is set to Disabled'
  desc 'Ensure User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.17.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('EnableUIADesktopToggle ', :type_dword, '1') }
  end
end

# 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
control '2.3.17.3' do
  impact 1.0
  title 'Ensure User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop'
  desc 'Ensure User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop'
  tag 'cis-level-1', 'cis-2.3.17.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('ConsentPromptBehaviorAdmin ', :type_dword, '1') }
  end
end

# 2.3.17.4 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
control '2.3.17.4' do
  impact 1.0
  title 'Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests'
  desc 'Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests'
  tag 'cis-level-1', 'cis-2.3.17.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('ConsentPromptBehaviorUser ', :type_dword, '1') }
  end
end

# 2.3.17.5 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
control '2.3.17.5' do
  impact 1.0
  title 'Ensure User Account Control: Detect application installations and prompt for elevation is set to Enabled'
  desc 'Ensure User Account Control: Detect application installations and prompt for elevation is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.17.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('EnableInstallerDetection ', :type_dword, '1') }
  end
end

# 2.3.17.6 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
control '2.3.17.6' do
  impact 1.0
  title 'Ensure User Account Control: Only elevate UIAccess applications that are installed in secure locations is set to Enabled'
  desc 'Ensure User Account Control: Only elevate UIAccess applications that are installed in secure locations is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.17.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('EnableSecureUIAPaths ', :type_dword, '1') }
  end
end

# 2.3.17.7 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
control '2.3.17.7' do
  impact 1.0
  title 'Ensure User Account Control: Run all administrators in Admin Approval Mode is set to Enabled'
  desc 'Ensure User Account Control: Run all administrators in Admin Approval Mode is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.17.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('EnableLUA ', :type_dword, '1') }
  end
end

# 2.3.17.8 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
control '2.3.17.8' do
  impact 1.0
  title 'Ensure User Account Control: Switch to the secure desktop when prompting for elevation is set to Enabled'
  desc 'Ensure User Account Control: Switch to the secure desktop when prompting for elevation is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.17.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('PromptOnSecureDesktop ', :type_dword, '1') }
  end
end

# 2.3.17.9 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
control '2.3.17.9' do
  impact 1.0
  title 'Ensure User Account Control: Virtualize file and registry write failures to per-user locations is set to Enabled'
  desc 'Ensure User Account Control: Virtualize file and registry write failures to per-user locations is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.17.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('EnableVirtualization ', :type_dword, '1') }
  end
end
