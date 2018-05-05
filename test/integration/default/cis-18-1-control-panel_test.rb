# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-18-1-control-panel

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
control '18.1.1.1' do
  impact 1.0
  title 'Ensure Prevent enabling lock screen camera is set to Enabled'
  desc 'Ensure Prevent enabling lock screen camera is set to Enabled'
  tag 'cis-level-1', 'cis-18.1.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
    it { should exist }
    it { should have_property_value('NoLockScreenCamera ', :type_dword, '1') }
  end
end

# 18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
control '18.1.1.2' do
  impact 1.0
  title 'Ensure Prevent enabling lock screen slide show is set to Enabled'
  desc 'Ensure Prevent enabling lock screen slide show is set to Enabled'
  tag 'cis-level-1', 'cis-18.1.1.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
    it { should exist }
    it { should have_property_value('NoLockScreenSlideshow ', :type_dword, '1') }
  end
end

# 18.1.2.1 (L1) Ensure 'Allow Input Personalization' is set to 'Disabled'
control '18.1.2.1' do
  impact 1.0
  title 'Ensure Allow Input Personalization is set to Disabled'
  desc 'Ensure Allow Input Personalization is set to Disabled'
  tag 'cis-level-1', 'cis-18.1.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization') do
    it { should exist }
    it { should have_property_value('AllowInputPersonalization ', :type_dword, '1') }
  end
end
