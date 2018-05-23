#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-19-1-admin-templates-user-control-panel

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 19.1.3.1 (L1) Ensure 'Enable screen saver' is set to 'Enabled'
control '19.1.3.1' do
  impact 1.0
  title 'Ensure Enable screen saver is set to Enabled'
  desc 'Ensure Enable screen saver is set to Enabled'
  tag 'cis-level-1', 'cis-19.1.3.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop') do
    it { should exist }
    it { should have_property_value('ScreenSaveActive', :type_string, '1') }
  end
end

# 19.1.3.2 (L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'
control '19.1.3.2' do
  impact 1.0
  title 'Ensure Force specific screen saver: Screen saver executable name is set to Enabled: scrnsave.scr'
  desc 'Ensure Force specific screen saver: Screen saver executable name is set to Enabled: scrnsave.scr'
  tag 'cis-level-1', 'cis-19.1.3.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop') do
    it { should exist }
    it { should have_property_value('SCRNSAVE.EXE', :type_string, 'scrnsave.scr') }
  end
end

# 19.1.3.3 (L1) Ensure 'Password protect the screen saver' is set to 'Enabled'
control '19.1.3.3' do
  impact 1.0
  title 'Ensure Password protect the screen saver is set to Enabled'
  desc 'Ensure Password protect the screen saver is set to Enabled'
  tag 'cis-level-1', 'cis-19.1.3.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop') do
    it { should exist }
    it { should have_property_value('ScreenSaverIsSecure', :type_string, '1') }
  end
end

# 19.1.3.4 (L1)  Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
control '19.1.3.4' do
  impact 1.0
  title ' Ensure Screen saver timeout is set to Enabled: 900 seconds or fewer, but not 0'
  desc ' Ensure Screen saver timeout is set to Enabled: 900 seconds or fewer, but not 0'
  tag 'cis-level-1', 'cis-19.1.3.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop') do
    it { should exist }
    it { should have_property_value('ScreenSaveTimeOut', :type_string, '900') }
  end
end
