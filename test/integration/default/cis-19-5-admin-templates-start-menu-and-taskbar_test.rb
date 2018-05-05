# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-19-5-admin-templates-start-menu-and-taskbar

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 19.5.1.1 (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
control '19.5.1.1' do
  impact 1.0
  title 'Ensure Turn off toast notifications on the lock screen is set to Enabled'
  desc 'Ensure Turn off toast notifications on the lock screen is set to Enabled'
  tag 'cis-level-1', 'cis-19.5.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_USERS\[USER SID]\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    it { should exist }
    it { should have_property_value('NoToastApplicationNotificationOnLockScreen ', :type_dword, '1') }
  end
end
