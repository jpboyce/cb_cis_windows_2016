#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-19-5-admin-templates-start-menu-and-taskbar
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 19.5.1.1 (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
registry_key 'HKEY_USERS\[USER SID]\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' do
  values [{ name: 'NoToastApplicationNotificationOnLockScreen ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end
