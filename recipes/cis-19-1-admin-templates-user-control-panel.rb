# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-19-1-admin-templates-user-control-panel
#
# Copyright:: 2018, Jesse Boyce, All Rights Reserved.

# 19.1.3.1 (L1) Ensure 'Enable screen saver' is set to 'Enabled'
registry_key 'HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' do
  values [{ name: 'ScreenSaveActive', type: :string, data: '1' }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 19.1.3.2 (L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'
registry_key 'HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' do
  values [{ name: 'SCRNSAVE.EXE', type: :string, data: 'scrnsave.scr' }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 19.1.3.3 (L1) Ensure 'Password protect the screen saver' is set to 'Enabled'
registry_key 'HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' do
  values [{ name: 'ScreenSaverIsSecure', type: :string, data: '1' }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 19.1.3.4 (L1)  Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
registry_key 'HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' do
  values [{ name: 'ScreenSaveTimeOut', type: :string, data: '900' }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end
