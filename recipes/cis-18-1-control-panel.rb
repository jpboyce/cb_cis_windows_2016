#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-18-1-control-panel
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization' do
  values [{ name: 'NoLockScreenCamera ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization' do
  values [{ name: 'NoLockScreenSlideshow ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.1.2.1 (L1) Ensure 'Allow Input Personalization' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization' do
  values [{ name: 'AllowInputPersonalization ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end
