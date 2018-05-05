#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-19-7-admin-templates-windows-components
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 19.7.4.1 (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
registry_key 'HKEY_USERS\[USER SID]\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' do
  values [{ name: 'SaveZoneInformation ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
registry_key 'HKEY_USERS\[USER SID]\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' do
  values [{ name: 'ScanWithAntiVirus ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 19.7.7.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
registry_key 'HKEY_USERS\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent' do
  values [{ name: 'DisableThirdPartySuggestions ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 19.7.26.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
registry_key 'HKEY_USERS\[USER SID]\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{ name: 'NoInplaceSharing ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 19.7.39.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'
registry_key 'HKEY_USERS\[USER SID]\SOFTWARE\Policies\Microsoft\Windows\Installer' do
  values [{ name: 'AlwaysInstallElevated ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end
