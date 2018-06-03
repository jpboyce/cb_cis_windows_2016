# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-7-interactive-logon
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 2.3.7.1 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'DontDisplayLastUserName', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.7.2 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'DisableCAD', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.7.3 (L1)  Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'InactivityTimeoutSecs', type: :dword, data: 900 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'LegalNoticeText', type: :string, data: 'This is a scary legal notice' }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'LegalNoticeCaption', type: :string, data: 'This is a heading for the scary notice' }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only)
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'CachedLogonsCount', type: :string, data: '4' }]
  action :create
  not_if { node['cb_cis_windows_2016']['is_domain_controller'] }
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'PasswordExpiryWarning', type: :dword, data: 10 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'ForceUnlockLogon', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'ScRemoveOption', type: :string, data: '1' }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end
