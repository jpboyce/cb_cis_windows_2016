#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-18-6-scm-pass-the-hash-mitigations
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 18.6.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'LocalAccountTokenFilterPolicy ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.6.2 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' do
  values [{ name: 'UseLogonCredential ', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end
