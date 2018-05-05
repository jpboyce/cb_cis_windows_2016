#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-5-logon-logoff
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.5.2 (L1) Ensure 'Audit Group Membership' is set to 'Success'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end
