#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-2-account-management
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end
