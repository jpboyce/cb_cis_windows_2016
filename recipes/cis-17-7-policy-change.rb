# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-7-policy-change
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
