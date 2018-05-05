#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-9-system
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] = true }
end
