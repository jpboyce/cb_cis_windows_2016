#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-1-1-password-policy
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 1.1.2 (L1)  Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
