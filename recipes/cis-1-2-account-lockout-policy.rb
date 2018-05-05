# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-1-2-account-lockout-policy
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 1.2.2 (L1)  Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
