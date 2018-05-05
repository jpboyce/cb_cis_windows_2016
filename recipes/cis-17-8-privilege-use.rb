#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-8-privilege-use
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end