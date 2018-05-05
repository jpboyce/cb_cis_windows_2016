# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-1-account-logon
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
execute 'name' do
  command 'auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable'
  action :run
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
