# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-8-privilege-use
#
# Copyright:: 2018, Jesse Boyce, All Rights Reserved.

# 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
execute 'Sensitive Privilege Use' do
  command 'auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Sensitive Privilege Use\s*Success and Failure.*/m }
end
