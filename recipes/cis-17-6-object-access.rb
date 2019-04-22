# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-6-object-access
#
# Copyright:: 2018, Jesse Boyce, All Rights Reserved.

# 17.6.1 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
execute 'Removable Storage' do
  command 'auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Removable Storage\s*Success and Failure.*/m }
end
