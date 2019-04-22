# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-2-account-management
#
# Copyright:: 2018, Jesse Boyce, All Rights Reserved.

# 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
execute 'Application Group Management' do
  command 'auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Application Group Management\s*Success and Failure.*/m }
end

# 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
execute 'Computer Account Management' do
  command 'auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Computer Account Management\s*Success and Failure.*/m }
end

# 17.2.3 (L1) Ensure 'Audit Distribution Group Management' is set to 'Success and Failure' (DC only)
execute 'Distribution Group Management' do
  command 'auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Distribution Group Management\s*Success and Failure.*/m }
end

# 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
execute 'Other Account Management Events' do
  command 'auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Other Account Management Events\s*Success and Failure.*/m }
end

# 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'
execute 'Security Group Management' do
  command 'auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Security Group Management\s*Success and Failure.*/m }
end

# 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
execute 'User Account Management' do
  command 'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*User Account Management\s*Success and Failure.*/m }
end
