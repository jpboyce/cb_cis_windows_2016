# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-7-policy-change
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
execute 'Audit Policy Change' do
  command 'auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Audit Policy Change\s*Success and Failure.*/m }
end

# 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'
execute 'Authentication Policy Change' do
  command 'auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Authentication Policy Change\s*Success.*/m }
end

# 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
execute 'Authorization Policy Change' do
  command 'auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:disable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Authorization Policy Change\s*Success.*/m }
end
