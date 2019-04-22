# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-4-ds-access
#
# Copyright:: 2018, Jesse Boyce, All Rights Reserved.

# 17.4.1 (L1) Ensure 'Audit Directory Service Access' is set to 'Success and Failure' (DC only)
execute 'Directory Service Access' do
  command 'auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Directory Service Access\s*Success and Failure.*/m }
end

# 17.4.2 (L1) Ensure 'Audit Directory Service Changes' is set to 'Success and Failure' (DC only)
execute 'Directory Service Changes' do
  command 'auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Directory Service Changes\s*Success and Failure.*/m }
end
