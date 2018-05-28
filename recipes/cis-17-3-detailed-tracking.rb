# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-3-detailed-tracking
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to 'Success'
execute 'Plug and Play Events' do
  command 'auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Plug and Play Events\s*Success.*/m }
end

# 17.3.2 (L1) Ensure 'Audit Process Creation' is set to 'Success'
execute 'Process Creation' do
  command 'auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~ /^\s*Process Creation\s*Success.*/m }
end
