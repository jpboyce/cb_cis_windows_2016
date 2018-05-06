# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-3-detailed-tracking
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to 'Success'
execute 'Plug and Play Events' do
  command 'auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable'
  action :run
end

# 17.3.2 (L1) Ensure 'Audit Process Creation' is set to 'Success'
execute 'Process Creation' do
  command 'auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable'
  action :run
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
