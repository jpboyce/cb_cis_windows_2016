# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-9-system
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
execute 'IPsec Driver' do
  command 'auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable'
  action :run
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
execute 'Other System Events' do
  command 'auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable'
  action :run
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
execute 'Security State Change' do
  command 'auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable'
  action :run
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
execute 'Security System Extension' do
  command 'auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable'
  action :run
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
execute 'System Integrity' do
  command 'auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable'
  action :run
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
