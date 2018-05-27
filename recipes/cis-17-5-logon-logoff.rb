# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-17-5-logon-logoff
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
execute 'Account Lockout' do
  command 'auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~  /^\s*Account Lockout\s*Success and Failure.*/m }
end

# 17.5.2 (L1) Ensure 'Audit Group Membership' is set to 'Success'
execute 'Group Membership' do
  command 'auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~  /^\s*Group Membership\s*Success.*/m }
end

# 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
execute 'Logoff' do
  command 'auditpol /set /subcategory:"Logoff" /success:enable /failure:disable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~  /^\s*Logoff\s*Success.*/m }
end

# 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
execute 'Logon' do
  command 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~  /^\s*Logon\s*Success and Failure.*/m }
end

# 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
execute 'Other Logon/Logoff Events' do
  command 'auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~  /^\s*Other Logon\/Logoff Events\s*Success and Failure.*/m }
end

# 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
execute 'Special Logon' do
  command 'auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable'
  action :run
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['auditpol_data'] =~  /^\s*Special Logon\s*Success.*/m }
end
