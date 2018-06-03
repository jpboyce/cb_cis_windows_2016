# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-6-domain-member
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'RequireSignOrSeal', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['is_domain_controller'] }
end

# 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'SealSecureChannel', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['is_domain_controller'] }
end

# 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'SignSecureChannel', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['is_domain_controller'] }
end

# 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'DisablePasswordChange', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['is_domain_controller'] }
end

# 2.3.6.5 (L1)  Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'MaximumPasswordAge', type: :dword, data: 30 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['is_domain_controller'] }
end

# 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'RequireStrongKey', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
  not_if { node['cb_cis_windows_2016']['is_domain_controller'] }
end
