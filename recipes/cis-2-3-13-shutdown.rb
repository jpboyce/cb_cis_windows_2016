#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-13-shutdown
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'ShutdownWithoutLogon ', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
