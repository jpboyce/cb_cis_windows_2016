# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-19-6-admin-templates-system
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 19.6.5.1.1 (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
registry_key 'HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0' do
  values [{ name: 'NoImplicitFeedback', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
  recursive true
end
