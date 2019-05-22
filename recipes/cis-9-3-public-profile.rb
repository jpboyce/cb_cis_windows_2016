# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-9-3-public-profile
#
# Copyright:: 2018, Jesse Boyce, All Rights Reserved.

# 9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' do
  if ENV['TEST_KITCHEN']
    values [{ name: 'EnableFirewall', type: :dword, data: 0 }]
  else
    values [{ name: 'EnableFirewall', type: :dword, data: 1 }]
  end
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' do
  values [{ name: 'DefaultInboundAction', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' do
  values [{ name: 'DefaultOutboundAction', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' do
  values [{ name: 'DisableNotifications', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' do
  values [{ name: 'AllowLocalPolicyMerge', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' do
  values [{ name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' do
  values [{ name: 'LogFilePath', type: :string, data: '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log' }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.8 (L1)  Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' do
  values [{ name: 'LogFileSize', type: :dword, data: 16384 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' do
  values [{ name: 'LogDroppedPackets', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' do
  values [{ name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# powershell_script 'Firewall Domain Profile Settings' do
#   code <<-EOH
#   $params = @{
#     'Name'='Public';
#     'Enabled'='True';
#     'DefaultInboundAction'='Block';
#     'DefaultOutboundAction'='Allow';
#     'AllowLocalFirewallRules'='False';
#     'AllowLocalIPsecRules'='False';
#     'NotifyOnListen'='True';
#     'LogFileName'='%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log';
#     'LogMaxSizeKilobytes'='16384';
#     'LogAllowed'='True';
#     'LogBlocked'='True';
#     'PolicyStore'="$env:COMPUTERNAME"
#   }

#   Set-NetFirewallProfile @params -Verbose
#   EOH
# end
