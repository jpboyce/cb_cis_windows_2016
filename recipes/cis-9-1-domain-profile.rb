# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-9-1-domain-profile
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' do
  if ENV['TEST_KITCHEN']
    values [{ name: 'EnableFirewall', type: :dword, data: 0 }]
  else
    values [{ name: 'EnableFirewall', type: :dword, data: 1 }]
  end
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' do
  values [{ name: 'DefaultInboundAction', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' do
  values [{ name: 'DefaultOutboundAction', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' do
  values [{ name: 'DisableNotifications', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' do
  values [{ name: 'AllowLocalPolicyMerge', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' do
  values [{ name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' do
  values [{ name: 'LogFilePath', type: :string, data: '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log' }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.8 (L1)  Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' do
  values [{ name: 'LogFileSize', type: :dword, data: 16384 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.9 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' do
  values [{ name: 'LogDroppedPackets', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 9.1.10 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' do
  values [{ name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

powershell_script 'Firewall Domain Profile Settings' do
  code <<-EOH
  $params = @{
    'Name'='Domain';
    'Enabled'='True';
    'DefaultInboundAction'='Block';
    'DefaultOutboundAction'='Allow';
    'AllowLocalFirewallRules'='True';
    'AllowLocalIPsecRules'='True';
    'NotifyOnListen'='False';
    'LogFileName'='%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log';
    'LogMaxSizeKilobytes'='16384';
    'LogAllowed'='True';
    'LogBlocked'='True';
    'PolicyStore'="$env:COMPUTERNAME"
  }

  Set-NetFirewallProfile @params -Verbose
  EOH
end
