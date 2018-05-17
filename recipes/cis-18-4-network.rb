# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-18-4-network
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 18.4.4.1 (L1) Set 'NetBIOS node.default type' to 'P-node.default' (Ensure NetBT Parameter 'node.defaultType' is set to '0x2 (2)') (MS Only)
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters' do
  values [{ name: 'NodeType', type: :dword, data: 2 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only)
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' do
  values [{ name: 'EnableMulticast', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' do
  values [{ name: 'AllowInsecureGuestAuth', type: :dword, data: 0 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections' do
  values [{ name: 'NC_AllowNetBridge_NLA', type: :dword, data: 0 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections' do
  values [{ name: 'NC_ShowSharedAccessUI', type: :dword, data: 0 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections' do
  values [{ name: 'NC_StdDomainUserSetLocation', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.14.1 (L1)  Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' do
  values [{ name: "\\*\NETLOGON", type: :string, data 'Require Mutual Authentication=1,Require Integrity=1'},
  { name: "\\*\SYSVOL", type: :string, data 'Require Mutual Authentication=1,Require Integrity=1'}]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.19.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' do
  values [{ name: 'DisabledComponents', type: :dword, data: 255 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_2'] = true }
end

# 18.4.19.2 (L2) Ensure Prohibit access of the Windows Connect Now wizards is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' do
  values [{ name: 'DisableWcnUi', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_2'] = true }
end

# 18.4.20.2.1 (L2) Ensure Configuration of wireless settings using Windows Connect Now is set to Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' do
  values [{ name: 'EnableRegistrars', type: :dword, data: 0 },
          { name: 'DisableWPDRegistrar', type: :dword, data: 0 },
          { name: 'DisableUPnPRegistrar', type: :dword, data: 0 },
          { name: 'DisableInBand802DOT11Registrar', type: :dword, data: 0 },
          { name: 'DisableFlashConfigRegistrar', type: :dword, data: 0 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_2'] = true }
end

# 18.4.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' do
  values [{ name: 'fMinimizeConnections', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.4.21.2 (L2) Ensure Prohibit connection to non-domain networks when connected to domain authenticated network is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' do
  values [{ name: 'fBlockNonDomain', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_2'] = true }
end
