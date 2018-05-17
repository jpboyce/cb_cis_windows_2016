# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-18-3-mss
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 18.3.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'AutoAdminLogon', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.3.2 (L1)  Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.3.3 (L1)  Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.3.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' do
  values [{ name: 'EnableICMPRedirect', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.3.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' do
  values [{ name: 'NoNameReleaseOnDemand', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.3.8 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' do
  values [{ name: 'SafeDllSearchMode', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.3.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'ScreenSaverGracePeriod', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 18.3.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security' do
  values [{ name: 'WarningLevel', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
