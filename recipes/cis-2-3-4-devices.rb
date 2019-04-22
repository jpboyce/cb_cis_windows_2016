# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-4-devices
#
# Copyright:: 2018, Jesse Boyce, All Rights Reserved.

# 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'AllocateDASD', type: :string, data: '0' }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' do
  values [{ name: 'AddPrinterDrivers', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end
