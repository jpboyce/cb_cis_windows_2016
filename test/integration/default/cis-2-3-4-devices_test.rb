#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-4-devices

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
control '2.3.4.1' do
  impact 1.0
  title 'Ensure Devices: Allowed to format and eject removable media is set to Administrators'
  desc 'Ensure Devices: Allowed to format and eject removable media is set to Administrators'
  tag 'cis-level-1', 'cis-2.3.4.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    it { should have_property_value('AllocateDASD', :type_dword, '0') }
  end
end

# 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
control '2.3.4.2' do
  impact 1.0
  title 'Ensure Devices: Prevent users from installing printer drivers is set to Enabled'
  desc 'Ensure Devices: Prevent users from installing printer drivers is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.4.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers') do
    it { should exist }
    it { should have_property_value('AddPrinterDrivers', :type_dword, '1') }
  end
end
