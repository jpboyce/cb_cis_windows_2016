#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-9-microsoft-network-server

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.9.1 (L1)  Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
control '2.3.9.1' do
  impact 1.0
  title ' Ensure Microsoft network server: Amount of idle time required before suspending session is set to 15 or fewer minute(s), but not 0'
  desc ' Ensure Microsoft network server: Amount of idle time required before suspending session is set to 15 or fewer minute(s), but not 0'
  tag 'cis-level-1', 'cis-2.3.9.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('AutoDisconnect', :type_dword, 15) }
  end
end

# 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
control '2.3.9.2' do
  impact 1.0
  title 'Ensure Microsoft network server: Digitally sign communications (always) is set to Enabled'
  desc 'Ensure Microsoft network server: Digitally sign communications (always) is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.9.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('RequireSecuritySignature', :type_dword, 1) }
  end
end

# 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
control '2.3.9.3' do
  impact 1.0
  title 'Ensure Microsoft network server: Digitally sign communications (if client agrees) is set to Enabled'
  desc 'Ensure Microsoft network server: Digitally sign communications (if client agrees) is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.9.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('EnableSecuritySignature', :type_dword, 1) }
  end
end

# 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
control '2.3.9.4' do
  impact 1.0
  title 'Ensure Microsoft network server: Disconnect clients when logon hours expire is set to Enabled'
  desc 'Ensure Microsoft network server: Disconnect clients when logon hours expire is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.9.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('EnableForcedLogoff', :type_dword, 1) }
  end
end

# 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)
control '2.3.9.5' do
  impact 1.0
  title 'Ensure Microsoft network server: Server SPN target name validation level is set to Accept if provided by client or higher (MS only)'
  desc 'Ensure Microsoft network server: Server SPN target name validation level is set to Accept if provided by client or higher (MS only)'
  tag 'cis-level-1', 'cis-2.3.9.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('SMBServerNameHardeningLevel', :type_dword, 1) }
  end
end
