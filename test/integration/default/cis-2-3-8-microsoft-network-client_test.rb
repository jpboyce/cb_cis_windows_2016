# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-8-microsoft-network-client

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
control '2.3.8.1' do
  impact 1.0
  title 'Ensure Microsoft network client: Digitally sign communications (always) is set to Enabled'
  desc 'Ensure Microsoft network client: Digitally sign communications (always) is set to Enabled'
  tag 'cis-level-1','cis-2.3.8.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    it { should have_property_value( 'RequireSecuritySignature ', :type_dword, '1' )}
  end
end

# 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
control '2.3.8.2' do
  impact 1.0
  title 'Ensure Microsoft network client: Digitally sign communications (if server agrees) is set to Enabled'
  desc 'Ensure Microsoft network client: Digitally sign communications (if server agrees) is set to Enabled'
  tag 'cis-level-1','cis-2.3.8.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    it { should have_property_value( 'EnableSecuritySignature ', :type_dword, '1' )}
  end
end

# 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
control '2.3.8.3' do
  impact 1.0
  title 'Ensure Microsoft network client: Send unencrypted password to third-party SMB servers is set to Disabled'
  desc 'Ensure Microsoft network client: Send unencrypted password to third-party SMB servers is set to Disabled'
  tag 'cis-level-1','cis-2.3.8.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    it { should have_property_value( 'EnablePlainTextPassword ', :type_dword, '1' )}
  end
end
