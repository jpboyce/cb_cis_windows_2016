# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-18-6-scm-pass-the-hash-mitigations

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 18.6.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)
control '18.6.1' do
  impact 1.0
  title 'Ensure Apply UAC restrictions to local accounts on network logons is set to Enabled (MS only)'
  desc 'Ensure Apply UAC restrictions to local accounts on network logons is set to Enabled (MS only)'
  tag 'cis-level-1','cis-18.6.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value( 'LocalAccountTokenFilterPolicy ', :type_dword, '1' )}
  end
end

# 18.6.2 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
control '18.6.2' do
  impact 1.0
  title 'Ensure WDigest Authentication is set to Disabled'
  desc 'Ensure WDigest Authentication is set to Disabled'
  tag 'cis-level-1','cis-18.6.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest') do
    it { should exist }
    it { should have_property_value( 'UseLogonCredential ', :type_dword, '1' )}
  end
end
