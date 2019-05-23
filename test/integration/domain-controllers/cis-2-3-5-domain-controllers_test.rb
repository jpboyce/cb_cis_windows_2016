#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-5-domain-controllers

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.5.1 (L1) Ensure Domain controller: Allow server operators to schedule tasks is set to Disabled (DC only)
control '2.3.5.1' do
  impact 1.0
  title 'Ensure Domain controller: Allow server operators to schedule tasks is set to Disabled (DC only)'
  desc 'Ensure Domain controller: Allow server operators to schedule tasks is set to Disabled (DC only)'
  tag 'cis-level-1', 'cis-2.3.5.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('SubmitControl', :type_dword, 0) }
  end
end

# 2.3.5.2 (L1) Ensure Domain controller: LDAP server signing requirements is set to Require signing (DC only)
control '2.3.5.2' do
  impact 1.0
  title 'Ensure Domain controller: LDAP server signing requirements is set to Require signing (DC only)'
  desc 'Ensure Domain controller: LDAP server signing requirements is set to Require signing (DC only)'
  tag 'cis-level-1', 'cis-2.3.5.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters') do
    it { should exist }
    it { should have_property_value('LDAPServerIntegrity', :type_dword, 2) }
  end
end

# 2.3.5.3 (L1) Ensure Domain controller: Refuse machine account password changes is set to Disabled (DC only)
control '2.3.5.3' do
  impact 1.0
  title 'Ensure Domain controller: Refuse machine account password changes is set to Disabled (DC only)'
  desc 'Ensure Domain controller: Refuse machine account password changes is set to Disabled (DC only)'
  tag 'cis-level-1', 'cis-2.3.5.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should exist }
    it { should have_property_value('RefusePasswordChange', :type_dword, 0) }
  end
end
