# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-1-accounts

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'
control '2.3.1.1' do
  impact 1.0
  title 'Ensure Accounts: Administrator account status is set to Disabled'
  desc 'Ensure Accounts: Administrator account status is set to Disabled'
  tag 'cis-level-1','cis-2.3.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
control '2.3.1.2' do
  impact 1.0
  title 'Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts'
  desc 'Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts'
  tag 'cis-level-1','cis-2.3.1.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value( 'NoConnectedUser ', :type_dword, '1' )}
  end
end

# 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
control '2.3.1.3' do
  impact 1.0
  title 'Ensure Accounts: Guest account status is set to Disabled'
  desc 'Ensure Accounts: Guest account status is set to Disabled'
  tag 'cis-level-1','cis-2.3.1.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
control '2.3.1.4' do
  impact 1.0
  title 'Ensure Accounts: Limit local account use of blank passwords to console logon only is set to Enabled'
  desc 'Ensure Accounts: Limit local account use of blank passwords to console logon only is set to Enabled'
  tag 'cis-level-1','cis-2.3.1.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value( 'LimitBlankPasswordUse ', :type_dword, '1' )}
  end
end

# 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'
control '2.3.1.5' do
  impact 1.0
  title 'Configure Accounts: Rename administrator account'
  desc 'Configure Accounts: Rename administrator account'
  tag 'cis-level-1','cis-2.3.1.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 2.3.1.6 (L1) Configure 'Accounts: Rename guest account'
control '2.3.1.6' do
  impact 1.0
  title 'Configure Accounts: Rename guest account'
  desc 'Configure Accounts: Rename guest account'
  tag 'cis-level-1','cis-2.3.1.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end
