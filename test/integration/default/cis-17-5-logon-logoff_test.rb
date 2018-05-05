# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-17-5-logon-logoff

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
control '17.5.1' do
  impact 1.0
  title 'Ensure Audit Account Lockout is set to Success and Failure'
  desc 'Ensure Audit Account Lockout is set to Success and Failure'
  tag 'cis-level-1','cis-17.5.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.5.2 (L1) Ensure 'Audit Group Membership' is set to 'Success'
control '17.5.2' do
  impact 1.0
  title 'Ensure Audit Group Membership is set to Success'
  desc 'Ensure Audit Group Membership is set to Success'
  tag 'cis-level-1','cis-17.5.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
control '17.5.3' do
  impact 1.0
  title 'Ensure Audit Logoff is set to Success'
  desc 'Ensure Audit Logoff is set to Success'
  tag 'cis-level-1','cis-17.5.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
control '17.5.4' do
  impact 1.0
  title 'Ensure Audit Logon is set to Success and Failure'
  desc 'Ensure Audit Logon is set to Success and Failure'
  tag 'cis-level-1','cis-17.5.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
control '17.5.5' do
  impact 1.0
  title 'Ensure Audit Other Logon/Logoff Events is set to Success and Failure'
  desc 'Ensure Audit Other Logon/Logoff Events is set to Success and Failure'
  tag 'cis-level-1','cis-17.5.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
control '17.5.6' do
  impact 1.0
  title 'Ensure Audit Special Logon is set to Success'
  desc 'Ensure Audit Special Logon is set to Success'
  tag 'cis-level-1','cis-17.5.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end
