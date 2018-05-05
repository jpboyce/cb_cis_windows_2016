# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-17-2-account-management

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
control '17.2.1' do
  impact 1.0
  title 'Ensure Audit Application Group Management is set to Success and Failure'
  desc 'Ensure Audit Application Group Management is set to Success and Failure'
  tag 'cis-level-1','cis-17.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
control '17.2.2' do
  impact 1.0
  title 'Ensure Audit Computer Account Management is set to Success and Failure'
  desc 'Ensure Audit Computer Account Management is set to Success and Failure'
  tag 'cis-level-1','cis-17.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
control '17.2.4' do
  impact 1.0
  title 'Ensure Audit Other Account Management Events is set to Success and Failure'
  desc 'Ensure Audit Other Account Management Events is set to Success and Failure'
  tag 'cis-level-1','cis-17.2.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'
control '17.2.5' do
  impact 1.0
  title 'Ensure Audit Security Group Management is set to Success and Failure'
  desc 'Ensure Audit Security Group Management is set to Success and Failure'
  tag 'cis-level-1','cis-17.2.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
control '17.2.6' do
  impact 1.0
  title 'Ensure Audit User Account Management is set to Success and Failure'
  desc 'Ensure Audit User Account Management is set to Success and Failure'
  tag 'cis-level-1','cis-17.2.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end
