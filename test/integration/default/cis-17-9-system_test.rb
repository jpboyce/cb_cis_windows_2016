# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-17-9-system

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
control '17.9.1' do
  impact 1.0
  title 'Ensure Audit IPsec Driver is set to Success and Failure'
  desc 'Ensure Audit IPsec Driver is set to Success and Failure'
  tag 'cis-level-1','cis-17.9.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
control '17.9.2' do
  impact 1.0
  title 'Ensure Audit Other System Events is set to Success and Failure'
  desc 'Ensure Audit Other System Events is set to Success and Failure'
  tag 'cis-level-1','cis-17.9.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
control '17.9.3' do
  impact 1.0
  title 'Ensure Audit Security State Change is set to Success'
  desc 'Ensure Audit Security State Change is set to Success'
  tag 'cis-level-1','cis-17.9.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
control '17.9.4' do
  impact 1.0
  title 'Ensure Audit Security System Extension is set to Success and Failure'
  desc 'Ensure Audit Security System Extension is set to Success and Failure'
  tag 'cis-level-1','cis-17.9.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
control '17.9.5' do
  impact 1.0
  title 'Ensure Audit System Integrity is set to Success and Failure'
  desc 'Ensure Audit System Integrity is set to Success and Failure'
  tag 'cis-level-1','cis-17.9.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end
