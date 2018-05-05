# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-1-1-password-policy

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
control '1.1.1' do
  impact 1.0
  title 'Ensure Enforce password history is set to 24 or more password(s)'
  desc 'Ensure Enforce password history is set to 24 or more password(s)'
  tag 'cis-level-1','cis-1.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 1.1.2 (L1)  Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
control '1.1.2' do
  impact 1.0
  title ' Ensure Maximum password age is set to 60 or fewer days, but not 0'
  desc ' Ensure Maximum password age is set to 60 or fewer days, but not 0'
  tag 'cis-level-1','cis-1.1.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
control '1.1.3' do
  impact 1.0
  title 'Ensure Minimum password age is set to 1 or more day(s)'
  desc 'Ensure Minimum password age is set to 1 or more day(s)'
  tag 'cis-level-1','cis-1.1.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
control '1.1.4' do
  impact 1.0
  title 'Ensure Minimum password length is set to 14 or more character(s)'
  desc 'Ensure Minimum password length is set to 14 or more character(s)'
  tag 'cis-level-1','cis-1.1.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
control '1.1.5' do
  impact 1.0
  title 'Ensure Password must meet complexity requirements is set to Enabled'
  desc 'Ensure Password must meet complexity requirements is set to Enabled'
  tag 'cis-level-1','cis-1.1.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end

# 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
control '1.1.6' do
  impact 1.0
  title 'Ensure Store passwords using reversible encryption is set to Disabled'
  desc 'Ensure Store passwords using reversible encryption is set to Disabled'
  tag 'cis-level-1','cis-1.1.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value( '', :type_dword, '1' )}
  end
end
