#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-17-8-privilege-use

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
control '17.8.1' do
  impact 1.0
  title 'Ensure Audit Sensitive Privilege Use is set to Success and Failure'
  desc 'Ensure Audit Sensitive Privilege Use is set to Success and Failure'
  tag 'cis-level-1', 'cis-17.8.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end
