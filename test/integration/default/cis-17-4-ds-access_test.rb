#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-17-4-ds-access

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 17.4.1 (L1) Ensure Audit Directory Service Access is set to Success and Failure (DC only)
control '17.4.1' do
  impact 1.0
  title 'Ensure Audit Directory Service Access is set to Success and Failure (DC only)'
  desc 'Ensure Audit Directory Service Access is set to Success and Failure (DC only)'
  tag 'cis-level-1', 'cis-17.4.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Directory Service Access"') do
    its('stdout') { should match /.*Directory Service Access.*Success and Failure\r\n/m }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

# 17.4.2 (L1) Ensure Audit Directory Service Changes is set to Success and Failure (DC only)
control '17.4.2' do
  impact 1.0
  title 'Ensure Audit Directory Service Changes is set to Success and Failure (DC only)'
  desc 'Ensure Audit Directory Service Changes is set to Success and Failure (DC only)'
  tag 'cis-level-1', 'cis-17.4.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Directory Service Changes"') do
    its('stdout') { should match /.*Directory Service Changes.*Success and Failure\r\n/m }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end
