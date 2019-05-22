#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-17-5-logon-logoff

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
control '17.5.1' do
  impact 1.0
  title 'Ensure Audit Account Lockout is set to Success and Failure'
  desc 'Ensure Audit Account Lockout is set to Success and Failure'
  tag 'cis-level-1', 'cis-17.5.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Account Lockout"') do
    its('stdout') { should match /.*Account Lockout.*Success and Failure\r\n/m }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

# 17.5.2 (L1) Ensure 'Audit Group Membership' is set to 'Success'
control '17.5.2' do
  impact 1.0
  title 'Ensure Audit Group Membership is set to Success'
  desc 'Ensure Audit Group Membership is set to Success'
  tag 'cis-level-1', 'cis-17.5.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Group Membership"') do
    its('stdout') { should match /.*Group Membership.*Success\r\n/m }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

# 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
control '17.5.3' do
  impact 1.0
  title 'Ensure Audit Logoff is set to Success'
  desc 'Ensure Audit Logoff is set to Success'
  tag 'cis-level-1', 'cis-17.5.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Logoff"') do
    its('stdout') { should match /.*Logoff.*Success\r\n/m }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

# 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
control '17.5.4' do
  impact 1.0
  title 'Ensure Audit Logon is set to Success and Failure'
  desc 'Ensure Audit Logon is set to Success and Failure'
  tag 'cis-level-1', 'cis-17.5.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Logon"') do
    its('stdout') { should match /.*Logon.*Success and Failure\r\n/m }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

# 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
control '17.5.5' do
  impact 1.0
  title 'Ensure Audit Other Logon/Logoff Events is set to Success and Failure'
  desc 'Ensure Audit Other Logon/Logoff Events is set to Success and Failure'
  tag 'cis-level-1', 'cis-17.5.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Other Logon/Logoff Events"') do
    its('stdout') { should match %r{/.*Other Logon\/Logoff Events.*Success and Failure\r\n/m} }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end

# 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
control '17.5.6' do
  impact 1.0
  title 'Ensure Audit Special Logon is set to Success'
  desc 'Ensure Audit Special Logon is set to Success'
  tag 'cis-level-1', 'cis-17.5.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/command/
  describe command('auditpol /get /subcategory:"Special Logon"') do
    its('stdout') { should match /.*Special Logon.*Success\r\n/m }
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end
end
