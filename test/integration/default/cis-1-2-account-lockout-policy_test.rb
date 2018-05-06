#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-1-2-account-lockout-policy

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
control '1.2.1' do
  impact 1.0
  title 'Ensure Account lockout duration is set to 15 or more minute(s)'
  desc 'Ensure Account lockout duration is set to 15 or more minute(s)'
  tag 'cis-level-1', 'cis-1.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('LockoutDuration') { should be >= 15 }
  end
end

# 1.2.2 (L1)  Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
control '1.2.2' do
  impact 1.0
  title ' Ensure Account lockout threshold is set to 10 or fewer invalid logon attempt(s), but not 0'
  desc ' Ensure Account lockout threshold is set to 10 or fewer invalid logon attempt(s), but not 0'
  tag 'cis-level-1', 'cis-1.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('LockoutBadCount') { should be <= 10 }
    its('LockoutBadCount') { should_not eq 0 }
  end
end

# 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
control '1.2.3' do
  impact 1.0
  title 'Ensure Reset account lockout counter after is set to 15 or more minute(s)'
  desc 'Ensure Reset account lockout counter after is set to 15 or more minute(s)'
  tag 'cis-level-1', 'cis-1.2.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe security_policy do
    its('ResetLockoutCount') { should be >= 15 }
  end
end
