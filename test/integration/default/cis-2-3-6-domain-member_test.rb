#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-6-domain-member

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
control '2.3.6.1' do
  impact 1.0
  title 'Ensure Domain member: Digitally encrypt or sign secure channel data (always) is set to Enabled'
  desc 'Ensure Domain member: Digitally encrypt or sign secure channel data (always) is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.6.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should exist }
    it { should have_property_value('RequireSignOrSeal', :type_dword, 1) }
  end
end

# 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
control '2.3.6.2' do
  impact 1.0
  title 'Ensure Domain member: Digitally encrypt secure channel data (when possible) is set to Enabled'
  desc 'Ensure Domain member: Digitally encrypt secure channel data (when possible) is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.6.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should exist }
    it { should have_property_value('SealSecureChannel', :type_dword, 1) }
  end
end

# 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
control '2.3.6.3' do
  impact 1.0
  title 'Ensure Domain member: Digitally sign secure channel data (when possible) is set to Enabled'
  desc 'Ensure Domain member: Digitally sign secure channel data (when possible) is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.6.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should exist }
    it { should have_property_value('SignSecureChannel', :type_dword, 1) }
  end
end

# 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
control '2.3.6.4' do
  impact 1.0
  title 'Ensure Domain member: Disable machine account password changes is set to Disabled'
  desc 'Ensure Domain member: Disable machine account password changes is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.6.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should exist }
    it { should have_property_value('DisablePasswordChange', :type_dword, 0) }
  end
end

# 2.3.6.5 (L1)  Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
control '2.3.6.5' do
  impact 1.0
  title ' Ensure Domain member: Maximum machine account password age is set to 30 or fewer days, but not 0'
  desc ' Ensure Domain member: Maximum machine account password age is set to 30 or fewer days, but not 0'
  tag 'cis-level-1', 'cis-2.3.6.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should exist }
    its('MaximumPasswordAge') { should be <= 30 }
    its('MaximumPasswordAge') { should_not be 0 }
  end
end

# 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
control '2.3.6.6' do
  impact 1.0
  title 'Ensure Domain member: Require strong (Windows 2000 or later) session key is set to Enabled'
  desc 'Ensure Domain member: Require strong (Windows 2000 or later) session key is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.6.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should exist }
    it { should have_property_value('RequireStrongKey', :type_dword, 1) }
  end
end
