#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-15-system-objects

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
control '2.3.15.1' do
  impact 1.0
  title 'Ensure System objects: Require case insensitivity for non-Windows subsystems is set to Enabled'
  desc 'Ensure System objects: Require case insensitivity for non-Windows subsystems is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.15.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel') do
    it { should exist }
    it { should have_property_value('ObCaseInsensitive ', :type_dword, '1') }
  end
end

# 2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
control '2.3.15.2' do
  impact 1.0
  title 'Ensure System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is set to Enabled'
  desc 'Ensure System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.15.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager') do
    it { should exist }
    it { should have_property_value('ProtectionMode ', :type_dword, '1') }
  end
end
