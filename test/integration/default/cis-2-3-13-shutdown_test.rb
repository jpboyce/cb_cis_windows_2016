# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-13-shutdown

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
control '2.3.13.1' do
  impact 1.0
  title 'Ensure Shutdown: Allow system to be shut down without having to log on is set to Disabled'
  desc 'Ensure Shutdown: Allow system to be shut down without having to log on is set to Disabled'
  tag 'cis-level-1','cis-2.3.13.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url:'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value( 'ShutdownWithoutLogon ', :type_dword, '1' )}
  end
end
