#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-19-6-admin-templates-system

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 19.6.5.1.1 (L2) Ensure Turn off Help Experience Improvement Program is set to Enabled
control '19.6.5.1.1' do
  impact 1.0
  title '(L2) Ensure Turn off Help Experience Improvement Program is set to Enabled'
  desc '(L2) Ensure Turn off Help Experience Improvement Program is set to Enabled'
  tag 'cis-level-2', 'cis-19.6.5.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0') do
    it { should exist }
    it { should have_property_value('NoImplicitFeedback', :type_dword, 1) }
  end
end
