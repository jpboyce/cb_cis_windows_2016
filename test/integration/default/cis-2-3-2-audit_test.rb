# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-2-audit

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
control '2.3.2.1' do
  impact 1.0
  title 'Ensure Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to Enabled'
  desc 'Ensure Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('SCENoApplyLegacyAuditPolicy ', :type_dword, '1') }
  end
end

# 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
control '2.3.2.2' do
  impact 1.0
  title 'Ensure Audit: Shut down system immediately if unable to log security audits is set to Disabled'
  desc 'Ensure Audit: Shut down system immediately if unable to log security audits is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('CrashOnAuditFail ', :type_dword, '1') }
  end
end
