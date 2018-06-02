# Tests for exceptions under Test Kitchen
# 18.6.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)
control 'TKE-18.6.1' do
  impact 1.0
  title 'Test Kitchen Exception - Ensure Apply UAC restrictions to local accounts on network logons is set to Disabled (CIS Value: Enabled)'
  desc 'Test Kitchen Exception - Ensure Apply UAC restrictions to local accounts on network logons is set to Disabled (CIS Value: Enabled)'
  tag 'cis-level-1', 'cis-18.6.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('LocalAccountTokenFilterPolicy', :type_dword, 1) }
  end
end
