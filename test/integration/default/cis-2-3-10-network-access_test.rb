# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-10-network-access

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
control '2.3.10.1' do
  impact 1.0
  title 'Ensure Network access: Allow anonymous SID/Name translation is set to Disabled'
  desc 'Ensure Network access: Allow anonymous SID/Name translation is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.10.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)
control '2.3.10.2' do
  impact 1.0
  title 'Ensure Network access: Do not allow anonymous enumeration of SAM accounts is set to Enabled (MS only)'
  desc 'Ensure Network access: Do not allow anonymous enumeration of SAM accounts is set to Enabled (MS only)'
  tag 'cis-level-1', 'cis-2.3.10.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('RestrictAnonymousSAM ', :type_dword, '1') }
  end
end

# 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
control '2.3.10.3' do
  impact 1.0
  title 'Ensure Network access: Do not allow anonymous enumeration of SAM accounts and shares is set to Enabled (MS only)'
  desc 'Ensure Network access: Do not allow anonymous enumeration of SAM accounts and shares is set to Enabled (MS only)'
  tag 'cis-level-1', 'cis-2.3.10.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('RestrictAnonymous ', :type_dword, '1') }
  end
end

# 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
control '2.3.10.5' do
  impact 1.0
  title 'Ensure Network access: Let Everyone permissions apply to anonymous users is set to Disabled'
  desc 'Ensure Network access: Let Everyone permissions apply to anonymous users is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.10.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('EveryoneIncludesAnonymous ', :type_dword, '1') }
  end
end

# 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'
control '2.3.10.6' do
  impact 1.0
  title 'Configure Network access: Named Pipes that can be accessed anonymously'
  desc 'Configure Network access: Named Pipes that can be accessed anonymously'
  tag 'cis-level-1', 'cis-2.3.10.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('NullSessionPipes ', :type_dword, '1') }
  end
end

# 2.3.10.7 (L1) Configure 'Network access: Remotely accessible registry paths'
control '2.3.10.7' do
  impact 1.0
  title 'Configure Network access: Remotely accessible registry paths'
  desc 'Configure Network access: Remotely accessible registry paths'
  tag 'cis-level-1', 'cis-2.3.10.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths') do
    it { should exist }
    it { should have_property_value('Machine ', :type_dword, '1') }
  end
end

# 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths'
control '2.3.10.8' do
  impact 1.0
  title 'Configure Network access: Remotely accessible registry paths and sub-paths'
  desc 'Configure Network access: Remotely accessible registry paths and sub-paths'
  tag 'cis-level-1', 'cis-2.3.10.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths') do
    it { should exist }
    it { should have_property_value('Machine ', :type_dword, '1') }
  end
end

# 2.3.10.9 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
control '2.3.10.9' do
  impact 1.0
  title 'Ensure Network access: Restrict anonymous access to Named Pipes and Shares is set to Enabled'
  desc 'Ensure Network access: Restrict anonymous access to Named Pipes and Shares is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.10.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('RestrictNullSessAccess ', :type_dword, '1') }
  end
end

# 2.3.10.11 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
control '2.3.10.11' do
  impact 1.0
  title 'Ensure Network access: Shares that can be accessed anonymously is set to None'
  desc 'Ensure Network access: Shares that can be accessed anonymously is set to None'
  tag 'cis-level-1', 'cis-2.3.10.11'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('NullSessionShares ', :type_dword, '1') }
  end
end

# 2.3.10.12 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
control '2.3.10.12' do
  impact 1.0
  title 'Ensure Network access: Sharing and security model for local accounts is set to Classic - local users authenticate as themselves'
  desc 'Ensure Network access: Sharing and security model for local accounts is set to Classic - local users authenticate as themselves'
  tag 'cis-level-1', 'cis-2.3.10.12'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('ForceGuest ', :type_dword, '1') }
  end
end

# 2.3.10.10 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)
control '2.3.10.10' do
  impact 1.0
  title 'Ensure Network access: Restrict clients allowed to make remote calls to SAM is set to Administrators: Remote Access: Allow (MS only)'
  desc 'Ensure Network access: Restrict clients allowed to make remote calls to SAM is set to Administrators: Remote Access: Allow (MS only)'
  tag 'cis-level-1', 'cis-2.3.10.10'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('restrictremotesam ', :type_dword, '1') }
  end
end
