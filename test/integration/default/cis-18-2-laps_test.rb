#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-18-2-laps

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 18.2.1 (L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)
control '18.2.1' do
  impact 1.0
  title 'Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)'
  desc 'Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)'
  tag 'cis-level-1', 'cis-18.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}') do
    it { should exist }
    it { should have_property_value('DllName ', :type_dword, '1') }
  end
end
# 18.2.2 (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only)
control '18.2.2' do
  impact 1.0
  title 'Ensure Do not allow password expiration time longer than required by policy is set to Enabled (MS only)'
  desc 'Ensure Do not allow password expiration time longer than required by policy is set to Enabled (MS only)'
  tag 'cis-level-1', 'cis-18.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd') do
    it { should exist }
    it { should have_property_value('PwdExpirationProtectionEnabled ', :type_dword, '1') }
  end
end

# 18.2.3 (L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only)
control '18.2.3' do
  impact 1.0
  title 'Ensure Enable Local Admin Password Management is set to Enabled (MS only)'
  desc 'Ensure Enable Local Admin Password Management is set to Enabled (MS only)'
  tag 'cis-level-1', 'cis-18.2.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd') do
    it { should exist }
    it { should have_property_value('AdmPwdEnabled ', :type_dword, '1') }
  end
end

# 18.2.4 (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only)
control '18.2.4' do
  impact 1.0
  title 'Ensure Password Settings: Password Complexity is set to Enabled: Large letters + small letters + numbers + special characters (MS only)'
  desc 'Ensure Password Settings: Password Complexity is set to Enabled: Large letters + small letters + numbers + special characters (MS only)'
  tag 'cis-level-1', 'cis-18.2.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd') do
    it { should exist }
    it { should have_property_value('PasswordComplexity ', :type_dword, '1') }
  end
end

# 18.2.5 (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only)
control '18.2.5' do
  impact 1.0
  title 'Ensure Password Settings: Password Length is set to Enabled: 15 or more (MS only)'
  desc 'Ensure Password Settings: Password Length is set to Enabled: 15 or more (MS only)'
  tag 'cis-level-1', 'cis-18.2.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd') do
    it { should exist }
    it { should have_property_value('PasswordLength ', :type_dword, '1') }
  end
end

# 18.2.6 (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only)
control '18.2.6' do
  impact 1.0
  title 'Ensure Password Settings: Password Age (Days) is set to Enabled: 30 or fewer (MS only)'
  desc 'Ensure Password Settings: Password Age (Days) is set to Enabled: 30 or fewer (MS only)'
  tag 'cis-level-1', 'cis-18.2.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd') do
    it { should exist }
    it { should have_property_value('PasswordAgeDays ', :type_dword, '1') }
  end
end
