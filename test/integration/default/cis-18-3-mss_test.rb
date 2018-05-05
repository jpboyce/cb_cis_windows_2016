#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-18-3-mss

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 18.3.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
control '18.3.1' do
  impact 1.0
  title 'Ensure MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended) is set to Disabled'
  desc 'Ensure MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended) is set to Disabled'
  tag 'cis-level-1', 'cis-18.3.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    it { should have_property_value('AutoAdminLogon ', :type_dword, '1') }
  end
end

# 18.3.2 (L1)  Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control '18.3.2' do
  impact 1.0
  title ' Ensure MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is set to Enabled: Highest protection, source routing is completely disabled'
  desc ' Ensure MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is set to Enabled: Highest protection, source routing is completely disabled'
  tag 'cis-level-1', 'cis-18.3.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters') do
    it { should exist }
    it { should have_property_value('DisableIPSourceRouting ', :type_dword, '1') }
  end
end

# 18.3.3 (L1)  Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
control '18.3.3' do
  impact 1.0
  title ' Ensure MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is set to Enabled: Highest protection, source routing is completely disabled'
  desc ' Ensure MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is set to Enabled: Highest protection, source routing is completely disabled'
  tag 'cis-level-1', 'cis-18.3.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
    it { should exist }
    it { should have_property_value('DisableIPSourceRouting ', :type_dword, '1') }
  end
end

# 18.3.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
control '18.3.4' do
  impact 1.0
  title 'Ensure MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is set to Disabled'
  desc 'Ensure MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is set to Disabled'
  tag 'cis-level-1', 'cis-18.3.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
    it { should exist }
    it { should have_property_value('EnableICMPRedirect ', :type_dword, '1') }
  end
end

# 18.3.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
control '18.3.6' do
  impact 1.0
  title 'Ensure MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is set to Enabled'
  desc 'Ensure MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is set to Enabled'
  tag 'cis-level-1', 'cis-18.3.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters') do
    it { should exist }
    it { should have_property_value('NoNameReleaseOnDemand ', :type_dword, '1') }
  end
end

# 18.3.8 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
control '18.3.8' do
  impact 1.0
  title 'Ensure MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended) is set to Enabled'
  desc 'Ensure MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended) is set to Enabled'
  tag 'cis-level-1', 'cis-18.3.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager') do
    it { should exist }
    it { should have_property_value('SafeDllSearchMode ', :type_dword, '1') }
  end
end

# 18.3.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
control '18.3.9' do
  impact 1.0
  title 'Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended) is set to Enabled: 5 or fewer seconds'
  desc 'Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended) is set to Enabled: 5 or fewer seconds'
  tag 'cis-level-1', 'cis-18.3.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    it { should have_property_value('ScreenSaverGracePeriod ', :type_dword, '1') }
  end
end

# 18.3.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
control '18.3.12' do
  impact 1.0
  title 'Ensure MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning is set to Enabled: 90% or less'
  desc 'Ensure MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning is set to Enabled: 90% or less'
  tag 'cis-level-1', 'cis-18.3.12'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security') do
    it { should exist }
    it { should have_property_value('WarningLevel ', :type_dword, '1') }
  end
end
