#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-18-4-network

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 18.4.4.1 (L1) Set 'NetBIOS node type' to 'P-node' (Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)') (MS Only)
control '18.4.4.1' do
  impact 1.0
  title 'Set NetBIOS node type to P-node (Ensure NetBT Parameter NodeType is set to 0x2 (2)) (MS Only)'
  desc 'Set NetBIOS node type to P-node (Ensure NetBT Parameter NodeType is set to 0x2 (2)) (MS Only)'
  tag 'cis-level-1', 'cis-18.4.4.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
    it { should exist }
    it { should have_property_value('NodeType', :type_dword, 2) }
  end
end

# 18.4.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only)
control '18.4.4.2' do
  impact 1.0
  title 'Ensure Turn off multicast name resolution is set to Enabled (MS Only)'
  desc 'Ensure Turn off multicast name resolution is set to Enabled (MS Only)'
  tag 'cis-level-1', 'cis-18.4.4.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient') do
    it { should exist }
    it { should have_property_value('EnableMulticast', :type_dword, 0) }
  end
end

# 18.4.5.1 (L2) Ensure Enable Font Providers is set to Disabled (Scored)
control '18.4.5.1' do
  impact 1.0
  title 'Ensure Enable Font Providers is set to Disabled'
  desc 'Ensure Enable Font Providers is set to Disabled'
  tag 'cis-level-2', 'cis-18.4.5.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('EnableFontProviders', :type_dword, 0) }
  end
end

# 18.4.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
control '18.4.8.1' do
  impact 1.0
  title 'Ensure Enable insecure guest logons is set to Disabled'
  desc 'Ensure Enable insecure guest logons is set to Disabled'
  tag 'cis-level-1', 'cis-18.4.8.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
    it { should exist }
    it { should have_property_value('AllowInsecureGuestAuth', :type_dword, 0) }
  end
end

# 18.4.9.1 (L2) Ensure Turn on Mapper I/O (LLTDIO) driver is set to Disabled
control '18.4.9.1' do
  impact 1.0
  title 'Ensure Turn on Mapper I/O (LLTDIO) driver is set to Disabled'
  desc 'Ensure Turn on Mapper I/O (LLTDIO) driver is set to Disabled'
  tag 'cis-level-2', 'cis-18.4.9.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD') do
    it { should exist }
    it { should have_property_value('AllowLLTDIOOnDomain', :type_dword, 0) }
    it { should have_property_value('AllowLLTDIOOnPublicNet', :type_dword, 0) }
    it { should have_property_value('EnableLLTDIO', :type_dword, 0) }
    it { should have_property_value('ProhibitLLTDIOOnPrivateNet', :type_dword, 0) }
  end
end

# 18.4.9.2 (L2) Ensure Turn on Responder (RSPNDR) driver is set to Disabled
control '18.4.9.2' do
  impact 1.0
  title 'Ensure Turn on Responder (RSPNDR) driver is set to Disabled'
  desc 'Ensure Turn on Responder (RSPNDR) driver is set to Disabled'
  tag 'cis-level-2', 'cis-18.4.9.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD') do
    it { should exist }
    it { should have_property_value('AllowRspndrOnDomain', :type_dword, 0) }
    it { should have_property_value('AllowRspndrOnPublicNet', :type_dword, 0) }
    it { should have_property_value('EnableRspndr', :type_dword, 0) }
    it { should have_property_value('ProhibitRspndrOnPrivateNet', :type_dword, 0) }
  end
end

# 18.4.10.2 (L2) Ensure Turn off Microsoft Peer-to-Peer Networking Services is set to Enabled
control '18.4.10.2' do
  impact 1.0
  title 'Ensure Turn off Microsoft Peer-to-Peer Networking Services is set to Enabled'
  desc 'Ensure Turn off Microsoft Peer-to-Peer Networking Services is set to Enabled'
  tag 'cis-level-2', 'cis-18.4.10.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet') do
    it { should exist }
    it { should have_property_value('Disabled', :type_dword, 1) }
  end
end

# 18.4.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
control '18.4.11.2' do
  impact 1.0
  title 'Ensure Prohibit installation and configuration of Network Bridge on your DNS domain network is set to Enabled'
  desc 'Ensure Prohibit installation and configuration of Network Bridge on your DNS domain network is set to Enabled'
  tag 'cis-level-1', 'cis-18.4.11.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    it { should exist }
    it { should have_property_value('NC_AllowNetBridge_NLA', :type_dword, 0) }
  end
end

# 18.4.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
control '18.4.11.3' do
  impact 1.0
  title 'Ensure Prohibit use of Internet Connection Sharing on your DNS domain network is set to Enabled'
  desc 'Ensure Prohibit use of Internet Connection Sharing on your DNS domain network is set to Enabled'
  tag 'cis-level-1', 'cis-18.4.11.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    it { should exist }
    it { should have_property_value('NC_ShowSharedAccessUI', :type_dword, 0) }
  end
end

# 18.4.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
control '18.4.11.4' do
  impact 1.0
  title 'Ensure Require domain users to elevate when setting a networks location is set to Enabled'
  desc 'Ensure Require domain users to elevate when setting a networks location is set to Enabled'
  tag 'cis-level-1', 'cis-18.4.11.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    it { should exist }
    it { should have_property_value('NC_StdDomainUserSetLocation', :type_dword, 1) }
  end
end

# 18.4.14.1 (L1)  Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
control '18.4.14.1' do
  impact 1.0
  title ' Ensure Hardened UNC Paths is set to Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
  desc ' Ensure Hardened UNC Paths is set to Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
  tag 'cis-level-1', 'cis-18.4.14.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
    it { should exist }
    it { should have_property_value("\\\\*\\NETLOGON", :type_string, 'RequireMutualAuthentication=1, RequireIntegrity=1') }
    it { should have_property_value("\\\\*\\SYSVOL", :type_string, 'RequireMutualAuthentication=1, RequireIntegrity=1') }
  end
end

# 18.4.19.2.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'
control '18.4.19.2.1' do
  impact 1.0
  title 'Disable IPv6 (Ensure TCPIP6 Parameter DisabledComponents is set to 0xff (255)'
  desc 'Disable IPv6 (Ensure TCPIP6 Parameter DisabledComponents is set to 0xff (255)'
  tag 'cis-level-2', 'cis-18.4.19.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters') do
    it { should exist }
    it { should have_property_value('DisabledComponents', :type_dword, 255) }
  end
end

# 18.4.20.1 (L2) Ensure Configuration of wireless settings using Windows Connect Now is set to Disabled
control '18.4.20.1' do
  impact 1.0
  title 'Ensure Configuration of wireless settings using Windows Connect Now is set to Disabled'
  desc 'Ensure Configuration of wireless settings using Windows Connect Now is set to Disabled'
  tag 'cis-level-2', 'cis-18.4.20.2.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars') do
    it { should exist }
    it { should have_property_value('EnableRegistrars', :type_dword, 0) }
    it { should have_property_value('DisableWPDRegistrar', :type_dword, 0) }
    it { should have_property_value('DisableUPnPRegistrar', :type_dword, 0) }
    it { should have_property_value('DisableInBand802DOT11Registrar', :type_dword, 0) }
    it { should have_property_value('DisableFlashConfigRegistrar', :type_dword, 0) }
  end
end

# 18.4.20.2 (L2) Ensure Prohibit access of the Windows Connect Now wizards is set to Enabled
control '18.4.20.2' do
  impact 1.0
  title 'Ensure Prohibit access of the Windows Connect Now wizards is set to Enabled'
  desc 'Ensure Prohibit access of the Windows Connect Now wizards is set to Enabled'
  tag 'cis-level-2', 'cis-18.4.20.2.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI') do
    it { should exist }
    it { should have_property_value('DisableWcnUi', :type_dword, 1) }
  end
end

# 18.4.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
control '18.4.21.1' do
  impact 1.0
  title 'Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain is set to Enabled'
  desc 'Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain is set to Enabled'
  tag 'cis-level-1', 'cis-18.4.21.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    it { should exist }
    it { should have_property_value('fMinimizeConnections', :type_dword, 1) }
  end
end

# 18.4.21.2 (L2) Ensure Prohibit connection to non-domain networks when connected to domain authenticated network is set to Enabled
control '18.4.21.2' do
  impact 1.0
  title '(L2) Ensure Prohibit connection to non-domain networks when connected to domain authenticated network is set to Enabled'
  desc '(L2) Ensure Prohibit connection to non-domain networks when connected to domain authenticated network is set to Enabled'
  tag 'cis-level-1', 'cis-18.4.21.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    it { should exist }
    it { should have_property_value('fBlockNonDomain', :type_dword, 1) }
  end
end
