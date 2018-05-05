# # encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-18-8-system

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Disabled'
control '18.8.3.1' do
  impact 1.0
  title 'Ensure Include command line in process creation events is set to Disabled'
  desc 'Ensure Include command line in process creation events is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.3.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    it { should exist }
    it { should have_property_value('ProcessCreationIncludeCmdLine_Enabled ', :type_dword, '1') }
  end
end

# 18.8.12.1 (L1)  Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
control '18.8.12.1' do
  impact 1.0
  title ' Ensure Boot-Start Driver Initialization Policy is set to Enabled: Good, unknown and bad but critical'
  desc ' Ensure Boot-Start Driver Initialization Policy is set to Enabled: Good, unknown and bad but critical'
  tag 'cis-level-1', 'cis-18.8.12.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch') do
    it { should exist }
    it { should have_property_value('DriverLoadPolicy ', :type_dword, '1') }
  end
end

# 18.8.19.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
control '18.8.19.2' do
  impact 1.0
  title 'Ensure Configure registry policy processing: Do not apply during periodic background processing is set to Enabled: FALSE'
  desc 'Ensure Configure registry policy processing: Do not apply during periodic background processing is set to Enabled: FALSE'
  tag 'cis-level-1', 'cis-18.8.19.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy ') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 18.8.19.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
control '18.8.19.3' do
  impact 1.0
  title 'Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE'
  desc 'Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE'
  tag 'cis-level-1', 'cis-18.8.19.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges ') do
    it { should exist }
    it { should have_property_value('', :type_dword, '1') }
  end
end

# 18.8.19.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
control '18.8.19.5' do
  impact 1.0
  title 'Ensure Turn off background refresh of Group Policy is set to Disabled'
  desc 'Ensure Turn off background refresh of Group Policy is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.19.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('DisableBkGndGroupPolicy ', :type_dword, '1') }
  end
end

# 18.8.19.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'
control '18.8.19.4' do
  impact 1.0
  title 'Ensure Continue experiences on this device is set to Disabled'
  desc 'Ensure Continue experiences on this device is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.19.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('EnableCdp ', :type_dword, '1') }
  end
end

# 18.8.25.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled'
control '18.8.25.2' do
  impact 1.0
  title 'Ensure Do not display network selection UI is set to Enabled'
  desc 'Ensure Do not display network selection UI is set to Enabled'
  tag 'cis-level-1', 'cis-18.8.25.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('DontDisplayNetworkSelectionUI ', :type_dword, '1') }
  end
end

# 18.8.25.3 (L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
control '18.8.25.3' do
  impact 1.0
  title 'Ensure Do not enumerate connected users on domain-joined computers is set to Enabled'
  desc 'Ensure Do not enumerate connected users on domain-joined computers is set to Enabled'
  tag 'cis-level-1', 'cis-18.8.25.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('DontEnumerateConnectedUsers ', :type_dword, '1') }
  end
end

# 18.8.25.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
control '18.8.25.4' do
  impact 1.0
  title 'Ensure Enumerate local users on domain-joined computers is set to Disabled'
  desc 'Ensure Enumerate local users on domain-joined computers is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.25.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('EnumerateLocalUsers ', :type_dword, '1') }
  end
end

# 18.8.25.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
control '18.8.25.5' do
  impact 1.0
  title 'Ensure Turn off app notifications on the lock screen is set to Enabled'
  desc 'Ensure Turn off app notifications on the lock screen is set to Enabled'
  tag 'cis-level-1', 'cis-18.8.25.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('DisableLockScreenAppNotifications ', :type_dword, '1') }
  end
end

# 18.8.25.6 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
control '18.8.25.6' do
  impact 1.0
  title 'Ensure Turn on convenience PIN sign-in is set to Disabled'
  desc 'Ensure Turn on convenience PIN sign-in is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.25.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('AllowDomainPINLogon ', :type_dword, '1') }
  end
end

# 18.8.25.1 (L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
control '18.8.25.1' do
  impact 1.0
  title 'Ensure Block user from showing account details on sign-in is set to Enabled'
  desc 'Ensure Block user from showing account details on sign-in is set to Enabled'
  tag 'cis-level-1', 'cis-18.8.25.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('BlockUserFromShowingAccountDetailsOnSignin ', :type_dword, '1') }
  end
end

# 18.8.26.1 (L1) Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'
control '18.8.26.1' do
  impact 1.0
  title 'Ensure Untrusted Font Blocking is set to Enabled: Block untrusted fonts and log events'
  desc 'Ensure Untrusted Font Blocking is set to Enabled: Block untrusted fonts and log events'
  tag 'cis-level-1', 'cis-18.8.26.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions') do
    it { should exist }
    it { should have_property_value('MitigationOptions_FontBocking ', :type_dword, '1') }
  end
end

# 18.8.31.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
control '18.8.31.1' do
  impact 1.0
  title 'Ensure Configure Offer Remote Assistance is set to Disabled'
  desc 'Ensure Configure Offer Remote Assistance is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.31.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should exist }
    it { should have_property_value('fAllowUnsolicited ', :type_dword, '1') }
  end
end

# 18.8.31.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
control '18.8.31.2' do
  impact 1.0
  title 'Ensure Configure Solicited Remote Assistance is set to Disabled'
  desc 'Ensure Configure Solicited Remote Assistance is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.31.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should exist }
    it { should have_property_value('fAllowToGetHelp ', :type_dword, '1') }
  end
end

# 18.8.32.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
control '18.8.32.1' do
  impact 1.0
  title 'Ensure Enable RPC Endpoint Mapper Client Authentication is set to Enabled (MS only)'
  desc 'Ensure Enable RPC Endpoint Mapper Client Authentication is set to Enabled (MS only)'
  tag 'cis-level-1', 'cis-18.8.32.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
    it { should exist }
    it { should have_property_value('EnableAuthEpResolution ', :type_dword, '1') }
  end
end
