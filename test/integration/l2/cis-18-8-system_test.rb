#
# encoding: utf-8

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
    it { should have_property_value('ProcessCreationIncludeCmdLine_Enabled', :type_dword, 0) }
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
    it { should have_property_value('DriverLoadPolicy', :type_dword, 3) }
  end
end

# 18.8.19.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
control '18.8.19.2' do
  impact 1.0
  title 'Ensure Configure registry policy processing: Do not apply during periodic background processing is set to Enabled: FALSE'
  desc 'Ensure Configure registry policy processing: Do not apply during periodic background processing is set to Enabled: FALSE'
  tag 'cis-level-1', 'cis-18.8.19.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should exist }
    it { should have_property_value('NoBackgroundPolicy', :type_dword, 0) }
  end
end

# 18.8.19.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
control '18.8.19.3' do
  impact 1.0
  title 'Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE'
  desc 'Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE'
  tag 'cis-level-1', 'cis-18.8.19.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should exist }
    it { should have_property_value('NoGPOListChanges', :type_dword, 0) }
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
    it { should have_property_value('EnableCdp', :type_dword, 0) }
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
    it { should have_property_value('DisableBkGndGroupPolicy', :type_dword, 0) }
  end
end

# 18.8.20.1.1 (L2) Ensure 'Turn off access to the Store' is set to 'Enabled'
control '18.8.20.1.1' do
  impact 1.0
  title 'Ensure Turn off access to the Store is set to Enabled'
  desc 'Ensure Turn off access to the Store is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    it { should exist }
    it { should have_property_value('NoUseStoreOpenWith', :type_dword, 1) }
  end
end

# 18.8.20.1.2 (L2) Ensure Turn off downloading of print drivers over HTTP is set to Enabled
control '18.8.20.1.2' do
  impact 1.0
  title 'Ensure Turn off downloading of print drivers over HTTP is set to Enabled'
  desc 'Ensure Turn off downloading of print drivers over HTTP is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    it { should exist }
    it { should have_property_value('DisableWebPnPDownload', :type_dword, 1) }
  end
end

# 18.8.20.1.3 (L2) Ensure Turn off handwriting personalization data sharing is set to Enabled
control '18.8.20.1.3' do
  impact 1.0
  title 'Ensure Turn off handwriting personalization data sharing is set to Enabled'
  desc 'Ensure Turn off handwriting personalization data sharing is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC') do
    it { should exist }
    it { should have_property_value('PreventHandwritingDataSharing', :type_dword, 1) }
  end
end

# 18.8.20.1.4 (L2) Ensure Turn off handwriting recognition error reporting is set to Enabled
control '18.8.20.1.4' do
  impact 1.0
  title 'Ensure Turn off handwriting recognition error reporting is set to Enabled'
  desc 'Ensure Turn off handwriting recognition error reporting is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports') do
    it { should exist }
    it { should have_property_value('PreventHandwritingErrorReports', :type_dword, 1) }
  end
end

# 18.8.20.1.5 (L2) Ensure Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled
control '18.8.20.1.5' do
  impact 1.0
  title 'Ensure Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled'
  desc 'Ensure Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard') do
    it { should exist }
    it { should have_property_value('ExitOnMSICW', :type_dword, 1) }
  end
end

# 18.8.20.1.6 (L2) Ensure Turn off Internet download for Web publishing and online ordering wizards is set to Enabled
control '18.8.20.1.6' do
  impact 1.0
  title 'Ensure Turn off Internet download for Web publishing and online ordering wizards is set to Enabled'
  desc 'Ensure Turn off Internet download for Web publishing and online ordering wizards is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should exist }
    it { should have_property_value('NoWebServices', :type_dword, 1) }
  end
end

# 18.8.20.1.7 (L2) Ensure Turn off printing over HTTP is set to Enabled
control '18.8.20.1.7' do
  impact 1.0
  title 'Ensure Turn off printing over HTTP is set to Enabled'
  desc 'Ensure Turn off printing over HTTP is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    it { should exist }
    it { should have_property_value('DisableHTTPPrinting', :type_dword, 1) }
  end
end

# 18.8.20.1.8 (L2) Ensure Turn off Registration if URL connection is referring to Microsoft.com is set to Enabled
control '18.8.20.1.8' do
  impact 1.0
  title 'Ensure Turn off Registration if URL connection is referring to Microsoft.com is set to Enabled'
  desc 'Ensure Turn off Registration if URL connection is referring to Microsoft.com is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control') do
    it { should exist }
    it { should have_property_value('NoRegistration', :type_dword, 1) }
  end
end

# 18.8.20.1.9 (L2) Ensure Turn off Search Companion content file updates is set to Enabled
control '18.8.20.1.9' do
  impact 1.0
  title 'Ensure Turn off Search Companion content file updates is set to Enabled'
  desc 'Ensure Turn off Search Companion content file updates is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion') do
    it { should exist }
    it { should have_property_value('DisableContentFileUpdates', :type_dword, 1) }
  end
end

# 18.8.20.1.10 (L2) Ensure Turn off the "Order Prints" picture task is set to Enabled
control '18.8.20.1.10' do
  impact 1.0
  title 'Ensure Turn off the "Order Prints" picture task is set to Enabled'
  desc 'Ensure Turn off the "Order Prints" picture task is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.10'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should exist }
    it { should have_property_value('NoOnlinePrintsWizard', :type_dword, 1) }
  end
end

# 18.8.20.1.11 (L2) Ensure Turn off the "Publish to Web" task for files and folders is set to Enabled
control '18.8.20.1.11' do
  impact 1.0
  title 'Ensure Turn off the "Publish to Web" task for files and folders is set to Enabled'
  desc 'Ensure Turn off the "Publish to Web" task for files and folders is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.11'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should exist }
    it { should have_property_value('NoPublishingWizard', :type_dword, 1) }
  end
end

# 18.8.20.1.12 (L2) Ensure Turn off the Windows Messenger Customer Experience Improvement Program is set to Enabled
control '18.8.20.1.12' do
  impact 1.0
  title 'Ensure Turn off the Windows Messenger Customer Experience Improvement Program is set to Enabled'
  desc 'Ensure Turn off the Windows Messenger Customer Experience Improvement Program is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.12'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client') do
    it { should exist }
    it { should have_property_value('CEIP', :type_dword, 2) }
  end
end

# 18.8.20.1.13 (L2) Ensure Turn off Windows Customer Experience Improvement Program is set to Enabled
control '18.8.20.1.13' do
  impact 1.0
  title 'Ensure Turn off Windows Customer Experience Improvement Program is set to Enabled'
  desc 'Ensure Turn off Windows Customer Experience Improvement Program is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.13'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows') do
    it { should exist }
    it { should have_property_value('CEIPEnable', :type_dword, 0) }
  end
end

# 18.8.20.1.14 (L2) Ensure Turn off Windows Error Reporting is set to Enabled
control '18.8.20.1.14' do
  impact 1.0
  title 'Ensure Turn off Windows Error Reporting is set to Enabled'
  desc 'Ensure Turn off Windows Error Reporting is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.20.1.14'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting') do
    it { should exist }
    it { should have_property_value('Disabled', :type_dword, 1) }
  end
end

# 18.8.23.1 (L2) Ensure Support device authentication using certificate is set to Enabled: Automatic
control '18.8.23.1' do
  impact 1.0
  title 'Ensure Support device authentication using certificate is set to Enabled: Automatic'
  desc 'Ensure Support device authentication using certificate is set to Enabled: Automatic'
  tag 'cis-level-2', 'cis-18.8.23.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters') do
    it { should exist }
    it { should have_property_value('DevicePKInitBehavior', :type_dword, 0) }
    it { should have_property_value('DevicePKInitEnabled', :type_dword, 1) }
  end
end

# 18.8.24.1 (L2) Ensure Disallow copying of user input methods to the system account for sign-in is set to Enabled
control '18.8.24.1' do
  impact 1.0
  title 'Ensure Disallow copying of user input methods to the system account for sign-in is set to Enabled'
  desc 'Ensure Disallow copying of user input methods to the system account for sign-in is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.24.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International') do
    it { should exist }
    it { should have_property_value('BlockUserInputMethodsForSignIn', :type_dword, 1) }
  end
end

# 18.8.25.1 (L1) Ensure Block user from showing account details on sign-in is set to Enabled
control '18.8.25.1' do
  impact 1.0
  title 'Ensure Block user from showing account details on sign-in is set to Enabled'
  desc 'Ensure Block user from showing account details on sign-in is set to Enabled'
  tag 'cis-level-1', 'cis-18.8.25.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('BlockUserFromShowingAccountDetailsOnSignin', :type_dword, 1) }
  end
end

# 18.8.25.2 (L1) Ensure Do not display network selection UI is set to Enabled
control '18.8.25.2' do
  impact 1.0
  title 'Ensure Do not display network selection UI is set to Enabled'
  desc 'Ensure Do not display network selection UI is set to Enabled'
  tag 'cis-level-1', 'cis-18.8.25.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should exist }
    it { should have_property_value('DontDisplayNetworkSelectionUI', :type_dword, 1) }
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
    it { should have_property_value('DontEnumerateConnectedUsers', :type_dword, 1) }
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
    it { should have_property_value('EnumerateLocalUsers', :type_dword, 0) }
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
    it { should have_property_value('DisableLockScreenAppNotifications', :type_dword, 1) }
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
    it { should have_property_value('AllowDomainPINLogon', :type_dword, 0) }
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
    it { should have_property_value('MitigationOptions_FontBocking', :type_string, '1000000000000') }
  end
end

# 18.8.29.5.1 (L2) Ensure Allow network connectivity during connectedstandby (on battery) is set to Disabled
control '18.8.29.5.1' do
  impact 1.0
  title 'Ensure Allow network connectivity during connectedstandby (on battery) is set to Disabled'
  desc 'Ensure Allow network connectivity during connectedstandby (on battery) is set to Disabled'
  tag 'cis-level-2', 'cis-18.8.29.5.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9') do
    it { should exist }
    it { should have_property_value('DCSettingIndex', :type_dword, 0) }
  end
end

# 18.8.29.5.2 (L2) Ensure Allow network connectivity during connectedstandby (plugged in) is set to Disabled
control '18.8.29.5.2' do
  impact 1.0
  title 'Ensure Allow network connectivity during connectedstandby (plugged in) is set to Disabled'
  desc 'Ensure Allow network connectivity during connectedstandby (plugged in) is set to Disabled'
  tag 'cis-level-2', 'cis-18.8.29.5.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9') do
    it { should exist }
    it { should have_property_value('ACSettingIndex', :type_dword, 0) }
  end
end

# 18.8.29.5.3 (L2) Ensure Require a password when a computer wakes (on battery) is set to Enabled
control '18.8.29.5.3' do
  impact 1.0
  title 'Ensure Require a password when a computer wakes (on battery) is set to Enabled'
  desc 'Ensure Require a password when a computer wakes (on battery) is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.29.5.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51') do
    it { should exist }
    it { should have_property_value('DCSettingIndex', :type_dword, 1) }
  end
end

# 18.8.29.5.4 (L2) Ensure Require a password when a computer wakes (plugged in) is set to Enabled
control '18.8.29.5.4' do
  impact 1.0
  title 'Ensure Require a password when a computer wakes (on battery) is set to Enabled'
  desc 'Ensure Require a password when a computer wakes (on battery) is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.29.5.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51') do
    it { should exist }
    it { should have_property_value('ACSettingIndex', :type_dword, 1) }
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
    it { should have_property_value('fAllowUnsolicited', :type_dword, 0) }
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
    it { should have_property_value('fAllowToGetHelp', :type_dword, 0) }
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
    it { should have_property_value('EnableAuthEpResolution', :type_dword, 1) }
  end
end

# 18.8.32.2 (L2) Ensure Restrict Unauthenticated RPC clients is set to Enabled: Authenticated (MS only)
control '18.8.32.2' do
  impact 1.0
  title 'Ensure Restrict Unauthenticated RPC clients is set to Enabled: Authenticated (MS only)'
  desc 'Ensure Restrict Unauthenticated RPC clients is set to Enabled: Authenticated (MS only)'
  tag 'cis-level-2', 'cis-18.8.32.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
    it { should exist }
    it { should have_property_value('RestrictRemoteClients', :type_dword, 1) }
  end
end

# 18.8.39.5.1 (L2) Ensure Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is set to Disabled
control '18.8.39.5.1' do
  impact 1.0
  title 'Ensure Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is set to Disabled'
  desc 'Ensure Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is set to Disabled'
  tag 'cis-level-2', 'cis-18.8.39.5.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy') do
    it { should exist }
    it { should have_property_value('DisableQueryRemoteServer', :type_dword, 0) }
  end
end

# 18.8.39.11.1 (L2) Ensure Enable/Disable PerfTrack is set to Disabled
control '18.8.39.11.1' do
  impact 1.0
  title 'Ensure Enable/Disable PerfTrack is set to Disabled'
  desc 'Ensure Enable/Disable PerfTrack is set to Disabled'
  tag 'cis-level-1', 'cis-18.8.39.11.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b9654fc3-8781-88dd50a6299d}') do
    it { should exist }
    it { should have_property_value('ScenarioExecutionEnabled', :type_dword, 0) }
  end
end

# 18.8.41.1 (L2) Ensure Turn off the advertising ID is set to Enabled
control '18.8.41.1' do
  impact 1.0
  title 'Ensure Turn off the advertising ID is set to Enabled'
  desc 'Ensure Turn off the advertising ID is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.41.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo') do
    it { should exist }
    it { should have_property_value('DisabledByGroupPolicy', :type_dword, 1) }
  end
end

# 18.8.44.1.1 (L2) Ensure Enable Windows NTP Client is set to Enabled
control '18.8.44.1.1' do
  impact 1.0
  title 'Ensure Enable Windows NTP Client is set to Enabled'
  desc 'Ensure Enable Windows NTP Client is set to Enabled'
  tag 'cis-level-2', 'cis-18.8.44.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient') do
    it { should exist }
    it { should have_property_value('Enabled', :type_dword, 1) }
  end
end

# 18.8.44.1.2 (L2) Ensure Enable Windows NTP Server is set to Disabled (MS only)
control '18.8.44.1.2' do
  impact 1.0
  title 'Ensure Enable Windows NTP Server is set to Disabled (MS only)'
  desc 'Ensure Enable Windows NTP Server is set to Disabled (MS only)'
  tag 'cis-level-1', 'cis-18.8.44.1.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer') do
    it { should exist }
    it { should have_property_value('Enabled', :type_dword, 0) }
  end
end
