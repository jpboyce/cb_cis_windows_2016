# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-18-8-system
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' do
  values [{ name: 'ProcessCreationIncludeCmdLine_Enabled', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.12.1 (L1)  Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' do
  values [{ name: 'DriverLoadPolicy', type: :dword, data: 3 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.19.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{ name: 'NoBackgroundPolicy', type: :dword, data: 0 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.19.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{ name: 'NoGPOListChanges', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.19.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' do
  values [{ name: 'EnableCdp', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.19.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'DisableBkGndGroupPolicy', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.20.1.1 (L2) Ensure 'Turn off access to the Store' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' do
  values [{ name: 'NoUseStoreOpenWith', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.2 (L2) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers' do
  values [{ name: 'DisableWebPnPDownload', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.3 (L2) Ensure Turn off handwriting personalization data sharing is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC' do
  values [{ name: 'PreventHandwritingDataSharing', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.4 (L2) Ensure Turn off handwriting recognition error reporting is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' do
  values [{ name: 'PreventHandwritingErrorReports', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.5 (L2) Ensure Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' do
  values [{ name: 'ExitOnMSICW', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.6 (L2) Ensure Turn off Internet download for Web publishing and online ordering wizards is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{ name: 'NoWebServices', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.7 (L2) Ensure Turn off printing over HTTP is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers' do
  values [{ name: 'DisableHTTPPrinting', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.8 (L2) Ensure Turn off Registration if URL connection is referring to Microsoft.com is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' do
  values [{ name: 'NoRegistration', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.9 (L2) Ensure Turn off Search Companion content file updates is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion' do
  values [{ name: 'DisableContentFileUpdates', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.10 (L2) Ensure Turn off the "Order Prints" picture task is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{ name: 'NoOnlinePrintsWizard', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.11 (L2) Ensure Turn off the "Publish to Web" task for files and folders is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{ name: 'NoPublishingWizard', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.12 (L2) Ensure Turn off the Windows Messenger Customer Experience Improvement Program is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client' do
  values [{ name: 'CEIP', type: :dword, data: 2 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.13 (L2) Ensure Turn off Windows Customer Experience Improvement Program is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows' do
  values [{ name: 'CEIPEnable', type: :dword, data: 0 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.20.1.14 (L2) Ensure Turn off Windows Error Reporting is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' do
  values [{ name: 'Disabled', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.23.1 (L2) Ensure Support device authentication using certificate is set to Enabled: Automatic
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters' do
  values [{ name: 'DevicePKInitBehavior', type: :dword, data: 0 },
          { name: 'DevicePKInitEnabled', type: :dword, data: 1 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.24.1 (L2) Ensure Disallow copying of user input methods to the system account for sign-in is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International' do
  values [{ name: 'BlockUserInputMethodsForSignIn', type: :dword, data: 1 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.25.1 (L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' do
  values [{ name: 'BlockUserFromShowingAccountDetailsOnSignin', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.25.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' do
  values [{ name: 'DontDisplayNetworkSelectionUI', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.25.3 (L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' do
  values [{ name: 'DontEnumerateConnectedUsers', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.25.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' do
  values [{ name: 'EnumerateLocalUsers', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.25.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' do
  values [{ name: 'DisableLockScreenAppNotifications', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.25.6 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' do
  values [{ name: 'AllowDomainPINLogon', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.26.1 (L1) Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions' do
  values [{ name: 'MitigationOptions_FontBocking', type: :string, data: '1000000000000' }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.29.5.1 (L2) Ensure Allow network connectivity during connectedstandby (on battery) is set to Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9' do
  values [{ name: 'DCSettingIndex', type: :dword, data: 0 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.29.5.2 (L2) Ensure Allow network connectivity during connectedstandby (plugged in) is set to Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9' do
  values [{ name: 'ACSettingIndex', type: :dword, data: 0 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.29.5.3 (L2) Ensure Require a password when a computer wakes (on battery) is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51' do
  values [{ name: 'DCSettingIndex', type: :dword, data: 1 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.29.5.4 (L2) Ensure Require a password when a computer wakes (plugged in) is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51' do
  values [{ name: 'ACSettingIndex', type: :dword, data: 1 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.31.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{ name: 'fAllowUnsolicited', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.31.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{ name: 'fAllowToGetHelp', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.32.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' do
  values [{ name: 'EnableAuthEpResolution', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 18.8.32.2 (L2) Ensure Restrict Unauthenticated RPC clients is set to Enabled: Authenticated (MS only)
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' do
  values [{ name: 'RestrictRemoteClients', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.39.5.1 (L2) Ensure Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is set to Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' do
  values [{ name: 'DisableQueryRemoteServer', type: :dword, data: 0 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.39.11.1 (L2) Ensure Enable/Disable PerfTrack is set to Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b9654fc3-8781-88dd50a6299d}' do
  values [{ name: 'ScenarioExecutionEnabled', type: :dword, data: 0 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.41.1 (L2) Ensure Turn off the advertising ID is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo' do
  values [{ name: 'DisabledByGroupPolicy', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.44.1.1 (L2) Ensure Enable Windows NTP Client is set to Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' do
  values [{ name: 'Enabled', type: :dword, data: 1 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end

# 18.8.44.1.2 (L2) Ensure Enable Windows NTP Server is set to Disabled (MS only)
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_2'] }
end
