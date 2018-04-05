#
# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-18-9-windows-components
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 18.9.4.1 (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'

# 18.9.5.1 (L2) Ensure 'Let Windows apps *' is set to 'Enabled: Force Deny'

# 18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'

# 18.9.6.2 (L2) Ensure 'Block launching Windows Store apps with Windows Runtime API access from hosted content.' is set to 'Enabled'

# 18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'

# 18.9.8.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'

# 18.9.8.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'

# 18.9.10.1.1 (L1) Ensure 'Use enhanced anti-spoofing when available' is set to 'Enabled'

# 18.9.12.1 (L2) Ensure 'Allow Use of Camera' is set to 'Disabled'

# 18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'



# 18.9.14.1 (L1) Ensure 'Require pin for pairing' is set to 'Enabled'

# 18.9.15.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'

# 18.9.15.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'

# 18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]'

# 18.9.16.2 (L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'

# 18.9.16.3 (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'

# 18.9.16.4 (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'

# 18.9.26.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

# 18.9.26.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'

# 18.9.26.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

# 18.9.26.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'

# 18.9.26.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

# 18.9.26.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'

# 18.9.26.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

# 18.9.26.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'

# 18.9.30.2 (L1) Ensure 'Configure Windows SmartScreen' is set to 'Enabled'

# 18.9.30.3 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'

# 18.9.30.4 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'

# 18.9.30.5 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'

# 18.9.37.2 (L2) Ensure 'Turn off location' is set to 'Enabled'

# 18.9.41.1 (L2) Ensure 'Allow Extensions' is set to 'Disabled'

# 18.9.41.2 (L2) Ensure 'Allow InPrivate Browsing' is set to 'Disabled'

# 18.9.41.3 (L1) Ensure 'Configure cookies' is set to 'Enabled: Block only 3rd-party cookies' or higher

# 18.9.41.4 (L1) Ensure 'Configure Password Manager' is set to 'Disabled'

# 18.9.41.5 (L2) Ensure 'Configure Pop-up Blocker' is set to 'Enabled'

# 18.9.41.6 (L1) Ensure 'Configure search suggestions in Address bar' is set to 'Disabled'

# 18.9.41.7 (L1) Ensure 'Configure SmartScreen Filter' is set to 'Enabled'

# 18.9.41.8 (L2) Ensure 'Prevent access to the about:flags page in Microsoft Edge' is set to 'Enabled'

# 18.9.41.9 (L2) Ensure 'Prevent bypassing SmartScreen prompts for files' is set to 'Enabled'

# 18.9.41.10 (L2) Ensure 'Prevent bypassing SmartScreen prompts for sites' is set to 'Enabled'

# 18.9.41.11 (L2) Ensure 'Prevent using Localhost IP address for WebRTC' is set to 'Enabled'

# 18.9.47.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'

# 18.9.52.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'

# 18.9.52.3.2.1 (L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'

# 18.9.52.3.3.1 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'

# 18.9.52.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'

# 18.9.52.3.3.3 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'

# 18.9.52.3.3.4 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'

# 18.9.52.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'

# 18.9.52.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'

# 18.9.52.3.9.3 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'

# 18.9.52.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'

# 18.9.52.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'

# 18.9.52.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'

# 18.9.52.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'

# 18.9.53.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'

# 18.9.54.2 (L1) Ensure 'Allow Cortana' is set to 'Disabled'

# 18.9.54.3 (L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled'

# 18.9.54.4 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'

# 18.9.54.5 (L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'

# 18.9.59.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'

# 18.9.61.1 (L2) Ensure 'Disable all apps from Windows Store' is set to 'Enabled'

# 18.9.61.2 (L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'

# 18.9.61.3 (L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'

# 18.9.61.4 (L2) Ensure 'Turn off the Store application' is set to 'Enabled'

# 18.9.69.3.1 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'

# 18.9.69.8.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled'

# 18.9.73.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'

# 18.9.73.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'

# 18.9.74.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'

# 18.9.74.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'

# 18.9.74.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'

# 18.9.75.1 (L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'

# 18.9.84.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'

# 18.9.84.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'

# 18.9.86.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'

# 18.9.86.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'

# 18.9.86.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'

# 18.9.86.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'

# 18.9.86.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'

# 18.9.86.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'

# 18.9.86.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'

# 18.9.87.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'

# 18.9.90.1.1 (L1) Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days'

# 18.9.90.1.2 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'

# 18.9.90.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'

# 18.9.90.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'

# 18.9.90.4 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
