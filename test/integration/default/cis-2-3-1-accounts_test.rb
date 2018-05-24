#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-1-accounts

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

script = <<-EOH
# Get SID Prefix
Function Get-SidPrefix {
  try {
    $userSid = (Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID
  }
  catch {
    $error[0].CategoryInfo.Reason
    exit 1
  }

  $sidPrefix = ($userSid.AccountDomainSid.Value)
  return $sidPrefix
}
Function Get-LocalUserNameStatus {
  # Return true if the user name of the provided SID matches the username also provided
  Param (
    [string]$userSidSuffix,
    [string]$userName
  )
  # Combine SID Prefix with the suffix to get the full SID of the user
  $userSid = "$(Get-SidPrefix)-$($userSidSuffix)"

  # Do some try...catch to elegantly handle failure
  try {
    $user = Get-LocalUser -SID $userSid -ErrorAction Stop
  }
  catch {
    $error[0].CategoryInfo.Reason
    exit 1
  }

  if ($user.name -eq $userName) {
    # The user names match
    return $true
  } else {
    return $false
  }
}
Function Get-LocalUserStatus {
  # Return true if the user is enabled
  Param (
    [string]$userSidSuffix
  )
  # Combine SID Prefix with the suffix to get the full SID of the user
  $userSid = "$(Get-SidPrefix)-$($userSidSuffix)"

  try {
    $user = Get-LocalUser -SID $userSid -ErrorAction Stop
  }
  catch {
    $error[0].CategoryInfo.Reason
    exit 1
  }

  if ($user.Enabled -eq $true) {
    # The user is enabled
    return $true
  } else {
    return $false
  }
}
Function Rename-LocalAdminOrGuest {
  Param(
    [string]$userSidSuffix,
    [string]$newName
  )
  # Combine SID Prefix with the suffix to get the full SID of the user
  $userSid = "$(Get-SidPrefix)-$($userSidSuffix)"

  try {
    Rename-LocalUser -SID $userSid -NewName $newName
  }
  catch {
    $error[0].CategoryInfo.Reason
    exit 1
  }
  try {
    $userNewName = Get-LocalUser -SID $userSid
  }
  catch {
    $error[0].CategoryInfo.Reason
    exit 1
  }

  if ($userNewName.name -eq $newName) {
    # Actual new name is the name we specified, so success!
    return $true
  } else {
    # The name change didn't work or something else went wrong
    return $false
  }
}
REPLACEME
EOH

# 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'
control '2.3.1.1' do
  impact 1.0
  title 'Ensure Accounts: Administrator account status is set to Disabled'
  desc 'Ensure Accounts: Administrator account status is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.1.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/powershell/
  admin_status_check = script.sub('REPLACEME', 'Get-LocalUserStatus -userSidSuffix 500')
  describe powershell(admin_status_check) do
    its('stdout') { should eq "False\r\n" }
    its('stderr') { should eq '' }
  end
end

# 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
control '2.3.1.2' do
  impact 1.0
  title 'Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts'
  desc 'Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts'
  tag 'cis-level-1', 'cis-2.3.1.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    it { should have_property_value('NoConnectedUser', :type_dword, '3') }
  end
end

# 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
control '2.3.1.3' do
  impact 1.0
  title 'Ensure Accounts: Guest account status is set to Disabled'
  desc 'Ensure Accounts: Guest account status is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.1.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/powershell/
  guest_status_check = script.sub('REPLACEME', 'Get-LocalUserStatus -userSidSuffix 501')
  describe powershell(guest_status_check) do
    its('stdout') { should eq "False\r\n" }
    its('stderr') { should eq '' }
  end
end

# 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
control '2.3.1.4' do
  impact 1.0
  title 'Ensure Accounts: Limit local account use of blank passwords to console logon only is set to Enabled'
  desc 'Ensure Accounts: Limit local account use of blank passwords to console logon only is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.1.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('LimitBlankPasswordUse', :type_dword, '1') }
  end
end

# 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'
control '2.3.1.5' do
  impact 1.0
  title 'Configure Accounts: Rename administrator account'
  desc 'Configure Accounts: Rename administrator account'
  tag 'cis-level-1', 'cis-2.3.1.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/powershell/
  admin_name_check = script.sub('REPLACEME', 'Get-LocalUserNameStatus -userSidSuffix 500 -username Administrator')
  describe powershell(admin_name_check) do
    its('stdout') { should eq "False\r\n" }
    its('stderr') { should eq '' }
  end
end

# 2.3.1.6 (L1) Configure 'Accounts: Rename guest account'
control '2.3.1.6' do
  impact 1.0
  title 'Configure Accounts: Rename guest account'
  desc 'Configure Accounts: Rename guest account'
  tag 'cis-level-1', 'cis-2.3.1.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  # http://inspec.io/docs/reference/resources/powershell/
  guest_name_check = script.sub('REPLACEME', 'Get-LocalUserNameStatus -userSidSuffix 501 -username Guest')
  describe powershell(guest_name_check) do
    its('stdout') { should eq "False\r\n" }
    its('stderr') { should eq '' }
  end
end
