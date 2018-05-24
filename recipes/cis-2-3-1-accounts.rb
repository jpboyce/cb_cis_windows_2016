# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-1-accounts
#
# Copyright:: 2018, The Authors, All Rights Reserved.

script = '
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
    # The name change didnt work or something else went wrong
    return $false
  }
}
Function Set-LocalUserStatus {
  [CmdletBinding()]
  Param (
    [parameter(Mandatory=$true)][ValidateSet("500","501")][string]$userSidSuffix
  )
  # Combine SID Prefix with the suffix to get the full SID of the user
  $userSid = "$(Get-SidPrefix)-$($userSidSuffix)"
  # Try to disable the user
  try {
    Disable-LocalUser -SID $userSid -ErrorAction Stop
  }
  catch {
    $error[0].CategoryInfo.Reason
    exit 1
  }
  # Get user object
  try {
    $userNewState = Get-LocalUser -SID $userSid -ErrorAction Stop
  }
  catch {
    $error[0].CategoryInfo.Reason
    exit 1
  }
  if ($userNewState.Enabled -eq $false) {
    # State change was successful
    return $true
  } else {
    # State was not changed for some reason
    return $false
  }
}
REPLACEME
'


# 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'
# TODO
#admin_disable = script.sub('REPLACEME', 'Rename-LocalAdminOrGuest -userSidSuffix 500 -newName NotAdmin')
admin_disable = script.sub('REPLACEME', 'Set-LocalUserStatus -userSidSuffix 500')
powershell_script 'Disable Administrator Account' do
  guard_interpreter :powershell_script
  code admin_disable
  only_if '$userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-500" ; $userStatus = Get-LocalUser -SID $userSid ; $userStatus.Enabled'
end


# 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'NoConnectedUser', type: :dword, data: 3 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
guest_disable = script.sub('REPLACEME', 'Set-LocalUserStatus -userSidSuffix 501')
powershell_script 'Disable Guest Account' do
  guard_interpreter :powershell_script
  code guest_disable
  only_if '$userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-501" ; $userStatus = Get-LocalUser -SID $userSid ; $userStatus.Enabled'
end
=begin
# 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' do
  values [{ name: 'LimitBlankPasswordUse', type: :dword, data: 0 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'
# TODO

# 2.3.1.6 (L1) Configure 'Accounts: Rename guest account'
# TODO
=end
