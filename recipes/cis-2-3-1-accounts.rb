# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-1-accounts
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'
powershell_script 'Disable Administrator Account' do
  guard_interpreter :powershell_script
  code <<-EOH
  $userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-500" ; Disable-LocalUser -SID $userSid
  EOH
  only_if '$userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-500" ; $userStatus = Get-LocalUser -SID $userSid ; $userStatus.Enabled'
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'NoConnectedUser', type: :dword, data: 3 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
powershell_script 'Disable Guest Account' do
  guard_interpreter :powershell_script
  code <<-EOH
  $userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-501" ; Disable-LocalUser -SID $userSid
  EOH
  only_if '$userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-501" ; $userStatus = Get-LocalUser -SID $userSid ; $userStatus.Enabled'
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' do
  values [{ name: 'LimitBlankPasswordUse', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'
powershell_script 'Rename Administrator Account' do
  guard_interpreter :powershell_script
  code <<-EOH
  $userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-500" ; Rename-LocalUser -SID $userSid -NewName #{node['cb_cis_windows_2016']['new_name_administrator']}
  EOH
  only_if '$userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-500" ; $userStatus = Get-LocalUser -SID $userSid ; $userStatus.Name -eq "Administrator"'
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.1.6 (L1) Configure 'Accounts: Rename Guest account'
powershell_script 'Rename Guest Account' do
  guard_interpreter :powershell_script
  code <<-EOH
  $userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-501" ; Rename-LocalUser -SID $userSid -NewName #{node['cb_cis_windows_2016']['new_name_guest']}
  EOH
  only_if '$userSid = "$((Get-LocalUser | Select-Object -First 1 | Select-Object SID).SID.AccountDomainSid.Value)-501" ; $userStatus = Get-LocalUser -SID $userSid ; $userStatus.Name -eq "Guest"'
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end
