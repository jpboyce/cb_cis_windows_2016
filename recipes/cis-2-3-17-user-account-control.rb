# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-17-user-account-control
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'FilterAdministratorToken', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.2 (L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'EnableUIADesktopToggle', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'ConsentPromptBehaviorAdmin', type: :dword, data: 2 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.4 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'ConsentPromptBehaviorUser', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.5 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'EnableInstallerDetection', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.6 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'EnableSecureUIAPaths', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.7 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'EnableLUA', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.8 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'PromptOnSecureDesktop', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.17.9 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'EnableVirtualization', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end
