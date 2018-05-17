# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-2-user-rights-assignment
#
# Copyright:: 2018, The Authors, All Rights Reserved.

security_policy 'Windows 10 CIS 2.2 - User Rights Assignment' do
  log_location "#{node['cb_cis_windows_2016']['secedit_template']['location']}\\User_Rights_Assignment.log"
  policy_template "#{node['cb_cis_windows_2016']['secedit_template']['location']}\\User_Rights_Assignment.inf"
  database "#{node['cb_cis_windows_2016']['secedit_database']['location']}\\#{node['cb_cis_windows_2016']['secedit_database']['name']}"
  action :configure
end


# 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.2 (L1) Configure 'Access this computer from the network'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.5 (L1)  Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.6 (L1) Configure 'Allow log on locally'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.7 (L1) Configure 'Allow log on through Remote Desktop Services'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.8 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.9 (L1)  Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.10 (L1)  Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.11 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.12 (L1) Ensure 'Create a token object' is set to 'No One'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.13 (L1)  Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.14 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.15 (L1) Configure 'Create symbolic links'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.16 (L1) Ensure 'Debug programs' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.17 (L1) Configure 'Deny access to this computer from the network'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.18 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.19 (L1) Ensure 'Deny log on as a service' to include 'Guests'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.20 (L1) Ensure 'Deny log on locally' to include 'Guests'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.21 (L1)  Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.22 (L1) Configure 'Enable computer and user accounts to be trusted for delegation'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.23 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.24 (L1)  Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.25 (L1) Configure 'Impersonate a client after authentication'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.26 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.27 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.28 (L1) Ensure 'Lock pages in memory' is set to 'No One'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.30 (L1) Configure 'Manage auditing and security log'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.35 (L1)  Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.36 (L1)  Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end

# 2.2.40 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
registry_key '' do
  values [{ name: '', type: :dword, data: 1 }]
  action :create
  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
end
