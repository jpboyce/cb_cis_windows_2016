# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-1-2-account-lockout-policy
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
# security_policy 'Account lockout duration' do
#  log_location "#{node['cb_cis_windows_2016']['secedit_template']['location']}\\Accout_Lockout_Policy.log"
#  policy_template "#{node['cb_cis_windows_2016']['secedit_template']['location']}\\Account_lockout_duration.inf"
#  database "#{node['cb_cis_windows_2016']['secedit_database']['location']}\\#{node['cb_cis_windows_2016']['secedit_database']['name']}"
#  action :configure
#  only_if { node.default['cb_cis_windows_2016']['cis_level_1'] = true }
# end

# 1.2.2 (L1)  Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
# security_policy 'Account lockout threshold' do
#  policy_template "#{node['cb_cis_windows_2016']['secedit_template']['location']}\\Account lockout threshold.inf}"
#  database "#{node['cb_cis_windows_2016']['secedit_database']['location']}\\#{['cb_cis_windows_2016']['secedit_database']['name']}"
#  action :configure
# end

# 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
# security_policy 'Reset account lockout counter after' do
#  policy_template "#{node['cb_cis_windows_2016']['secedit_template']['location']}\\Reset account lockout counter after.inf}"
#  database "#{node['cb_cis_windows_2016']['secedit_database']['location']}\\#{['cb_cis_windows_2016']['secedit_database']['name']}"
#  action :configure
# end
