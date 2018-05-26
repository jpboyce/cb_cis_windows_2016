# Cookbook:: cb_cis_windows_2016
# Recipe:: cis-2-3-11-network-security
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' do
  values [{ name: 'UseMachineId', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' do
  values [{ name: 'AllowNullSessionFallback', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' do
  values [{ name: 'AllowOnlineID', type: :dword, data: 0 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.4 (L1)  Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' do
  values [{ name: 'SupportedEncryptionTypes', type: :dword, data: 1 }]
  recursive true
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' do
  values [{ name: 'NoLMHash', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' do
  values [{ name: 'EnableForcedLogOff', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' do
  values [{ name: 'LmCompatibilityLevel', type: :dword, data: 5 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP' do
  values [{ name: 'LDAPClientIntegrity', type: :dword, data: 1 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.9 (L1)  Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' do
  values [{ name: 'NTLMMinClientSec', type: :dword, data: 537395200 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end

# 2.3.11.10 (L1)  Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' do
  values [{ name: 'NTLMMinServerSec', type: :dword, data: 537395200 }]
  action :create
  only_if { node['cb_cis_windows_2016']['cis_level_1'] }
end
