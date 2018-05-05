#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-11-network-security

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
control '2.3.11.1' do
  impact 1.0
  title 'Ensure Network security: Allow Local System to use computer identity for NTLM is set to Enabled'
  desc 'Ensure Network security: Allow Local System to use computer identity for NTLM is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.11.1'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('UseMachineId ', :type_dword, '1') }
  end
end

# 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
control '2.3.11.2' do
  impact 1.0
  title 'Ensure Network security: Allow LocalSystem NULL session fallback is set to Disabled'
  desc 'Ensure Network security: Allow LocalSystem NULL session fallback is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.11.2'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    it { should have_property_value('AllowNullSessionFallback ', :type_dword, '1') }
  end
end

# 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
control '2.3.11.3' do
  impact 1.0
  title 'Ensure Network Security: Allow PKU2U authentication requests to this computer to use online identities is set to Disabled'
  desc 'Ensure Network Security: Allow PKU2U authentication requests to this computer to use online identities is set to Disabled'
  tag 'cis-level-1', 'cis-2.3.11.3'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\pku2u') do
    it { should exist }
    it { should have_property_value('AllowOnlineID ', :type_dword, '1') }
  end
end

# 2.3.11.4 (L1)  Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
control '2.3.11.4' do
  impact 1.0
  title ' Ensure Network security: Configure encryption types allowed for Kerberos is set to RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
  desc ' Ensure Network security: Configure encryption types allowed for Kerberos is set to RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
  tag 'cis-level-1', 'cis-2.3.11.4'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
    it { should exist }
    it { should have_property_value('SupportedEncryptionTypes ', :type_dword, '1') }
  end
end

# 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
control '2.3.11.5' do
  impact 1.0
  title 'Ensure Network security: Do not store LAN Manager hash value on next password change is set to Enabled'
  desc 'Ensure Network security: Do not store LAN Manager hash value on next password change is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.11.5'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('NoLMHash ', :type_dword, '1') }
  end
end

# 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
control '2.3.11.6' do
  impact 1.0
  title 'Ensure Network security: Force logoff when logon hours expire is set to Enabled'
  desc 'Ensure Network security: Force logoff when logon hours expire is set to Enabled'
  tag 'cis-level-1', 'cis-2.3.11.6'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    it { should have_property_value('EnableForcedLogOff ', :type_dword, '1') }
  end
end

# 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
control '2.3.11.7' do
  impact 1.0
  title 'Ensure Network security: LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM & NTLM'
  desc 'Ensure Network security: LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM & NTLM'
  tag 'cis-level-1', 'cis-2.3.11.7'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    it { should have_property_value('LmCompatibilityLevel ', :type_dword, '1') }
  end
end

# 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
control '2.3.11.8' do
  impact 1.0
  title 'Ensure Network security: LDAP client signing requirements is set to Negotiate signing or higher'
  desc 'Ensure Network security: LDAP client signing requirements is set to Negotiate signing or higher'
  tag 'cis-level-1', 'cis-2.3.11.8'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP') do
    it { should exist }
    it { should have_property_value('LDAPClientIntegrity ', :type_dword, '1') }
  end
end

# 2.3.11.9 (L1)  Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control '2.3.11.9' do
  impact 1.0
  title ' Ensure Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security, Require 128-bit encryption'
  desc ' Ensure Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security, Require 128-bit encryption'
  tag 'cis-level-1', 'cis-2.3.11.9'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    it { should have_property_value('NTLMMinClientSec ', :type_dword, '1') }
  end
end

# 2.3.11.10 (L1)  Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
control '2.3.11.10' do
  impact 1.0
  title ' Ensure Network security: Minimum session security for NTLM SSP based (including secure RPC) servers is set to Require NTLMv2 session security, Require 128-bit encryption'
  desc ' Ensure Network security: Minimum session security for NTLM SSP based (including secure RPC) servers is set to Require NTLMv2 session security, Require 128-bit encryption'
  tag 'cis-level-1', 'cis-2.3.11.10'
  ref 'CIS Windows 2016 RTM (Release 1607) v1.0.0', url: 'https://www.cisecurity.org/cis-benchmarks/'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    it { should have_property_value('NTLMMinServerSec ', :type_dword, '1') }
  end
end
