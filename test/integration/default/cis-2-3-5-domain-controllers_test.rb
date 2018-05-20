#
# encoding: utf-8

# Inspec test for recipe cb_cis_windows_2016::cis-2-3-5-domain-controllers

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# 2.3.5.1 (L1) Ensure Domain controller: Allow server operators to schedule tasks is set to Disabled (DC only)
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa:SubmitControl

# 2.3.5.2 (L1) Ensure Domain controller: LDAP server signing requirements is set to Require signing (DC only)
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters:LDAPServ erIntegrity

# 2.3.5.3 (L1) Ensure Domain controller: Refuse machine account password changes is set to Disabled (DC only)
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:Refu sePasswordChange
