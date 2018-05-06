# Cookbook:: cb_cis_windows_2016
# Recipe:: default
#
# The MIT License (MIT)
#
# Copyright:: 2018, Jesse
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

windows_version = Chef::ReservedNames::Win32::Version.new

Chef::Log.warn('Starting checks...')
Chef::Log.warn("Platform is: #{node['platform']}")
Chef::Log.warn("Platform version is: #{node['platform_version']}")
Chef::Log.warn("Is this system running 2016?  #{windows_version.windows_server_2016?}")
Chef::Log.warn('Finished checks!')

include_recipe 'cb_cis_windows_2016::cis-1-1-password-policy'
# include_recipe 'cb_cis_windows_2016::cis-1-2-account-lockout-policy'
# include_recipe 'cb_cis_windows_2016::cis-2-2-user-rights-assignment'
# include_recipe 'cb_cis_windows_2016::cis-2-3-1-accounts'
# include_recipe 'cb_cis_windows_2016::cis-2-3-10-network-access'
# include_recipe 'cb_cis_windows_2016::cis-2-3-11-network-security'
# include_recipe 'cb_cis_windows_2016::cis-2-3-13-shutdown'
# include_recipe 'cb_cis_windows_2016::cis-2-3-15-system-objects'
# include_recipe 'cb_cis_windows_2016::cis-2-3-17-user-account-control'
# include_recipe 'cb_cis_windows_2016::cis-2-3-2-audit'
# include_recipe 'cb_cis_windows_2016::cis-2-3-4-devices'
# include_recipe 'cb_cis_windows_2016::cis-2-3-5-domain-controllers'
# include_recipe 'cb_cis_windows_2016::cis-2-3-6-domain-member'
# include_recipe 'cb_cis_windows_2016::cis-2-3-7-interactive-logon'
# include_recipe 'cb_cis_windows_2016::cis-2-3-8-microsoft-network-client'
# include_recipe 'cb_cis_windows_2016::cis-2-3-9-microsoft-network-server'
# include_recipe 'cb_cis_windows_2016::cis-9-1-domain-profile'
# include_recipe 'cb_cis_windows_2016::cis-9-2-private-profile'
# include_recipe 'cb_cis_windows_2016::cis-9-3-public-profile'
# include_recipe 'cb_cis_windows_2016::cis-17-1-account-logon'
# include_recipe 'cb_cis_windows_2016::cis-17-2-account-management'
# include_recipe 'cb_cis_windows_2016::cis-17-3-detailed-tracking'
# include_recipe 'cb_cis_windows_2016::cis-17-4-ds-access'
# include_recipe 'cb_cis_windows_2016::cis-17-5-logon-logoff'
# include_recipe 'cb_cis_windows_2016::cis-17-6-object-access'
# include_recipe 'cb_cis_windows_2016::cis-17-7-policy-change'
# include_recipe 'cb_cis_windows_2016::cis-17-8-privilege-use'
# include_recipe 'cb_cis_windows_2016::cis-17-9-system'
# include_recipe 'cb_cis_windows_2016::cis-18-1-control-panel'
# include_recipe 'cb_cis_windows_2016::cis-18-2-laps'
# include_recipe 'cb_cis_windows_2016::cis-18-3-mss'
# include_recipe 'cb_cis_windows_2016::cis-18-4-network'
# include_recipe 'cb_cis_windows_2016::cis-18-6-scm-pass-the-hash-mitigations'
# include_recipe 'cb_cis_windows_2016::cis-18-8-system'
# include_recipe 'cb_cis_windows_2016::cis-18-9-windows-components'
# include_recipe 'cb_cis_windows_2016::cis-19-1-admin-templates-user-control-panel'
# include_recipe 'cb_cis_windows_2016::cis-19-5-admin-templates-start-menu-and-taskbar'
# include_recipe 'cb_cis_windows_2016::cis-19-6-admin-templates-system'
# include_recipe 'cb_cis_windows_2016::cis-19-7-admin-templates-windows-components'
