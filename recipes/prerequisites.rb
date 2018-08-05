# Cookbook:: cb_cis_windows_2016
# Recipe:: prerequisites
#
# Copyright:: 2018, The Authors, All Rights Reserved.
=begin
# Copy MSS ADMX file
cookbook_file 'C:\Windows\PolicyDefinitions\MSS-legacy.admx' do
  source 'MSS-legacy.admx'
  action :create
  only_if { node['cb_cis_windows_2016']['copy_mss'] }
end

# Copy MSS ADML file
cookbook_file 'C:\Windows\PolicyDefinitions\en-US\MSS-legacy.adml' do
  source 'MSS-legacy.adml'
  action :create
  only_if { node['cb_cis_windows_2016']['copy_mss'] }
end

#cookbook_file 'c:\users\vagrant\desktop\Wireshark-win64-2.6.1.exe' do
#source 'Wireshark-win64-2.6.1.exe.zip'
#action :create
#end
=end
