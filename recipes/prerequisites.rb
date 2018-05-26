# Cookbook:: cb_cis_windows_2016
# Recipe:: prerequisites
#
# Copyright:: 2018, The Authors, All Rights Reserved.

# Copy MSS ADMX file
cookbook_file 'C:\Windows\PolicyDefinitions\MSS-legacy.admx' do
  source 'MSS-legacy.admx'
  action :create
end

# Copy MSS ADML file
cookbook_file 'C:\Windows\PolicyDefinitions\en-US\MSS-legacy.adml' do
  source 'MSS-legacy.adml'
  action :create
end
