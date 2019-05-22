name              'cb_cis_windows_2016'
maintainer        'Jesse Boyce'
maintainer_email  'jesse@jpboyce.org'
license           'MIT'
description       'Installs/Configures cb_cis_windows_2016'
long_description  IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version           '0.1.0'
supports          'windows'
depends           'windows', '~> 6.0.0'
depends           'windows-security-policy', '~> 0.3.7'
source_url        'https://github.com/jpboyce/cb_cis_windows_2016'
issues_url        'https://github.com/jpboyce/cb_cis_windows_2016/issues'
chef_version      '>= 12.14' if respond_to?(:chef_version)
