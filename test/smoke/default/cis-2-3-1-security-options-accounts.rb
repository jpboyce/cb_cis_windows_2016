# Require CSV to load the file
require 'csv'

cisList = CSV.read('../../../files/cis-windows-2016-registry.csv')

cisList.each do |i|
  if i[0] == '2.3.1'
  control 'cis-windows-2016-' + i[1] do
    impact 0.7
    title i[2]
    desc i[2]
    key = registry_key(i[4], i[3])
    describe key do
      its(i[4]) { should eq i[5] }
    end
  end
  end
end

    #puts i[1]
    #puts i[2]
    #puts i[3]
    #puts i[4]
   # puts i[5]
