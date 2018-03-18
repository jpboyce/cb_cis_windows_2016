# Require CSV to load the file
require 'csv'

# Load CSV file
cisList = CSV.read('../files/cis-windows-2016-registry.csv')

# Select by section
result = cisList.select do |elem|
  elem[0] == '2.3.1'
end
puts result[0][0]
#cisList.each do |i|
#  if i[0] == '2.3.1'
#    puts i[1]
    #puts i[2]
    #puts i[3]
    #puts i[4]
   # puts i[5]
#  end
#end
