#!/usr/bin/tclsh

puts "Content-type: text/html; charset=iso-8559-1\n"
puts "<html>"
puts "<head><title>Environment</title></head>"
puts "<body>"
puts "<pre>"
foreach var [lsort -nocase [array names ::env]] {
    puts "$var = $::env($var)"
}
puts "</pre>"
puts "</body></html>"
