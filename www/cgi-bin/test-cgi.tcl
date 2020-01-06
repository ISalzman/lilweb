#!/usr/bin/tclsh

puts "Content-Type: text/plain\n"
puts "CGI/1.0 test script report:\n"
puts "argc is $::argc. argv is $::argv.\n"

set varlist {
    SERVER_SOFTWARE
    SERVER_NAME
    GATEWAY_INTERFACE
    SERVER_PROTOCOL
    SERVER_PORT
    REQUEST_METHOD
    PATH_INFO
    PATH_TRANSLATED
    DOCUMENT_ROOT
    SCRIPT_NAME
    QUERY_STRING
    REMOTE_HOST
    REMOTE_ADDR
    REMOTE_USER
    REMOTE_IDENT
    AUTH_TYPE
    CONTENT_TYPE
    CONTENT_LENGTH
    HTTP_HOST
    HTTP_ACCEPT
    HTTP_USER_AGENT
    HTTP_REFERER
}

foreach var $varlist {
    puts "$var = [expr {[info exists ::env($var)] ? $::env($var) : {}}]"
}
