#!/bin/env tclsh

# Ideas taken from:
#   https://wiki.tcl-lang.org/page/DustMote
#   https://wiki.tcl-lang.org/page/Playing+CGI
#   https://wiki.tcl-lang.org/page/Embedded+TCL+Web+Server
#   https://wiki.tcl-lang.org/page/Dandelion

package require Tcl 8.5

namespace eval ::httpd {
    variable httpd
    variable mimetype
    variable status

    array set httpd {
        docroot     ~/public_html
        cgiroot     cgi-bin
        host        localhost
        port        8080
        limit       32768
        cgiuri      cgi-bin
        cgiext      {.tcl .cgi}
        default     index.html
        encoding    ISO-8859-1
    }

    array set mimetype {
        .txt    "text/plain"
        .htm    "text/html"
        .html   "text/html"
        .tml    "text/html"
        .css    "text/css"
        .csv    "text/csv"
        .gif    "image/gif"
        .png    "image/png"
        .bmp    "image/bmp"
        .jpg    "image/jpeg"
        .jpeg   "image/jpeg"
        .tif    "image/tiff"
        .tiff   "image/tiff"
        .ico    "image/x-icon"
        .mp3    "audio/mpeg"
        .mid    "audio/midi"
        .midi   "audio/midi"
        .ogg    "audio/ogg"
        .wav    "audio/x-wav"
        .wma    "audio/x-ms-wma"
        .mpg    "video/mpeg"
        .mpeg   "video/mpeg"
        .mp4    "video/mp4"
        .ogv    "video/ogg"
        .asf    "video/x-ms-asf"
        .avi    "video/x-msvideo"
        .wmv    "video/x-ms-wmv"
        .mov    "video/quicktime"
        .ps     "application/postscript"
        .js     "application/javascript"
        .json   "application/json"
        .xml    "application/xml"
        .xsl    "application/xml"
        .rtf    "application/rtf"
        .pdf    "application/pdf"
        .zip    "application/zip"
        .doc    "application/msword"
        .iso    "application/octet-stream"
        .dll    "application/octet-stream"
        .exe    "application/octet-stream"
        .tar    "application/x-tar"
        .gz     "application/x-gzip"
        .bz2    "application/x-bzip"
        .rar    "application/x-rar-compressed"
        .tcl    "application/x-tcl"
        .wiki   "application/x-fossil-wiki"
    }

    array set status {
        100 {Continue}
        101 {Switching Protocols}
        200 {OK}
        201 {Created}
        202 {Accepted}
        203 {Non-Authoritative Information}
        204 {No Content}
        205 {Reset Content}
        206 {Partial Content}
        300 {Multiple Choices}
        301 {Moved Permanently}
        302 {Found}
        303 {See Other}
        304 {Not Modified}
        305 {Use Proxy}
        307 {Temporary Redirect}
        400 {Bad Request}
        401 {Unauthorized}
        403 {Forbidden}
        404 {Not Found}
        405 {Method Not Allowed}
        406 {Not Acceptable}
        407 {Proxy Authentication Required}
        408 {Request Timeout}
        409 {Conflict}
        410 {Gone}
        411 {Length Required}
        412 {Precondition Failed}
        413 {Request Entity Too Large}
        414 {Request-URI Too Long}
        415 {Unsupported Media Type}
        416 {Requested Range Not Satisfiable}
        417 {Expectation Failed}
        500 {Internal Server Error}
        501 {Not Implemented}
        502 {Bad Gateway}
        503 {Service Unavailable}
        504 {Gateway Timeout}
        505 {HTTP Version Not Supported}
    }

    proc bgerror {err opt} {
        puts stderr "httpd error: $err"
        puts stderr "[dict get $opt -errorinfo]"
        return
    }

    proc decode {str} {
        # rewrite "+" back to space
        # protect \ from quoting another '\'
        set str [string map [list + { } "\\" "\\\\"] $str]

        # convert %HH to \uxxx, process the escapes, and convert from utf-8
        regsub -all -- {%([A-Fa-f0-9][A-Fa-f0-9])} $str {\\u00\1} str
        return [encoding convertfrom utf-8 [subst -novariables -nocommands $str]]
    }

    proc dateformat {time} {
        return [clock format $time -format {%a, %d %b %Y %T GMT} -timezone :UTC]
    }

    proc accept {sid ip port} {
        lassign [chan configure $sid -peername] addr host rport
        #puts stderr "Accepted connection from [lindex [split $host .] 0]"

        chan configure $sid -blocking off
        chan event $sid readable [namespace code [list serve $sid]]

        return
    }

    proc serve {sid} {
        variable httpd

        if {[chan pending input $sid] > $httpd(limit)} {
            deny $sid 413
            return
        }

        if {[catch {chan gets $sid line} err] || [chan eof $sid]} {
            catch {chan close $sid}
            return
        } elseif {[chan blocked $sid]} {
            return
        }
        chan event $sid readable {}
        #puts stderr $line

        if {[llength $line] != 3} {
            deny $sid 400
            return
        }

        lassign $line method uri version

        # Reject absolute uri
        if {[string index $uri 0] ne "/"} {
            deny $sid 400
            return
        }

        # Reject relative uri
        if {[string first {./} $uri] != -1} {
            deny $sid 404
            return
        }

        # Remove fragment
        set hash [string first # $uri]
        if {$hash != -1} {
            set uri [string range $uri 0 ${hash}-1]
        }

        if {$method ni [list GET POST HEAD]} {
            #puts stderr "Unsupported method '$method' from '[lindex [chan configure $sid -peername] 1]'"
            deny $sid 501
            return
        }

        set req [dict create method $method uri $uri version $version]
        chan event $sid readable [namespace code [list headers $sid $req {}]]

        return
    }

    proc headers {sid req field} {
        variable httpd

        if {[chan pending input $sid] > $httpd(limit)} {
            deny $sid 413
            return
        }

        if {[catch {chan gets $sid line} err] || [chan eof $sid]} {
            catch {chan close $sid}
            return
        } elseif {[chan blocked $sid]} {
            return
        }

        if {$line eq ""} {
            switch -exact -- [dict get $req method] {
                GET -
                HEAD {
                    chan event $sid readable {}
                    after 0 [namespace code [list respond $sid $req $field]]
                }
                POST {
                    if {! [dict exists $field content-length]} {
                        deny $sid 411
                        return
                    }
                    if {[dict get $field content-length] > $httpd(limit)} {
                        deny $sid 413
                        return
                    }
                    chan event $sid readable [namespace code [list body $sid $req $field {}]]
                }
            }

            return
        }

        if {[regexp {^([^:]+):\s*(.*)\s*$} $line -> key val]} {
            set key [string tolower $key]
            if {[dict exists $field $key]} {
                dict append field $key ,$val
            } else {
                dict set field $key $val
            }
        } elseif {[regexp {^\s+\S+} $line]} {
            dict append field [lindex [dict keys $field] end] " [string trim $line]"
        } else {
            deny $sid 400
            return
        }

        chan event $sid readable [namespace code [list headers $sid $req $field]]
        return
    }

    proc body {sid req field body} {
        variable httpd

        if {[chan pending input $sid] > $httpd(limit)} {
            deny $sid 413
            return
        }

        if {[catch {chan read -nonewline $sid} data] || [chan eof $sid]} {
            catch {chan close $sid}
            return
        }

        append body $data

        if {[string length $body] > $httpd(limit)} {
            deny $sid 413
            return
        }

        if {[chan blocked $sid]
                || [string length $body] < [dict get $field content-length]} {
            chan event $sid readable [namespace code [list body $sid $field $body]]
            return
        }

        chan event $sid readable {}
        after 0 [namespace code [list respond $sid $req $field $body]]

        return
    }

    proc respond {sid req field {body {}}} {
        variable httpd
        variable status
        variable mimetype

        if {[playcgi $sid $req $field $body]} {
            return
        }

        lassign [split [dict get $req uri] ?] name query
        set fpath [string trimleft [decode $name] /]
        set fpath [file normalize [file join $httpd(docroot) $fpath]]

        if {[file isdirectory $fpath]} {
            set fpath [file join $fpath $httpd(default)]

            if {! [file exists $fpath]} {
                deny $sid 403
                return
            }
        }
        #puts stderr $fpath

        if {! [file readable $fpath]} {
            deny $sid 404
            return
        }

        set ctype "text/plain"
        set ext [file extension $fpath]
        if {[info exists mimetype($ext)]} {
            set ctype $mimetype($ext)
        }
        if {[lindex [split $ctype /] 0] eq "text"} {
            append ctype "; charset=$httpd(encoding)"
        }

        if {[catch {
            cd [file normalize $httpd(docroot)]
            chan puts $sid "HTTP/1.1 200 $status(200)"
            chan puts $sid "Content-Type: $ctype"
            chan puts $sid "Content-Length: [file size $fpath]"
            chan puts $sid "Date: [dateformat [clock seconds]]"
            chan puts $sid "Last-Modified: [dateformat [file mtime $fpath]]"
            chan puts $sid "Connection: close\n"

            if {[dict get $req method] eq "HEAD"} {
                catch {chan close $sid}
                return
            }

            set fid [open $fpath r]
            chan configure $fid -translation binary
            chan configure $sid -translation binary
            chan copy $fid $sid -command [namespace code [list done $fid $sid]]
        } err]} {
            done $fid $sid 0 $err
            return
        }

        return
    }

    proc playcgi {sid req field body} {
        variable httpd

        lassign [split [dict get $req uri] ?] name query
        lassign [chan configure $sid -peername] raddr rhost rport

        if {[regexp "^$httpd(cgiuri)\[^/\]+(/|$)" $name]} {
            regexp "^($httpd(cgiuri)\[^/\]+)(/.+)?$" $name -> script info
            set root [file join $httpd(docroot) $httpd(cgiroot)]
            set fpath [regsub "^$httpd(cgiuri)" [decode $script] {}]
        } elseif {[regexp "/\[^/\]+(?:[join $httpd(cgiext) |])(/|$)" $name]} {
            regexp "^(/(?:.+?/)?\[^/\]+(?:[join $httpd(cgiext) |]))(/.+)?$" $name -> script info
            set root $httpd(docroot)
            set fpath [decode $script]
        } else {
            return 0
        }

        set fpath [file normalize [file join $root [string trimleft $fpath /]]]

        if {! [file readable $fpath]} {
            deny $sid 404
            return 1
        }

        if {[catch {
            set fid [open $fpath r]
            chan gets $fid line
            chan close $fid
            #puts stderr $line
        } err]} {
            catch {chan close $fid}
            deny $sid 500
            return 1
        }

        if {[string range $line 0 1] ne "#!"} {
            return 0
        }

        # Setup environment
        foreach envvar [array names ::env] {
            if {$envvar ni [list PATH LD_LIBRARY_PATH TZ HOME COMSPEC SYSTEMROOT SYSTEMDRIVE TEMP TMP]} {
                unset ::env($envvar)
            }
        }
        if {[dict exists $field content-type]} {
            set ::env(CONTENT_TYPE) [dict get $field content-type]
            set field [dict remove $field content-type]
        }
        if {[dict exists $field content-length]} {
            set ::env(CONTENT_LENGTH) [dict get $field content-length]
            set field [dict remove $field content-length]
        }
        if {! [dict exists $field host]} {
            set ::env(HTTP_HOST) "$httpd(host)"
            if {$httpd(port) != 80} {
                append ::env(HTTP_HOST) ":$httpd(port)"
            }
        }
        dict for {key val} $field {
            set envvar HTTP_[string map {- _} [string toupper $key]]
            set ::env($envvar) $val
        }
        set ::env(GATEWAY_INTERFACE) "CGI/1.1"
        set ::env(SERVER_PROTOCOL) "HTTP/1.1"
        set ::env(SERVER_NAME) $httpd(host)
        set ::env(SERVER_PORT) $httpd(port)
        set ::env(REQUEST_URI) [dict get $req uri]
        set ::env(REQUEST_METHOD) [dict get $req method]
        set ::env(QUERY_STRING) $query
        set ::env(SCRIPT_NAME) [decode $script]
        set ::env(PATH_INFO) [decode $info]
        set ::env(REMOTE_ADDR) $raddr
        set ::env(REMOTE_HOST) $rhost
        set ::env(REMOTE_PORT) $rport

        # Construct command-line
        set cmd [string range $line 2 end]
        lappend cmd [file tail $fpath]
        if {[dict get $req method] eq "POST"} {
            lappend cmd <<$body
        }

        if {[catch {
            cd [file dirname $fpath]
            set pipe [open "|$cmd" r]
        } err]} {
            #puts stderr $err
            catch {chan close $pipe}
            deny $sid 500
            return 1
        }

        # Handle Non-Parsed Headers CGI script
        if {[regexp {^nph-} [file tail $fpath]]} {
            chan configure $pipe -translation binary
            chan configure $sid -translation binary
            chan copy $pipe $sid -command [namespace code [list done $pipe $sid]]
        } else {
            chan configure $pipe -blocking off
            chan event $pipe readable [namespace code [list respondcgi $sid $pipe]]
        }

        return 1
    }

    proc respondcgi {sid pipe} {
        variable httpd
        variable status

        # Determine how to respond by processing first line only
        if {[catch {chan gets $pipe line} err] || [chan eof $pipe]} {
            catch {chan close $pipe}
            deny $sid 500
            return
        } elseif {[chan blocked $pipe]} {
            return
        }
        chan event $pipe readable {}

        set code 200
        if {[regexp {^Location:\s*(.*)\s*$} $line -> location]} {
            set code 302
        } elseif {[regexp {^Status:\s*(\d{3})\s+(.*)\s*$} $line -> code text]} {
            set line "X-$line"
        } elseif {[string first : $line] == -1} {
            set line "\n$line"
        }

        if {[catch {
            chan puts $sid "HTTP/1.1 $code $status($code)"
            chan puts $sid "Connection: close"
            chan puts $sid $line
            chan configure $pipe -translation binary
            chan configure $sid -translation binary
            chan copy $pipe $sid -command [namespace code [list done $pipe $sid]]
        } err]} {
            done $pipe $sid 0 $err
            return
        }

        return
    }

    proc done {fid sid bytes {err {}}} {
        if {$err ne ""} {
            puts stderr $err
        }

        catch {
            chan close $fid
            chan close $sid
        }

        return
    }

    proc deny {sid code} {
        variable status
        variable mimetype

        set body "<html><head><title>$status($code)</title></head><body><h1>$code: $status($code)</h1></body></html>"
        catch {
            chan puts $sid "HTTP/1.1 $code $status($code)"
            chan puts $sid "Date: [dateformat [clock seconds]]"
            chan puts $sid "Content-Type: $mimetype(.html)"
            chan puts $sid "Content-Length: [string bytelength $body]"
            chan puts $sid "Connection: close\n"
            chan puts $sid "$body"
            chan close $sid
        }

        return
    }

    proc start {args} {
        variable httpd
        array set httpd $args

        set myaddr {}
        if {$httpd(host) ne ""} {
            set myaddr [list -myaddr $httpd(host)]
        }

        if {[string index $httpd(cgiuri) 0] ne "/"} {
            set httpd(cgiuri) "/$httpd(cgiuri)"
        }
        if {[string index $httpd(cgiuri) end] ne "/"} {
            append httpd(cgiuri) /
        }

        if {[catch {
            set sid [socket -server [namespace code [list accept]] {*}$myaddr $httpd(port)]
            chan close stdin
        } err]} {
            catch {chan close $sid}
            error $err
        }

        puts stderr "Server ready on $httpd(host):$httpd(port)"
        return $sid
    }
}

interp bgerror {} ::httpd::bgerror

#set host [info hostname]
set host localhost

#set sid [::httpd::start host $host]
if {[catch {::httpd::start host $host} sid]} {
    puts stderr "httpd error: $sid"
    exit 1
}

vwait ::forever

catch {chan close $sid}
exit 0
