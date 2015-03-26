! File: pdsh.factor
! Version: 0.1
! DRI: Dave Carlton
! Description: Another fine Factor file!
! Copyright (C) 2014 Dave Carlton.
! See http://factorcode.org/license.txt for BSD license.

USING: accessors continuations combinators help.markup help.syntax io
io.encodings.utf8 io.files ip-parser kernel libc locals make
math math.parser namespaces ping ping6 regexp sbufs sequences
sequences.strings sets splitting strings tools.dns.hosts prettyprint parser
ui.clipboards io.encodings.binary byte-arrays tools.dns.hosts ;

IN: playnet.pdsh

FROM: sets => set ;

SYMBOL: duplicate-hosts 
SYMBOL: hostNum
SYMBOL: hosts


: rename-duplicate ( record -- record )
    dup name>>  "_" append
    ! hostNum get  number>string append  "_" append
    ! hostNum inc
    over domain>> 
    first2 [ swap , , ] "" make  append
    >>name
    ;
    
: playnet.com ( records -- records )   [ domain>> "playnet.com" = ] filter ;
: wwiionline.com ( records -- records )   [ domain>> "wwiionline.com" = ] filter ;

FROM: namespaces => set ;
: rename-duplicates ( records -- records+duplicates )
    dup playnet.com  swap wwiionline.com
    append dup
    1 hostNum set
    duplicates
    [ rename-duplicate ] map
    append  members
    ;

: get-lines ( s -- s )   >sbuf "\r\n" split ;

:: (to-root) ( record -- root )
    record name>>
    "root" 
    record type>>
    record ip>>
    record active?>>
    <dns-record>
    ;
        
: to-root ( records -- records )  [ (to-root) ] map ;
: has-ip ( string record -- 'string )   ip>> append  " " append ;
: as-root ( string record -- 'string )   name>> ".root " append  append ;
: as-hostname ( string record -- 'string )   name>> append  " " append ;
: as-domain ( string record -- 'string )   dup name>>  swap domain>>  name+domain append  " " append ;
: is-active ( string record -- 'string )   [ "\t # " append ] dip  active?>> bool>string  append ;

:: gap-by-ip ( lines -- lines )
    V{ } :> collection!
    ! get the first ip in list, should already be sorted and lowest ip number
    lines first " " split first ipv4-aton :> previous!
    lines [
        " " split :> line
        line first ipv4-aton :> thisip  ! compare this ip with previous, if same or inc by 1, no break
        previous thisip =
        previous 1+ thisip =  or
        [ collection  line " " join suffix  collection! ]
        [ collection  " " suffix  line " " join suffix  collection! ]
        if
        line first ipv4-aton previous! ! set this ip for next compare  
        ] each
    collection 
    ;

: playnet-only ( records -- records )   { "66.28.224.128/25" "209.144.109.0/24" } networks-only ;
          
:: host-format ( records -- lines )
          records playnet-only
          [ :> record ""
            record has-ip
            record as-root
            record as-domain
            record as-hostname
            record is-active 
          ] map
          gap-by-ip
          ;

: only-active ( records -- records ) [ active?>> ] filter ;

FROM: ping => alive? ;

:: ping-hosts ( records -- records )
    "Testing hosts...\n" print
    records [
        :> record
        record name>>  record domain>>  name+domain " " append
        record ip>> append  ": " append
        record type>> {
            { "A" [ record ip>> alive? ] }
            { "AAAA" [ record ip>> alive6? ] }
        } case
        dup  record active?<<  
        bool>string  append print
        record
    ] map ;

: make-records ( lines -- records )
    { } swap
    [      
        " " split dup length 2 >
        [ dup second dnsTypes member?
          [ first3 <dns>  suffix ]
          [ drop ] if
        ]
        [ drop ] if
    ] each
    ;

: find-active-hosts ( hosts -- )
    ping-hosts 
    hosts set
    ;

: cleanup-file ( lines -- 'lines )
    squeeze-lines
    detab-lines
    squeeze-spaces
    trim-ends
    ;
          
: gather-records ( path -- records )
    utf8 file-lines
    cleanup-file
    strip-host-comment-lines
    strip-TTL-lines
    prepend-origin
    make-records
    A-records
    [ name>> R/ ^6[0-9].*/ matches? not ] filter
    rename-duplicates
    sort-by-ip
    ;        
    

: read-file ( path -- file )   utf8 file-lines ;
: write-file ( lines path -- )   utf8 set-file-lines ;
          
:: append-hosts ( lines -- newhosts )
   "### PLAYNET" :> tag
   lines [ tag = ] split-when  first
   tag suffix
   hosts get
   dup
   [ host-format append ]
   [ 2drop "No Hosts" print  -1 rethrow ]
   if
   ;

: new-hosts-lines ( path -- lines )   read-file append-hosts ;

CONSTANT: hosts-to-prune { "digicom" "edge" "edge1" "wwiiol19" "esxi1" "wwiiol20" "fw2" "mtc" "mto" "lenny" "nas" "awulf"} 
CONSTANT: ip-to-prune { "66.28.224.195" } 

: prune-hosts ( records -- `records )
    [ name>> hosts-to-prune member? not ] filter
    [ ip>> ip-to-prune member? not ] filter
    ;

: playnet-hosts ( -- records )
          hosts get
          only-active
          members
          playnet-only
          to-root
          prune-hosts
          [ dup name>> swap domain>> name+domain ] map
          ;
          
: write-hosts-file ( path -- )   dup  new-hosts-lines  swap write-file ;
: write-dsh-all ( -- )   playnet-hosts  "~/.dsh/all" utf8 set-file-lines ; 
: update-local-files ( -- )   "~/.ssh/hosts" write-hosts-file  write-dsh-all ;

: do-system ( string -- )
    dup system 0= [ ": ok" ] [ ": error" ] if  append print ;

: fetch-dns-files ( -- )
    "rsync -auz --exclude=\".git*\" ns1.root:/etc/bind/ ~/bind/" do-system
    "cat ~/bind/db.playnet ~/bind/db.wwiionline > ~/bind/playnet.dns" do-system
    ;

: get-dns-lines ( -- lines )   "~/bind/playnet.dns" gather-records ;
          
: process-hosts-file ( -- )
    get-dns-lines
    find-active-hosts
    update-local-files
    ;
          
: save-hosts ( path -- )   hosts get  [ unparse ] map  swap  utf8 set-file-lines ;
: read-hosts ( path -- )   parse-file  hosts set ;
: restore-hosts ( -- )  "~/bind/playnet.hosts" read-hosts ;
          
: create-new-hosts ( -- )
  fetch-dns-files  process-hosts-file  "~/bind/playnet.hosts" save-hosts
  ;

: remotes-local-file ( remote -- path )   ".hosts" append  "/tmp/" prepend ;
        
:: scp-from-remote ( remote -- string )          
          "scp " remote append  ":/etc/hosts " append
          remote remotes-local-file append
          ;
          
:: scp-to-remote ( remote -- string )          
          "scp " remote remotes-local-file append
          " " append
          remote append  ":/etc/hosts " append
          ;

: get-remote-hosts-file ( host -- )   scp-from-remote do-system ;
: put-remote-hosts-file ( host -- )   scp-to-remote do-system ;

:: update-remote-host ( host -- )
          host get-remote-hosts-file
          host remotes-local-file  write-hosts-file
          host put-remote-hosts-file
          ;
          
: update-remote-hosts ( -- )
          playnet-hosts
          [ update-remote-host ] each
          ;
          
: get-interfaces ( record -- string )
          (to-root) fqdn
          "ssh " prepend
          "ifconfig " do-system ;
          
          
: usage ( -- )
          "create-new-hosts" print
          "\tCreate new hosts file and pdsh all file from DNS files on Playnet" print
          ;
