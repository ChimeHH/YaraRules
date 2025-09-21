/*
Kernel configurations
*/

rule sshd_port : sshd space {
    meta:
        author = "test"
        values = "22"
    strings:
        $a = /^Port\s+\S+/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_login_grace_time : sshd space {
    meta:
        author = "test"
        audit = "$time_range(30, )"
    strings:
        $a = /^PermitRootLogin\s+\S+/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_permit_root_login : sshd space {
    meta:
        author = "test"
    strings:
        $a = /^StrictModes\s+no/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_max_auth_tries : sshd space {
    meta:
        author = "test"
        audit = "$int_range(0, 6)"
    strings:
        $a = /^MaxAuthTries\s+\S+/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_max_sessions : sshd space {
    meta:
        author = "test"
        audit = "$int_range(0, 10)"
    strings:
        $a = /^MaxSessions\s+\S+/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_permit_root_login : sshd space {
    meta:
        author = "test"
    strings:
        $a = /^PermitEmptyPasswords\s+yes/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_permit_tunnel : sshd space {
    meta:
        author = "test"
    strings:
        $a = /^PermitTunnel\s+yes/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_permit_chroot : sshd space {
    meta:
        author = "test"
        values = "none"
    strings:
        $a = /^ChrootDirectory\s+\S+/ nocase ascii        
    condition:
        any of "$*"
}

rule sshd_ignore_rhosts : sshd space {
    meta:
        author = "test"
        description = "Don't read the user's ~/.rhosts and ~/.shosts files"
    strings:
        $a = /^IgnoreRhosts\s+no/ nocase ascii        
    condition:
        any of "$*"
}

