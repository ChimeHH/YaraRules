/*
Kernel configurations
*/

rule linux_kernel_alsr : linx_kernel equal {
    meta:
        author = "test"
        values = "1,2"
    strings:
        $alsr = /^kernel\.randomize_va_space\s*=\s*\S+/ nocase ascii        
    condition:
        any of "$*"
}

rule linux_kernel_exec_shield : linx_kernel equal {
    meta:
        author = "test"
        values = "1"
    strings:
        $a = /^kernel\.exec-shield\s*=\s*\S+/ nocase ascii      
    condition:
        any of "$*"
}
rule linux_kernel_icmp_broadcast : linx_kernel equal {
    meta:
        author = "test"
        values = "1"
    strings:
        $a = /^net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*\S+/ nocase ascii        
    condition:
        any of "$*"
}
rule linux_kernel_icmp_ignore_bogus : linx_kernel equal {
    meta:
        author = "test"
        values = "1"
    strings:
        $a = /^net\.ipv4\.icmp_ignore_bogus_error_messages\s*=\s*\S+/ nocase ascii  
    condition:
        any of "$*"
}

rule linux_kernel_ip_accept_source_route : linx_kernel equal {
    meta:
        author = "test"
        values = "1,2"
    strings: 
        $a = /^net\.ipv4\.conf\.all\.accept_source_route\s*=\s*\S+/ nocase ascii  
        $a = /^net\.ipv6\.conf\.all\.accept_source_route\s*=\s*\S+/ nocase ascii
    condition:
        any of "$*"
}

rule linux_kernel_ip_all_rp_filter : linx_kernel equal {
    meta:
        author = "test"
        values = "1,2"
    strings:
        $a = /^net\.ipv4\.conf\.all\.rp_filter\s*=\s*\S+/ nocase ascii  
        $a = /^net\.ipv6\.conf\.all\.rp_filter\s*=\s*\S+/ nocase ascii  
    condition:
        any of "$*"
}

rule linux_kernel_sysrq : linx_kernel equal {
    meta:
        author = "test"
        values = "0"
    strings:
        $a = /^net\.sysrq\s*=\s*\S+/ nocase ascii
    condition:
        any of "$*"
}