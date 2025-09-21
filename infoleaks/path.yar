rule windows_absolute_path : path
{
    meta:
        description = "Detects absolute Windows file paths"
        threat_level = 5
        in_the_wild = true
    
    strings:
        $windows_abs = /[a-zA-Z]:\\[a-z0-9_\-\+=]+(\\[a-z0-9_\-\+=]+)+/i
    
    condition:
        $windows_abs
}

rule windows_relative_path : path
{
    meta:
        description = "Detects relative Windows file paths"
        threat_level = 5
        in_the_wild = true    

    strings:
        $windows_rel = /(~[\\\/]|\.\/|\.\.\/|[a-z0-9_\-\+=]+(\\[a-z0-9_\-\+=]+)+)/i
    
    condition:
        $windows_rel
}

rule linux_absolute_path : path
{
    meta:
        description = "Detects absolute Linux file paths"
        threat_level = 5
        in_the_wild = true    

    strings:
        $linux_abs = /\/[a-z0-9_\-\+=]+(\/[a-z0-9_\-\+=]+)+/i
    
    condition:
        $linux_abs
}

rule linux_relative_path : path
{
    meta:
        description = "Detects relative Linux file paths"
        threat_level = 5
        in_the_wild = true    

    strings:
        $linux_rel = /(~[\/]|\.\/|\.\.\/|[a-z0-9_\-\+=]+(\/[a-z0-9_\-\+=]+)+)/i
    
    condition:
        $linux_rel
}
