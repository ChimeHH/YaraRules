rule email : email
{
    meta:
        description = "email"
        threat_level = 5
        in_the_wild = true

    strings:
        $re = /\\b[_0-9a-z][_0-9a-z\.\-]{0,64}@([_0-9a-z\-]+\.){1,3}[_0-9a-z\-]+\\b/i

    condition:
        $re
}