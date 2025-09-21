rule cid : cid
{
    meta:
        description = "cid"
        threat_level = 5
        in_the_wild = true

    strings:
        $re = /\\b\d{17}(\d|x)|\d{15}\\b/

    condition:
        any of them
}