rule phone : phone
{
    meta:
        description = "cid"
        threat_level = 5
        in_the_wild = true

    strings:
        $national = /\+\d[\d\s\-]{11, 18}\d/
        $local = /\d{11,20}/

    condition:
        any of them
}