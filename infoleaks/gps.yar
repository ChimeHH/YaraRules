rule gps : gps
{
    meta:
        description = "gps"
        threat_level = 5
        in_the_wild = true

    strings:
        $xtag = /lat\=\"[+\-]?\d+(\.\d+)?\"[,\s]+lon\=\"[+\-]?\d+(\.\d+)?\"/
        $text = /N[+\-]?\d+(\.\d+){0,2}\s+W[+\-]?\d+(\.\d+){0,2}/

    condition:
        any of them
}