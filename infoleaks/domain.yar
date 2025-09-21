/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule domain : domain {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $domain_regex = /\b([\w\-]+\.){1,3}[\w\-]{2,6}\b/ wide ascii
    condition:
        $domain_regex
}
