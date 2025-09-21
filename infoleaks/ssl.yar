
rule private_key : ssl  
{  
    meta:  
        author = "Chime Lab"  
        description = "This rule finds private keys, such as PEM-encoded private keys."  
    
    strings:  
        $a = /(^|\n)-{3,5}BEGIN ([A-Z]{2,10} )?PRIVATE KEY-{3,5}[0-9a-zA-Z+=\/\r\n]{128,2600}-{3,5}END ([A-Z]{2,10} )?PRIVATE KEY-{3,5}/ nocase  
    
    condition:
        $a  
}

rule public_key : ssl  
{  
    meta:  
        author = "Chime Lab"  
        description = "This rule finds public key"  
    
    strings:  
        $a = /(^|\n)-{3,5}BEGIN ([A-Z]{2,10} )?PUBLIC KEY( BLOCK)?-{3,5}[0-9a-zA-Z+=\/\r\n]{128,2600}-{3,5}END ([A-Z]{2,10} )?PUBLIC KEY( BLOCK)?-{3,5}/ nocase  

    condition:  
        $a  
}  

rule public_certificate : ssl  
{  
    meta:  
        author = "Chime Lab"  
        description = "This rule finds public certificate"  
    
    strings:  
        $a = /(^|\n)-{3,5}BEGIN ([A-Z]{2,10} )?CERTIFICATE( REQUEST)?-{3,5}[0-9a-zA-Z+=\/\r\n]{32,2600}-{3,5}END ([A-Z]{2,10} )?CERTIFICATE( REQUEST)?-{3,5}/ nocase  

    condition:  
        $a  
}  

rule x509_crl : ssl  
{  
    meta:  
        author = "Chime Lab"  
        description = "This rule finds x509 crl"  
    
    strings:  
        $a = /(^|\n)-{3,5}BEGIN X509 CRL-{3,5}[0-9a-zA-Z+=\/\r\n]{128,2600}-{3,5}END X509 CRL-{3,5}/ nocase  

    condition:  
        $a  
}  

rule ssh_public_key : ssl  
{  
    meta:  
        author = "Chime Lab"  
        description = "This rule finds open ssh public key"  
    
    strings:  
        $a = /(^|\n)ssh-[a-z0-9]+ +[A-Za-z0-9+\/]+={0,2}/ nocase  

    condition:  
        $a  
}  

rule ecdsa_public_key : ssl  
{  
    meta:  
        author = "Chime Lab"  
        description = "This rule finds ecdsa public key"  
    
    strings:  
        $a = /(^|\n)ecdsa(-[a-z0-9]+){1,2} +[A-Za-z0-9+\/]+={0,2}/ nocase  

    condition:  
        $a  
}