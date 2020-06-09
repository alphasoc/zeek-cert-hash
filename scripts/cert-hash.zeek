module SSL;
export {
    redef record Info += {
        cert_hash: string &log &optional;
    };
}
hook ssl_finishing(c: connection) &priority=5
    {
    if ( c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 && c$ssl$cert_chain[0]?$x509 )
        {
        c$ssl$cert_hash = c$ssl$cert_chain[0]$sha1;
        }
    }