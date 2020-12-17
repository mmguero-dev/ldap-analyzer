# Bro::LDAP
=================================

#### This should be compatibile till Zeek 3.1.2.
> Also this repo is logging the response code and error for a BindRequest.

This package provides an analyzer for Lightweight Directory Access Protocol write operations.  The following operations will be written to ldap.log after running the analyzer:

* modifyRequest and modifyResponse
* modifyDNRequest and modifyDNResponse
* addRequest and addResponse
* deleteRequest and deleteResponse
* bindRequest and bindResponse

Additionally, the analyzer will deliver GSSAPI GSS-SPNEGO authentication data in LDAP bindRequests to the gssapi analyzer to be written to the Kerberos or NTLM logs.

## If using the analyzer as a local plugin:

* `$ git clone https://github.com/git-davi/ldap-analyzer.git`
* `$ cd ldap-analyzer`
* `$ ./configure --zeek-dist=/path/to/zeek && make`
* `$ export ZEEK_PLUGIN_PATH=/path/to/ldap-analyzer/build` or `$ make install`
* Check if plugin got loaded `$ zeek -N | grep LDAP` 
* Run it : `$ zeek -r your_ldap.pcap`


# TO DO:
* Testing script produces an error.  It attempts to access a non-existent file.
