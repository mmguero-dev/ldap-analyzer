# @TEST-EXEC: zeek -C -r $TRACES/ldap-delete.pcap %INPUT
# @TEST-EXEC: btest-diff ldap.log
