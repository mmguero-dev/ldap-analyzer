##! Implements base functionality for LDAP analysis.
##! Generates the ldap.log file.

module LDAP;

export {
    redef enum Log::ID += { LOG };


    type Info: record {
        ## Timestamp for when the event happened.
        ts:     time    &log;
        ## Unique ID for the connection.
        #uid:    string  &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:     conn_id &log;
		
        ## LDAP message
        messageID:  int &log;
        op:		string &log;
		
        # Will hold the value of the request.  This is usually built 
        # from a number of values from the request.  The end result is a 
        # string of all of the values.
        value: string &log;

        # Used for entry or object
        entry:	string &log;
		
        # Holds the integer value of the return code for a response.  
        # Whatever consumes this log will need to map the integer value 
        # to the code.
        result:		int &log;
        # Error string.  This is not the mapped result code.
        error:		string &log;
    };

    ## Event that can be handled to access the LDAP record as it is sent on
    ## to the logging framework.
    global log_ldap: event(rec: Info);
}

const ports = { 389/tcp };


redef likely_server_ports += { ports };

event zeek_init() &priority=5
    {
    Log::create_stream(LDAP::LOG, [$columns=Info, $ev=log_ldap, $path="ldap"]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_LDAP, ports);
    }

# Bind Request
event ldap_bind_req(c: connection, pdu : BindReqPDU) &priority=5
    {

    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "bindRequest";

    Log::write(LDAP::LOG, info);
    }
	
# Bind Response
event ldap_bind_res(c: connection, pdu : LDAP::LDAPResultPDU) &priority=5
    {

    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

	# LDAP
    info$messageID = pdu$messageID;
    info$op = "bindResponse";
    info$result = pdu$result;
    info$error = pdu$error;

    Log::write(LDAP::LOG, info);
    }

# Modify Request
event ldap_mod_req(c: connection, pdu : LDAP::ModifyReqPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "modifyRequest";
    info$entry = pdu$entry;
    info$value = pdu$value;

    Log::write(LDAP::LOG, info);
    }

# Modify Response
event ldap_mod_res(c: connection, pdu : LDAP::LDAPResultPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "modifyResponse";
    info$result = pdu$result;
    info$error = pdu$error;

    Log::write(LDAP::LOG, info);
    }


# Delete Request
event ldap_del_req(c: connection, pdu : LDAP::DeleteReqPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "delRequest";
    info$value = pdu$value;

    Log::write(LDAP::LOG, info);
    }
	
event ldap_del_res(c: connection, pdu : LDAP::LDAPResultPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "delResponse";
    info$result = pdu$result;
    info$error = pdu$error;

    Log::write(LDAP::LOG, info);
    }
	
# Add Request
event ldap_add_req(c: connection, pdu : LDAP::AddReqPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "addRequest";
    info$entry = pdu$entry;
    info$value = pdu$value;
       

    Log::write(LDAP::LOG, info);
    }
	
# Add Response
event ldap_add_res(c: connection, pdu : LDAP::LDAPResultPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "addResponse";
    info$result = pdu$result;
    info$error = pdu$error;

    Log::write(LDAP::LOG, info);
    }

# Modify DN Request
event ldap_modDN_req(c: connection, pdu : LDAP::ModifyDNReqPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "modDNRequest";
    info$entry = pdu$entry;
    info$value = pdu$value;

    Log::write(LDAP::LOG, info);
    }

# Modify DN Response
event ldap_modDN_res(c: connection, pdu : LDAP::LDAPResultPDU) &priority=5
    {
    local info: Info;
    info$ts  = network_time();
    info$id  = c$id;

    # LDAP
    info$messageID = pdu$messageID;
    info$op = "modDNResponse";
    info$result = pdu$result;
    info$error = pdu$error;

    Log::write(LDAP::LOG, info);
    }
