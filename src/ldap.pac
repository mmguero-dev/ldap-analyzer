# Analyzer for Protocol analyzer for LDAP implementations, tested on MS Active Directory

%include binpac.pac
%include zeek.pac

%extern{
	#include "analyzer/Manager.h"
	#include "analyzer/Analyzer.h"
	#include "types.bif.h"
	#include "events.bif.h"
%}

analyzer LDAP withcontext {
	connection: LDAP_Conn;
	flow:       LDAP_Flow;
};

# Our connection consists of two flows, one in each direction.
connection LDAP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = LDAP_Flow(true);
	downflow = LDAP_Flow(false);
};

# Checks for whether or not message is encapsulated in a SASL buffer
type LDAP_TCP(is_orig: bool) = record {
	initial : ASN1EncodingMeta;
	body    : case initial.tag of {
		# GSSAPI header before LDAP message
		0x00 -> before : LDAP_SASL(is_orig);
		# GSSAPI header within LDAP message
		0x30 -> within : Common_PDU(is_orig);
	};
} &byteorder=littleendian;

# Consumes SASL Header if present
type LDAP_SASL(is_orig : bool) = record {
	len          : uint16;
	header       : bytestring &length = 28;
	message_meta : ASN1SequenceMeta;
	seq_check    : case message_meta.encoding.tag of {
		0x30    -> pdu : Common_PDU(is_orig);
		default -> unk : UnknownOp(message_meta.encoding.tag);
	};
};

%include ldap-protocol.pac

# Now we define the flow:
flow LDAP_Flow(is_orig: bool) {
	#flowunit = LDAP_TCP(is_orig) withcontext(connection, this);
	datagram = LDAP_TCP(is_orig) withcontext(connection, this);
};

%include ldap-analyzer.pac
