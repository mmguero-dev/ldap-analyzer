%extern{
#include <cstdlib>
#include <vector>
#include <string>
%}

%header{
zeek::IntrusivePtr<zeek::Val> build_ldap_res(LDAPResult *pdu);
%}

%code{

/*
Builds a, LDAPResult record
- messageID
- result of request
- error string
*/
zeek::IntrusivePtr<zeek::Val> build_ldap_res(LDAPResult *pdu)
	{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::LDAP::LDAPResultPDU);
	rv->Assign(0, asn1_integer_to_val(${pdu.messageID}, zeek::TYPE_INT));
	rv->Assign(1, zeek::val_mgr->Count(${pdu.result}));
	rv->Assign(2, asn1_octet_string_to_val(${pdu.error}));

	return rv;
	}

%}

refine connection LDAP_Conn += {
	%member{
		// Fields used to determine if the protocol has been confirmed or not.
		bool confirmed;
		bool orig_pdu;
		bool resp_pdu;

		zeek::analyzer::Analyzer *gssapi;
		zeek::analyzer::Analyzer *krb5;
	%}

	%init{
		confirmed = false;
		orig_pdu = false;
		resp_pdu = false;

		gssapi = 0;
		krb5 = 0;
	%}

	%cleanup{
		if ( gssapi )
			{
			gssapi->Done();
			delete gssapi;
			}

		if ( krb5 )
			{
			krb5->Done();
			delete krb5;
			}
	%}

	function SetPDU(is_orig: bool): bool
		%{
		if ( is_orig )
			orig_pdu = true;
		else
			resp_pdu = true;

		return true;
		%}

	function SetConfirmed(): bool
		%{
		confirmed = true;
		return true;
		%}

	function IsConfirmed(): bool
		%{
		return confirmed && orig_pdu && resp_pdu;
		%}

	function proc_ldap_mod_req(pdu: ModifyReqPDU): bool
		%{
		if ( ! ldap_mod_req )
			return false;

		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::LDAP::ModifyReqPDU);

		rv->Assign(0, asn1_integer_to_val(${pdu.messageID}, zeek::TYPE_INT));
		rv->Assign(1, asn1_octet_string_to_val(${pdu.object}));

		std::string fullStr;
		for ( auto it = ${pdu.mods}->begin(); it != ${pdu.mods}->end(); ++it )
			{
			if ( (*it)->mod_or_control_case_index() != 10 )
				continue;

			switch ( (*it)->mod()->op() )
				{
				case 0:
					fullStr.append("add ");
					break;
				case 1:
					fullStr.append("delete ");
					break;
				case 2:
					fullStr.append("replace ");
					break;
				default:
					fullStr.append("unknown ");
					break;
				};

				const u_char * typeStr = asn1_octet_string_to_val((*it)->mod()->type())->Bytes();
				fullStr.append((const char*)typeStr);
				fullStr.append(" ");

				const u_char * valStr = asn1_octet_string_to_val((*it)->mod()->val())->Bytes();
				fullStr.append((const char*)valStr);
				fullStr.append("/");
			}

		rv->Assign(2, zeek::make_intrusive<zeek::StringVal>(fullStr));

		zeek::BifEvent::enqueue_ldap_mod_req(zeek_analyzer(),
		                                     zeek_analyzer()->Conn(),
		                                     std::move(rv));

		return true;
		%}

	function proc_ldap_mod_res(pdu: ModifyResPDU): bool
		%{
		if ( ! ldap_mod_res )
			return false;

		zeek::BifEvent::enqueue_ldap_mod_res(zeek_analyzer(),
		                                      zeek_analyzer()->Conn(),
		                                      build_ldap_res(pdu->result()));

		return true;
		%}

	function proc_ldap_del_req(pdu: DeleteReqPDU): bool
		%{
		if ( ! ldap_del_req )
			return false;

		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::LDAP::DeleteReqPDU);
		rv->Assign(0, asn1_integer_to_val(${pdu.messageID}, zeek::TYPE_INT));
		rv->Assign(1, binpac::to_stringval(${pdu.request}));

		zeek::BifEvent::enqueue_ldap_del_req(zeek_analyzer(),
		                                      zeek_analyzer()->Conn(),
		                                      std::move(rv));

		return true;
		%}

	function proc_ldap_del_res(pdu: DeleteResPDU): bool
		%{
		if ( ! ldap_del_res )
			return false;

		zeek::BifEvent::enqueue_ldap_del_res(zeek_analyzer(),
		                                      zeek_analyzer()->Conn(),
		                                      build_ldap_res(pdu->result()));

		return true;
		%}

	function proc_ldap_add_req(pdu: AddReqPDU): bool
		%{
		if ( ! ldap_add_req )
			return false;

		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::LDAP::AddReqPDU);
		rv->Assign(0, asn1_integer_to_val(${pdu.messageID}, zeek::TYPE_INT));
		rv->Assign(1, asn1_octet_string_to_val(${pdu.entry}));

		std::string fullStr;
		auto atts = ${pdu.attributes.atts};
		for ( auto it = atts->begin(); it != atts->end(); ++it )
			{
			if ( (*it)->control_check_case_index() != 48 )
				continue;

			const u_char * typeStr = asn1_octet_string_to_val((*it)->att()->type())->Bytes();
			fullStr.append((const char*)typeStr);
			fullStr.append(" ");

			const u_char * valStr = asn1_octet_string_to_val((*it)->att()->val())->Bytes();
			fullStr.append((const char*)valStr);
			fullStr.append("/");
			}

		rv->Assign(2, zeek::make_intrusive<zeek::StringVal>(fullStr));

		zeek::BifEvent::enqueue_ldap_add_req(zeek_analyzer(),
		                                      zeek_analyzer()->Conn(),
		                                      std::move(rv));
		return true;
		%}

	function proc_ldap_add_res(pdu: AddResPDU): bool
		%{
		if ( ! ldap_add_res )
			return false;

		zeek::BifEvent::enqueue_ldap_add_res(zeek_analyzer(),
		                                      zeek_analyzer()->Conn(),
		                                      build_ldap_res(pdu->result()));

		return true;
		%}

	function proc_ldap_modDN_req(pdu: ModifyDNReqPDU): bool
		%{
		if ( ! ldap_modDN_req )
			return false;

		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::LDAP::ModifyDNReqPDU);
		rv->Assign(0, asn1_integer_to_val(${pdu.messageID}, zeek::TYPE_INT));
		rv->Assign(1, asn1_octet_string_to_val(${pdu.entry}));

		std::string fullStr;
		const u_char * newRDN = asn1_octet_string_to_val(${pdu.newrdn})->Bytes();
		const u_char * newSupe = binpac::to_stringval(${pdu.newSuperior})->Bytes();

		fullStr.append("newRDN: ");
		fullStr.append((const char*)newRDN);
		fullStr.append(" ");
		fullStr.append("newSuperior: ");
		fullStr.append((const char*)newSupe);
		fullStr.append(" ");
		fullStr.append("deleteold: ");

		uint8 deleteold = ${pdu.deleteoldrdn};
		switch ( deleteold )
			{
			case 0:
				fullStr.append("false ");
				break;
			default:
				fullStr.append("true ");
				break;
			}

		rv->Assign(2, zeek::make_intrusive<zeek::StringVal>(fullStr));

		zeek::BifEvent::enqueue_ldap_modDN_req(zeek_analyzer(),
		                                        zeek_analyzer()->Conn(),
		                                        std::move(rv));
		return true;
		%}

	function proc_ldap_modDN_res(pdu: ModifyDNResPDU): bool
		%{
		if ( ! ldap_modDN_res )
			return false;

		zeek::BifEvent::enqueue_ldap_modDN_res(zeek_analyzer(),
		                                        zeek_analyzer()->Conn(),
		                                        build_ldap_res(pdu->result()));

		return true;
		%}

	function proc_ldap_bind_req(pdu: BindReqPDU, is_orig: bool): bool
		%{
		if ( ldap_bind_req )
			{
			auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::LDAP::BindReqPDU);
			rv->Assign(0, asn1_integer_to_val(${pdu.messageID}, zeek::TYPE_INT));

			zeek::BifEvent::enqueue_ldap_bind_req(zeek_analyzer(),
			                                       zeek_analyzer()->Conn(),
			                                       std::move(rv));
			}

		if( memcmp("\x47\x53\x53\x2d\x53\x50\x4e\x45\x47\x4f",
		           asn1_octet_string_to_val(pdu->mechanism())->Bytes(),
		           10) == 0 )
			{
			// "GSS-SPNEGO"
			if ( ! gssapi )
				{
				gssapi = zeek::analyzer_mgr->InstantiateAnalyzer("GSSAPI", zeek_analyzer()->Conn());
				}
			if ( gssapi )
				{
				gssapi->DeliverStream(pdu->gssapi().length(), pdu->gssapi().begin(), is_orig);
				}
			}

		return true;
		%}

	function proc_ldap_bind_res(pdu: BindResPDU, is_orig: bool): bool
		%{
		zeek::BifEvent::enqueue_ldap_bind_res(zeek_analyzer(),
		                                       zeek_analyzer()->Conn(),
		                                       build_ldap_res(pdu->result()));

		if ( ${pdu.oid2}->encoding()->meta()->length() == 9 &&
		     (memcmp("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", asn1_oid_to_val(pdu->oid2())->Bytes(), pdu->oid2()->encoding()->meta()->length()) == 0 ||
		      memcmp("\x2a\x86\x48\x82\xf7\x12\x01\x02\x02", asn1_oid_to_val(pdu->oid2())->Bytes(), pdu->oid2()->encoding()->meta()->length()) == 0 ) )
			{
			// krb5 && ms-krb5
			if ( ! krb5 )
				{
				krb5 = zeek::analyzer_mgr->InstantiateAnalyzer("KRB", zeek_analyzer()->Conn());
				}

			if ( krb5 && memcmp("\x02\x00", pdu->blob().begin(), 2) == 0 )
				{
				// 0x0200 is an AP_REP
				krb5->DeliverPacket(pdu->blob().length()-2, pdu->blob().begin()+2, is_orig, 0, 0, 0);
				}
			}

		return true;
		%}
};


refine typeattr ModifyReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_mod_req(this);
};

refine typeattr ModifyResPDU += &let {
	proc: bool = $context.connection.proc_ldap_mod_res(this);
};

refine typeattr DeleteReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_del_req(this);
};

refine typeattr DeleteResPDU += &let {
	proc: bool = $context.connection.proc_ldap_del_res(this);
};

refine typeattr AddReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_add_req(this);
};

refine typeattr AddResPDU += &let {
	proc: bool = $context.connection.proc_ldap_add_res(this);
};

refine typeattr ModifyDNReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_modDN_req(this);
};

refine typeattr ModifyDNResPDU += &let {
	proc: bool = $context.connection.proc_ldap_modDN_res(this);
};

refine typeattr BindReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_bind_req(this, is_orig);
};

refine typeattr BindResPDU += &let {
	proc: bool = $context.connection.proc_ldap_bind_res(this, is_orig);
};
