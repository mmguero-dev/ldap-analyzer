
#ifndef ZEEK_PLUGIN_ZEEK_LDAP
#define ZEEK_PLUGIN_ZEEK_LDAP

#include <plugin/Plugin.h>

namespace plugin {
namespace Zeek_LDAP {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
