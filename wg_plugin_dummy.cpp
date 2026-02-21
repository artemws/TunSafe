#include "tunsafe_wg_plugin.h"

class DummyPlugin : public TunsafePlugin {
public:
    DummyPlugin() {}
    virtual ~DummyPlugin() {}
};

extern "C"
TunsafePlugin* CreateTunsafePlugin(PluginDelegate*, WireguardProcessor*) {
    return new DummyPlugin();
}
