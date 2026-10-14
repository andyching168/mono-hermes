package com.hermesmovil.app;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;
import com.hermesmovil.app.net.BoundedHttpPlugin;
import com.hermesmovil.app.oauth.OAuthLoopbackPlugin;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Local plugins must be registered before super.onCreate() builds the bridge.
        registerPlugin(BoundedHttpPlugin.class);
        registerPlugin(OAuthLoopbackPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
