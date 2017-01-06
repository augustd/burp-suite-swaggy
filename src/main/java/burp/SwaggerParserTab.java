package burp;

import java.awt.*;
import java.util.ArrayList;

import javax.swing.*;

public class SwaggerParserTab implements ITab {

    JTabbedPane tabbedPane;
    private IBurpExtenderCallbacks callbacks;
    static int tabCount = 0;
    static int removedTabCount = 0;
    private java.util.List<SwaggerTab> tabs = new ArrayList<>();

    public SwaggerParserTab(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        tabbedPane = new JTabbedPane();

        callbacks.customizeUiComponent(tabbedPane);

        callbacks.addSuiteTab(SwaggerParserTab.this);
    }

    public SwaggerTab createTab(String request) {

        SwaggerTab swaggerTab = new SwaggerTab(callbacks, tabbedPane, request);
        tabbedPane.setSelectedIndex(tabCount - removedTabCount);
        tabCount++;
        
        tabs.add(swaggerTab);

        return swaggerTab;
    }

    @Override
    public String getTabCaption() {
        return "Swaggy";
    }

    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }

    public boolean isSwaggerMessage(byte[] message) {
        for (SwaggerTab tab : tabs) {
            if (tab.containsEntry(message)) return true;
        }
        return false;
    }
    
    public String getSwaggerJson(byte[] message) {
        for (SwaggerTab tab : tabs) {
            SwaggerEntry entry = tab.getEntry(message);
            if (entry != null) return entry.json;
        }
        return null;
    }
}
