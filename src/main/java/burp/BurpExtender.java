package burp;

import com.codemagi.burp.BaseExtender;

/**
 * Swaggy: A BurpSuite extension to parse Swagger web service definition files and produce HTTP requests
 * @author adetlefsen
 */
public class BurpExtender extends BaseExtender implements IBurpExtender, IMessageEditorTabFactory {

    public static final String TAB_NAME = "Swaggy";
    public static final String EXTENSION_NAME = "Swaggy";
    private static BurpExtender instance;
    private SwaggerParserTab parserTab;
    
    @Override
    protected void initialize() {
        extensionName = EXTENSION_NAME;
        
        parserTab = new SwaggerParserTab(callbacks);
        
        callbacks.registerContextMenuFactory(new Menu(callbacks, parserTab));
        
        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
        
        instance = this;
    }
    
    public static BurpExtender getInstance() {
        return instance;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new SwaggerSchemaTab(controller, callbacks);
    }

    public SwaggerParserTab getParserTab() {
        return parserTab;
    }
    
    
}
