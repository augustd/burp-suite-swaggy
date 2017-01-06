package burp;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class SwaggerTab extends AbstractTableModel implements IMessageEditorController {

    private final List<SwaggerEntry> entries = new ArrayList<>();
    private SwaggerTable swaggerTable;
    private EachRowEditor rowEditor;
    private IMessageEditor requestViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    JSplitPane splitPane;
    JTabbedPane tabbedPane;
	
	private final IBurpExtenderCallbacks callbacks;

    public SwaggerTab(final IBurpExtenderCallbacks callbacks, JTabbedPane tabbedPane, String request) {
		this.callbacks = callbacks;
        this.tabbedPane = tabbedPane;
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        swaggerTable = new SwaggerTable(this);
        swaggerTable.setAutoCreateRowSorter(true);

        rowEditor = new EachRowEditor(swaggerTable);
        JScrollPane scrollPane = new JScrollPane(swaggerTable);

        splitPane.setLeftComponent(scrollPane);

        JTabbedPane tabs = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(this, false);
        tabs.addTab("Request", requestViewer.getComponent());
        splitPane.setTopComponent(scrollPane);
        splitPane.setBottomComponent(tabs);
        tabbedPane.add(request, splitPane);
        tabbedPane.setTabComponentAt(SwaggerParserTab.tabCount - SwaggerParserTab.removedTabCount, new ButtonTabComponent(tabbedPane));

    }

    public void addEntry(SwaggerEntry entry) {
        synchronized (entries) {
            int row = entries.size();
            entries.add(entry);
            fireTableRowsInserted(row, row);
            UIManager.put("tabbedPane.selected",
                    new javax.swing.plaf.ColorUIResource(Color.RED));
        }
    }
    
    public boolean containsEntry(byte[] message) {
        for (SwaggerEntry entry : entries) {
            if (message == entry.request) return true;
        }
        
        return false;
    }
    
    public SwaggerEntry getEntry(byte[] message) {
        for (SwaggerEntry entry : entries) {
            if (message == entry.request) return entry;
        }
        
        return null;
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "Operation";
            case 1:
                return "Path";
            case 2:
                return "Description";
            default:
                return "";
        }
    }

    @Override
    public Class getColumnClass(int columnIndex) {
		return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        
        SwaggerEntry swaggerEntry = entries.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return swaggerEntry.operationName;
            case 1:
                return swaggerEntry.path;
            case 2:
                return swaggerEntry.endpoints;
            default:
                return "";
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col >= 2;
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    private class SwaggerTable extends JTable {

        public SwaggerTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {

            SwaggerEntry swaggerEntry = entries.get(super.convertRowIndexToModel(row));
            requestViewer.setMessage(swaggerEntry.request, true);
            currentlyDisplayedItem = swaggerEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }

        private boolean painted;

        @Override
        public void paint(Graphics g) {
            super.paint(g);

            if (!painted) {
                painted = true;
                splitPane.setResizeWeight(.30);
                splitPane.setDividerLocation(0.30);
            }
        }
    }

 }
