package ui;

import analyzer.PacketAnalyzerAbstract;
import app.Captor;
import jpcap.packet.Packet;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

class Table extends JComponent {

    private static final long serialVersionUID = 1L;

    private final TableModel model;
    final TableSorter sorter;
    private final JTable tableComponent;
    private final List<TableView> views = new ArrayList<TableView>();
    private final Captor captor;

    Table(TablePane parent, Captor captor) {
        this.captor = captor;
        model = new TableModel();
        sorter = new TableSorter(model);
        tableComponent = new JTable(sorter);
        sorter.addMouseListenerToHeaderInTable(tableComponent);

        tableComponent.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tableComponent.getSelectionModel().addListSelectionListener(parent);
        tableComponent.setDefaultRenderer(Object.class, new TableRenderer());
        JScrollPane tableView = new JScrollPane(tableComponent);

        setLayout(new BorderLayout());
        add(tableView, BorderLayout.CENTER);
    }

    void refreshPackets() {
        model.refresh();
        if (model.shouldAutoScroll()) {
            scrollToLastRow();
        }
    }

    void clear() {
        model.clear();
    }

    void setTableView(PacketAnalyzerAbstract analyzer, String name, boolean set) {
        if (set) {
            TableView view = new TableView(analyzer, name);
            if (!views.contains(view)) {
                views.add(view);
            }
        } else {
            views.remove(new TableView(analyzer, name));
        }
        model.structureChanged();
    }

    void setFilterText(String text) {
        model.setFilterText(text);
    }

    void setAutoScroll(boolean enabled) {
        model.setAutoScroll(enabled);
    }

    boolean isAutoScrollEnabled() {
        return model.shouldAutoScroll();
    }

    int getVisiblePacketCount() {
        return model.getRowCount();
    }

    Packet getPacketAtViewRow(int viewRow) {
        if (viewRow < 0 || viewRow >= sorter.getRowCount()) {
            return null;
        }
        int modelRow = sorter.getOriginalIndex(viewRow);
        return captor.getPacketAt(model.getPacketIndexAtModelRow(modelRow));
    }

    String[] getTableViewStatus() {
        String[] status = new String[views.size()];

        for (int i = 0; i < status.length; i++) {
            TableView view = views.get(i);
            status[i] = view.analyzer.getProtocolName() + ":" + view.valueName;
        }

        return status;
    }

    private void scrollToLastRow() {
        int rowCount = sorter.getRowCount();
        if (rowCount <= 0) {
            return;
        }
        int lastRow = rowCount - 1;
        Rectangle rect = tableComponent.getCellRect(lastRow, 0, true);
        tableComponent.scrollRectToVisible(rect);
    }

    static class TableView {
        final PacketAnalyzerAbstract analyzer;
        final String valueName;

        TableView(PacketAnalyzerAbstract analyzer, String name) {
            this.analyzer = analyzer;
            valueName = name;
        }

        public boolean equals(Object obj) {
            if (!(obj instanceof TableView)) {
                return false;
            }
            TableView other = (TableView) obj;
            return analyzer == other.analyzer && valueName.equals(other.valueName);
        }

        public int hashCode() {
            return analyzer.hashCode() * 31 + valueName.hashCode();
        }
    }

    class TableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private final List<Integer> visiblePacketIndexes = new ArrayList<Integer>();
        private final IdentityHashMap<Packet, Map<TableView, Object>> cellCache =
                new IdentityHashMap<Packet, Map<TableView, Object>>();
        private String filterText = "";
        private boolean autoScroll = true;
        private int knownPacketCount = 0;
        private int knownBufferVersion = -1;

        public int getRowCount() {
            return visiblePacketIndexes.size();
        }

        public int getColumnCount() {
            return views.size() + 1;
        }

        public Object getValueAt(int row, int column) {
            if (row < 0 || row >= visiblePacketIndexes.size()) {
                return "";
            }

            int packetIndex = visiblePacketIndexes.get(row).intValue();
            Packet packet = captor.getPacketAt(packetIndex);
            if (packet == null) {
                return "";
            }

            if (column == 0) {
                return Integer.valueOf(packetIndex);
            }

            TableView view = views.get(column - 1);
            return getDisplayValue(packet, view);
        }

        public boolean isCellEditable(int row, int column) {
            return false;
        }

        public String getColumnName(int column) {
            if (column == 0) {
                return "No.";
            }

            return views.get(column - 1).valueName;
        }

        int getPacketIndexAtModelRow(int modelRow) {
            if (modelRow < 0 || modelRow >= visiblePacketIndexes.size()) {
                return -1;
            }
            return visiblePacketIndexes.get(modelRow).intValue();
        }

        void setFilterText(String text) {
            String normalized = normalize(text);
            if (filterText.equals(normalized)) {
                return;
            }
            filterText = normalized;
            rebuildVisibleIndexes();
            fireTableDataChanged();
        }

        void setAutoScroll(boolean enabled) {
            autoScroll = enabled;
        }

        boolean shouldAutoScroll() {
            return autoScroll;
        }

        void clear() {
            knownPacketCount = 0;
            knownBufferVersion = captor.getBufferVersion();
            visiblePacketIndexes.clear();
            cellCache.clear();
            fireTableDataChanged();
        }

        void structureChanged() {
            cellCache.clear();
            rebuildVisibleIndexes();
            fireTableStructureChanged();
        }

        void refresh() {
            int currentCount = captor.getPacketCount();
            int currentVersion = captor.getBufferVersion();

            if (currentVersion == knownBufferVersion && currentCount == knownPacketCount) {
                return;
            }

            if (currentCount < knownPacketCount || currentVersion != knownBufferVersion + (currentCount - knownPacketCount)) {
                rebuildVisibleIndexes();
                fireTableDataChanged();
                return;
            }

            if (filterText.length() == 0) {
                int oldVisibleCount = visiblePacketIndexes.size();
                for (int i = knownPacketCount; i < currentCount; i++) {
                    visiblePacketIndexes.add(Integer.valueOf(i));
                }
                knownPacketCount = currentCount;
                knownBufferVersion = currentVersion;
                if (visiblePacketIndexes.size() != oldVisibleCount) {
                    fireTableRowsInserted(oldVisibleCount, visiblePacketIndexes.size() - 1);
                }
                return;
            }

            int oldVisibleCount = visiblePacketIndexes.size();
            for (int i = knownPacketCount; i < currentCount; i++) {
                Packet packet = captor.getPacketAt(i);
                if (packet != null && matches(packet)) {
                    visiblePacketIndexes.add(Integer.valueOf(i));
                }
            }
            knownPacketCount = currentCount;
            knownBufferVersion = currentVersion;
            if (visiblePacketIndexes.size() != oldVisibleCount) {
                fireTableDataChanged();
            }
        }

        private void rebuildVisibleIndexes() {
            visiblePacketIndexes.clear();
            cellCache.clear();
            int packetCount = captor.getPacketCount();
            for (int i = 0; i < packetCount; i++) {
                Packet packet = captor.getPacketAt(i);
                if (packet != null && matches(packet)) {
                    visiblePacketIndexes.add(Integer.valueOf(i));
                }
            }
            knownPacketCount = packetCount;
            knownBufferVersion = captor.getBufferVersion();
        }

        private boolean matches(Packet packet) {
            if (filterText.length() == 0) {
                return true;
            }
            if (normalize(packet.toString()).indexOf(filterText) >= 0) {
                return true;
            }
            for (int i = 0; i < views.size(); i++) {
                Object value = getDisplayValue(packet, views.get(i));
                if (value != null && normalize(String.valueOf(value)).indexOf(filterText) >= 0) {
                    return true;
                }
            }
            return false;
        }

        private Object getDisplayValue(Packet packet, TableView view) {
            Map<TableView, Object> packetCache = cellCache.get(packet);
            if (packetCache == null) {
                packetCache = new IdentityHashMap<TableView, Object>();
                cellCache.put(packet, packetCache);
            }
            if (packetCache.containsKey(view)) {
                return packetCache.get(view);
            }

            Object value = null;
            if (view.analyzer.isAnalyzable(packet)) {
                synchronized (view.analyzer) {
                    view.analyzer.analyze(packet);
                    value = view.analyzer.getValue(view.valueName);
                }
                if (value instanceof java.util.Vector) {
                    java.util.Vector vector = (java.util.Vector) value;
                    value = vector.size() > 0 ? vector.elementAt(0) : null;
                }
            }
            packetCache.put(view, value);
            return value;
        }

        private String normalize(String value) {
            if (value == null) {
                return "";
            }
            return value.trim().toLowerCase(Locale.ENGLISH);
        }
    }
}
