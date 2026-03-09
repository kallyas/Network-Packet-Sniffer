/*This class shows the pane i.e when clicked on a check box in the protocol menu they will be displayed
 *
 *
 */
package ui;

import analyzer.PacketAnalyzerAbstract;
import app.Captor;
import app.NetPackSniff;
import app.PacketAnalyzerLoader;
import jpcap.packet.Packet;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.StringTokenizer;

class TablePane extends JPanel implements ActionListener, ListSelectionListener {
    private static final String AUTO_SCROLL_KEY = "TableAutoScroll";

    Table table;
    TableTree tree;
    TableTextArea text;
    Captor captor;
    PacketAnalyzerAbstract[] analyzers;
    JTextField filterField;
    JLabel filterStatusLabel;
    JCheckBox autoScrollCheck;

    JMenu[] tableViewMenu = new JMenu[4];

    TablePane(Captor captor) {
        this.captor = captor;
        table = new Table(this, captor);
        tree = new TableTree();
        text = new TableTextArea();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane splitPane2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setTopComponent(table);
        splitPane2.setTopComponent(tree);
        splitPane2.setBottomComponent(new JScrollPane(text));
        splitPane.setBottomComponent(splitPane2);
        splitPane.setDividerLocation(200);
        splitPane2.setDividerLocation(200);

        tableViewMenu[0] = new JMenu("Datalink Layer");
        tableViewMenu[1] = new JMenu("Network Layer");
        tableViewMenu[2] = new JMenu("Transport Layer");
        tableViewMenu[3] = new JMenu("Application Layer");
        analyzers = PacketAnalyzerLoader.getAnalyzers();
        JMenuItem item, subitem;
        for (int i = 0; i < analyzers.length; i++) {
            item = new JMenu(analyzers[i].getProtocolName());
            String[] valueNames = analyzers[i].getValueNames();
            if (valueNames == null) continue;
            for (int j = 0; j < valueNames.length; j++) {
                subitem = new JCheckBoxMenuItem(valueNames[j]);
                subitem.setActionCommand("TableView" + i);
                subitem.addActionListener(this);
                item.add(subitem);
            }
            tableViewMenu[analyzers[i].layer].add(item);
        }

        setLayout(new BorderLayout());
        add(createControlBar(), BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);

        loadProperty();
        refreshPackets();
        setSize(400, 200);
    }

    void refreshPackets() {
        table.refreshPackets();
        updateFilterStatus();
    }

    void clear() {
        table.clear();
        updateFilterStatus();
    }

    int getVisiblePacketCount() {
        return table.getVisiblePacketCount();
    }

    public void setTableViewMenu(JMenu menu) {
        menu.add(tableViewMenu[0]);
        menu.add(tableViewMenu[1]);
        menu.add(tableViewMenu[2]);
        menu.add(tableViewMenu[3]);
    }

    public void actionPerformed(ActionEvent evt) {
        String cmd = evt.getActionCommand();

        if (cmd.startsWith("TableView")) {
            int index = Integer.parseInt(cmd.substring(9));
            JCheckBoxMenuItem item = (JCheckBoxMenuItem) evt.getSource();
            table.setTableView(analyzers[index], item.getText(), item.isSelected());
            refreshPackets();
        }
    }

    public void valueChanged(ListSelectionEvent evt) {
        if (evt.getValueIsAdjusting()) return;

        int index = ((ListSelectionModel) evt.getSource()).getMinSelectionIndex();
        if (index >= 0) {
            Packet p = table.getPacketAtViewRow(index);
            if (p != null) {
                tree.analyzePacket(p);
                text.showPacket(p);
            }
        }
    }

    void loadProperty() {
        if (NetPackSniff.JDProperty.getProperty("TableView") != null) {
            Component[] menus = new Component[analyzers.length];
            int k = 0;
            for (int j = 0; j < tableViewMenu[0].getMenuComponents().length; j++)
                menus[k++] = tableViewMenu[0].getMenuComponents()[j];
            for (int j = 0; j < tableViewMenu[1].getMenuComponents().length; j++)
                menus[k++] = tableViewMenu[1].getMenuComponents()[j];
            for (int j = 0; j < tableViewMenu[2].getMenuComponents().length; j++)
                menus[k++] = tableViewMenu[2].getMenuComponents()[j];
            for (int j = 0; j < tableViewMenu[3].getMenuComponents().length; j++)
                menus[k++] = tableViewMenu[3].getMenuComponents()[j];

            StringTokenizer status = new StringTokenizer(NetPackSniff.JDProperty.getProperty("TableView"), ",");

            while (status.hasMoreTokens()) {
                StringTokenizer s = new StringTokenizer(status.nextToken(), ":");
                if (s.countTokens() == 2) {
                    String name = s.nextToken(), valueName = s.nextToken();
                    for (int i = 0; i < menus.length; i++) {
                        if (((JMenu) menus[i]).getText() == null || name == null) continue;
                        if (((JMenu) menus[i]).getText().equals(name)) {
                            Component[] vn = ((JMenu) menus[i]).getMenuComponents();
                            for (int j = 0; j < vn.length; j++)
                                if (valueName.equals(((JCheckBoxMenuItem) vn[j]).getText())) {
                                    ((JCheckBoxMenuItem) vn[j]).setState(true);
                                    break;
                                }
                            break;
                        }
                    }

                    for (int i = 0; i < analyzers.length; i++)
                        if (analyzers[i].getProtocolName().equals(name)) {
                            table.setTableView(analyzers[i], valueName, true);
                            break;
                        }
                }
            }
        }

        boolean autoScroll = Boolean.valueOf(NetPackSniff.JDProperty.getProperty(AUTO_SCROLL_KEY, "true")).booleanValue();
        autoScrollCheck.setSelected(autoScroll);
        table.setAutoScroll(autoScroll);
    }

    void saveProperty() {
        String[] viewStatus = table.getTableViewStatus();
        if (viewStatus.length > 0) {
            StringBuffer buf = new StringBuffer(viewStatus[0]);
            for (int i = 1; i < viewStatus.length; i++)
                buf.append(",").append(viewStatus[i]);
            NetPackSniff.JDProperty.put("TableView", buf.toString());
        } else {
            NetPackSniff.JDProperty.remove("TableView");
        }
        NetPackSniff.JDProperty.put(AUTO_SCROLL_KEY, String.valueOf(autoScrollCheck.isSelected()));
    }

    private JComponent createControlBar() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));

        JPanel left = new JPanel(new BorderLayout(4, 0));
        left.add(new JLabel("Filter"), BorderLayout.WEST);
        filterField = new JTextField();
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                applyFilter();
            }

            public void removeUpdate(DocumentEvent e) {
                applyFilter();
            }

            public void changedUpdate(DocumentEvent e) {
                applyFilter();
            }
        });
        left.add(filterField, BorderLayout.CENTER);

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                filterField.setText("");
            }
        });
        left.add(clearButton, BorderLayout.EAST);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        autoScrollCheck = new JCheckBox("Auto-scroll", true);
        autoScrollCheck.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                table.setAutoScroll(autoScrollCheck.isSelected());
            }
        });
        filterStatusLabel = new JLabel();
        right.add(autoScrollCheck);
        right.add(filterStatusLabel);

        panel.add(left, BorderLayout.CENTER);
        panel.add(right, BorderLayout.EAST);
        return panel;
    }

    private void applyFilter() {
        table.setFilterText(filterField.getText());
        refreshPackets();
    }

    private void updateFilterStatus() {
        filterStatusLabel.setText(table.getVisiblePacketCount() + " shown");
    }
}
