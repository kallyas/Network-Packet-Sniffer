/*Author Aditya
 *
 *
 * This class shows the statistics in the form of graphs and similar to the cumulative statistics frame
 */


package ui;

import java.awt.BorderLayout;
import java.util.List;

import jpcap.packet.Packet;
import stat.StatisticsTaker;
import ui.graph.LineGraph;


public class ContinuousStatFrame extends StatFrame {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    LineGraph lineGraph;

    StatisticsTaker staker;
    int statType;
    boolean drawTimescale; //true-> time, false->packet#
    int count, currentCount = 0;
    long currentSec = 0;

    ContinuousStatFrame(List<Packet> packets, int count, boolean isTime, StatisticsTaker staker, int type) {
        super(staker.getName() + " [" + staker.getStatTypes()[type] + "]");
        this.staker = staker;
        this.drawTimescale = isTime;
        this.count = count;
        statType = type;

        lineGraph = new LineGraph(staker.getLabels());

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(lineGraph, BorderLayout.CENTER);
        setSize(300, 300);

        if (packets == null || packets.size() == 0) return;

        currentSec = packets.get(0).sec;
        currentCount = 0;
        int index = 0;
        if (isTime) {
            while (index < packets.size()) {
                Packet p = packets.get(index++);

                while (index < packets.size() && p.sec - currentSec <= count) {
                    staker.addPacket(p);
                    p = packets.get(index++);
                }
                if (index == packets.size()) break;
                currentSec += count;
                index--;
                lineGraph.addValue(staker.getValues(type));
                staker.clear();
            }
        } else {
            while (index < packets.size()) {
                for (int i = 0; index < packets.size() && i < count; i++, currentCount++, index++)
                    staker.addPacket(packets.get(index));
                if (index >= packets.size()) break;
                currentCount = 0;
                lineGraph.addValue(staker.getValues(type));
                staker.clear();
            }
        }
    }

    public static ContinuousStatFrame openWindow(List<Packet> packets, StatisticsTaker staker) {
        ContinuousStatFrame frame = new ContinuousStatFrame(packets, 5, true, staker, 0);
        frame.setVisible(true);
        return frame;
    }

    public void addPacket(Packet p) {
        staker.addPacket(p);
        if (drawTimescale) {
            if (currentSec == 0) currentSec = p.sec;
            if (p.sec - currentSec > count) {
                lineGraph.addValue(staker.getValues(statType));
                staker.clear();
                currentSec += count;
                if (p.sec - currentSec > count)
                    for (long s = p.sec - currentSec - count; s > count; s -= count) {
                        lineGraph.addValue(staker.getValues(statType));
                    }
            }
        } else {
            currentCount++;
            if (currentCount == count) {
                lineGraph.addValue(staker.getValues(statType));
                staker.clear();
                currentCount = 0;
            }
        }
    }

    public void clear() {
        currentCount = 0;
        currentSec = 0;
        lineGraph.clear();
    }

    void fireUpdate() {
        repaint();
    }
}
