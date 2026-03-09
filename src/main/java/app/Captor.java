package app;

import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import stat.StatisticsTaker;
import ui.CaptureDialog;
import ui.ContinuousStatFrame;
import ui.CumlativeStatFrame;
import ui.Frame;
import ui.StatFrame;

import javax.swing.*;
import javax.swing.SwingUtilities;
import java.io.File;
import java.util.Vector;

public class Captor {
    private static final int MAX_PACKETS_HOLD = 10000;

    private final Vector<Packet> packets = new Vector<Packet>();
    private final Vector<StatFrame> sframes = new Vector<StatFrame>();

    private JpcapCaptor jpcap = null;

    private boolean isLiveCapture;
    private boolean isSaved = false;
    private long totalCapturedPackets = 0;
    private long totalCapturedBytes = 0;
    private long droppedPackets = 0;
    private int bufferVersion = 0;

    private Frame frame;
    private volatile Thread captureThread;

    public void setJDFrame(Frame frame) {
        this.frame = frame;
    }

    public Vector<Packet> getPackets() {
        return packets;
    }

    public int getPacketCount() {
        return packets.size();
    }

    public Packet getPacketAt(int index) {
        synchronized (packets) {
            if (index < 0 || index >= packets.size()) {
                return null;
            }
            return packets.elementAt(index);
        }
    }

    public Vector<Packet> getPacketsSnapshot() {
        synchronized (packets) {
            return new Vector<Packet>(packets);
        }
    }

    public long getTotalCapturedPackets() {
        return totalCapturedPackets;
    }

    public long getTotalCapturedBytes() {
        return totalCapturedBytes;
    }

    public long getDroppedPackets() {
        return droppedPackets;
    }

    public int getBufferVersion() {
        return bufferVersion;
    }

    public boolean isCapturing() {
        return captureThread != null;
    }

    public String getStatusText(int visiblePackets) {
        StringBuilder builder = new StringBuilder();
        builder.append("Showing ").append(visiblePackets).append(" of ").append(getPacketCount()).append(" buffered packets");
        builder.append(" | Total captured: ").append(totalCapturedPackets);
        builder.append(" | Bytes: ").append(totalCapturedBytes);
        if (droppedPackets > 0) {
            builder.append(" | Rotated out: ").append(droppedPackets);
        }
        return builder.toString();
    }

    public void capturePacketsFromDevice() {
        if (jpcap != null) {
            jpcap.close();
        }

        jpcap = CaptureDialog.getJpcap(frame);
        if (jpcap != null) {
            clear();
        }

        if (jpcap != null) {
            isLiveCapture = true;
            frame.disableCapture();
            startCaptureThread();
        }
    }


    public void loadPacketsFromFile() {
        isLiveCapture = false;
        clear();

        int ret = NetPackSniff.chooser.showOpenDialog(frame);
        if (ret == JFileChooser.APPROVE_OPTION) {
            String path = NetPackSniff.chooser.getSelectedFile().getPath();
            String filename = NetPackSniff.chooser.getSelectedFile().getName();

            try {
                if(jpcap!=null){
                    jpcap.close();
                }
                jpcap = JpcapCaptor.openFile(path);
            } catch (java.io.IOException e) {
                JOptionPane.showMessageDialog(
                        frame,
                        "Can't open file: " + path);
                e.printStackTrace();
                return;
            }

            frame.disableCapture();

            startCaptureThread();
        }
    }

    private void clear(){
        synchronized (packets) {
            packets.clear();
            totalCapturedPackets = 0;
            totalCapturedBytes = 0;
            droppedPackets = 0;
            bufferVersion++;
        }
        frame.clear();

        for(int i= 0; i< sframes.size(); i++)
            ((StatFrame)sframes.get(i)).clear();
    }

    public void saveToFile() {
        if (packets == null)
            return;

        int ret = NetPackSniff.chooser.showSaveDialog(frame);
        if (ret == JFileChooser.APPROVE_OPTION) {
            File file = NetPackSniff.chooser.getSelectedFile();

            if (file.exists()) {
                if (JOptionPane
                        .showConfirmDialog(
                                frame,
                                "Overwrite " + file.getName() + "?",
                                "Overwrite?",
                                JOptionPane.YES_NO_OPTION)
                        == JOptionPane.NO_OPTION) {
                    return;
                }
            }

            try {
                JpcapWriter writer = JpcapWriter.openDumpFile(jpcap,file.getPath());
                Vector<Packet> snapshot = getPacketsSnapshot();

                for (int i = 0; i < snapshot.size(); i++) {
                    writer.writePacket(snapshot.elementAt(i));
                }

                writer.close();
                isSaved = true;
            } catch (java.io.IOException e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(
                        frame,
                        "Can't save file: " + file.getPath());
            }
        }
    }

    public void stopCapture() {
        stopCaptureThread();
    }

    public void saveIfNot() {
        if (isLiveCapture && !isSaved) {
            int ret =
                    JOptionPane.showConfirmDialog(
                            null,
                            "Save this data?",
                            "Save this data?",
                            JOptionPane.YES_NO_OPTION);
            if (ret == JOptionPane.YES_OPTION)
                saveToFile();
        }
    }

    public void addCumulativeStatFrame(StatisticsTaker taker) {
        sframes.add(CumlativeStatFrame.openWindow(getPacketsSnapshot(),taker.newInstance()));
    }

    public void addContinuousStatFrame(StatisticsTaker taker) {
        sframes.add(ContinuousStatFrame.openWindow(getPacketsSnapshot(),taker.newInstance()));
    }

    public void closeAllWindows(){
        for(int i=0;i<sframes.size();i++)
            ((StatFrame)sframes.get(i)).dispose();
    }

    private void startCaptureThread() {
        if (captureThread != null)
            return;

        captureThread = new Thread(new Runnable(){
            //body of capture thread
            public void run() {
                Thread currentThread = Thread.currentThread();
                while (captureThread == currentThread) {
                    if (jpcap.processPacket(1, handler) == 0 && !isLiveCapture)
                        stopCaptureThread();
                    Thread.yield();
                }

                jpcap.breakLoop();
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        frame.enableCapture();
                    }
                });
            }
        }, "packet-capture-thread");
        captureThread.setDaemon(true);
        captureThread.setPriority(Thread.MIN_PRIORITY);

        frame.startUpdating();
        for(int i=0;i<sframes.size();i++){
            ((StatFrame)sframes.get(i)).startUpdating();
        }

        captureThread.start();
    }

    void stopCaptureThread() {
        captureThread = null;
        frame.stopUpdating();
        for(int i=0;i<sframes.size();i++){
            ((StatFrame)sframes.get(i)).stopUpdating();
        }
    }


    private PacketReceiver handler=new PacketReceiver(){
        public void receivePacket(Packet packet) {
            synchronized (packets) {
                packets.addElement(packet);
                totalCapturedPackets++;
                totalCapturedBytes += packet.len;
                while (packets.size() > MAX_PACKETS_HOLD) {
                    packets.removeElementAt(0);
                    droppedPackets++;
                }
                bufferVersion++;
            }
            if (!sframes.isEmpty()) {
                for (int i = 0; i < sframes.size(); i++)
                    ((StatFrame)sframes.get(i)).addPacket(packet);
            }
            isSaved = false;
        }
    };

}
