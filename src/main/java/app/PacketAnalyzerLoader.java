package app;

import analyzer.ARPAnalyzer;
import analyzer.EthernetAnalyzer;
import analyzer.FTPAnalyzer;
import analyzer.HTTPAnalyzer;
import analyzer.ICMPAnalyzer;
import analyzer.IPv4Analyzer;
import analyzer.IPv6Analyzer;
import analyzer.POP3Analyzer;
import analyzer.PacketAnalyzer;
import analyzer.PacketAnalyzerAbstract;
import analyzer.SMTPAnalyzer;
import analyzer.SSHAnalyzer;
import analyzer.TCPAnalyzer;
import analyzer.TelnetAnalyzer;
import analyzer.UDPAnalyzer;

import java.util.ArrayList;
import java.util.List;

public class PacketAnalyzerLoader {
    static List<PacketAnalyzerAbstract> analyzers = new ArrayList<PacketAnalyzerAbstract>();

    static void loadDefaultAnalyzer() {
        analyzers.clear();
        analyzers.add(new PacketAnalyzer());
        analyzers.add(new EthernetAnalyzer());
        analyzers.add(new IPv4Analyzer());
        analyzers.add(new IPv6Analyzer());
        analyzers.add(new TCPAnalyzer());
        analyzers.add(new UDPAnalyzer());
        analyzers.add(new ICMPAnalyzer());
        analyzers.add(new HTTPAnalyzer());
        analyzers.add(new FTPAnalyzer());
        analyzers.add(new TelnetAnalyzer());
        analyzers.add(new SSHAnalyzer());
        analyzers.add(new SMTPAnalyzer());
        analyzers.add(new POP3Analyzer());
        analyzers.add(new ARPAnalyzer());
    }

    public static PacketAnalyzerAbstract[] getAnalyzers() {
        return analyzers.toArray(new PacketAnalyzerAbstract[0]);
    }

    public static PacketAnalyzerAbstract[] getAnalyzersOf(int layer){
        List<PacketAnalyzerAbstract> v = new ArrayList<PacketAnalyzerAbstract>();

        for(int i=0;i<analyzers.size();i++)
            if(analyzers.get(i).layer==layer)
                v.add(analyzers.get(i));

        return v.toArray(new PacketAnalyzerAbstract[0]);
    }
}
