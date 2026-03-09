package app;

import stat.ApplicationProtocolStat;
import stat.FreeMemStat;
import stat.NetworkProtocolStat;
import stat.PacketStat;
import stat.StatisticsTaker;
import stat.TransportProtocolStat;

import java.util.Vector;

public class StatisticsTakerLoader {
   static Vector stakers = new Vector();

    static void loadStatisticsTaker(){
        stakers.addElement(new PacketStat());
        stakers.addElement(new NetworkProtocolStat());
        stakers.addElement(new TransportProtocolStat());
        stakers.addElement(new ApplicationProtocolStat());
        stakers.addElement(new FreeMemStat());
    }

    public static StatisticsTaker[] getStatisticsTakers(){
        StatisticsTaker[] array = new StatisticsTaker[stakers.size()];

        for(int i=0;i <array.length; i++)
            array[i]=(StatisticsTaker)stakers.elementAt(i);

        return array;
    }

    public static StatisticsTaker getStatisticsTakerAt(int index){
        return (StatisticsTaker)stakers.get(index);
    }
}
