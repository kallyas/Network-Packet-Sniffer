package app;

import stat.ApplicationProtocolStat;
import stat.FreeMemStat;
import stat.NetworkProtocolStat;
import stat.PacketStat;
import stat.StatisticsTaker;
import stat.TransportProtocolStat;

import java.util.ArrayList;
import java.util.List;

public class StatisticsTakerLoader {
   static List<StatisticsTaker> stakers = new ArrayList<StatisticsTaker>();

    static void loadStatisticsTaker(){
        stakers.clear();
        stakers.add(new PacketStat());
        stakers.add(new NetworkProtocolStat());
        stakers.add(new TransportProtocolStat());
        stakers.add(new ApplicationProtocolStat());
        stakers.add(new FreeMemStat());
    }

    public static StatisticsTaker[] getStatisticsTakers(){
        return stakers.toArray(new StatisticsTaker[0]);
    }

    public static StatisticsTaker getStatisticsTakerAt(int index){
        return stakers.get(index);
    }
}
