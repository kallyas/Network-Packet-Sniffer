/*This class shows the free memory of the system
 * 
 */

package stat;
import java.util.List;

import jpcap.packet.Packet;

public class FreeMemStat extends StatisticsTaker
{
	String[] labels={"Free Memory"};
	String[] types={"Bytes"};

	public String getName(){
		return "Free Memory";
	}

	public void analyze(List<Packet> packets){}
	public void addPacket(Packet p){}

	public String[] getLabels(){
		return labels;
	}

	public String[] getStatTypes(){
		return types;
	}

	public long[] getValues(int index){
		long[] ret=new long[1];
		ret[0]=Runtime.getRuntime().freeMemory();
		return ret;
	}
	public void clear(){}
}
