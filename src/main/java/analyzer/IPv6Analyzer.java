
package analyzer;
import jpcap.packet.*;
import java.util.HashMap;
import java.util.Map;

public class IPv6Analyzer extends PacketAnalyzerAbstract
{
	private static final String[] valueNames={
		"Version",
		"Class",
		"Flow Label",
		"Length",
		"Protocol",
		"Hop Limit",
		"Source IP",
		"Destination IP"//,
		//"Source Host Name",
		//"Destination Host Name"
		};
	
	private final Map<String, Object> values = new HashMap<String, Object>();
	
	public IPv6Analyzer(){
		layer=NETWORK_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		if(p instanceof IPPacket && ((IPPacket)p).version==6) return true;
		else return false;
	}
	
	public String getProtocolName(){
		return "IPv6";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet packet){
		values.clear();
		if(!isAnalyzable(packet))	return;
		IPPacket ip=(IPPacket)packet;
		values.put(valueNames[0],Integer.valueOf(6));
		values.put(valueNames[1],Integer.valueOf(ip.priority));
		values.put(valueNames[2],Integer.valueOf(ip.flow_label));
		values.put(valueNames[3],Integer.valueOf(ip.length));
		values.put(valueNames[4],Integer.valueOf(ip.protocol));
		values.put(valueNames[5],Integer.valueOf(ip.hop_limit));
		values.put(valueNames[6],ip.src_ip.getHostAddress());
		values.put(valueNames[7],ip.dst_ip.getHostAddress());
		//values.put(valueNames[8],ip.src_ip.getHostName());
		//values.put(valueNames[9],ip.dst_ip.getHostName());
	}
	
	public Object getValue(String valueName){
		return values.get(valueName);
	}
	
	Object getValueAt(int index){
		if(index<0 || index>=valueNames.length) return null;
		return values.get(valueNames[index]);
	}
	
	public Object[] getValues(){
		Object[] v=new Object[valueNames.length];
		
		for(int i=0;i<valueNames.length;i++)
			v[i]=values.get(valueNames[i]);
		
		return v;
	}
}
