package PCAP_GUI.TableInfo;

/**
 * Gagan Heer
 * Renzo Pamplona
 * Rodney Tran
 */
public class UsageTable {

    private String IPaddressProperty;
    private Integer packetProperty;

    public UsageTable(String IPaddress, Integer packet){
        this.IPaddressProperty = IPaddress;
        this.packetProperty = packet;
    }

    public String getIPaddressProperty() {
        return IPaddressProperty;
    }

    public Integer getPacketProperty() {
        return packetProperty;
    }
}
