package PCAP_GUI;

import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.util.PcapPacketArrayList;

import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Gagan Heer
 * Renzo Pamplona
 * Rodney Tran
 */
public class PcapModel {

    private String fileName;
    private byte[] srcIP;
    private Ip4 ip4 = new Ip4();
    private Ip6 ip6 = new Ip6();
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("MM/dd' 'HH:mm:ss:S");
    private Map<String, Integer> packetCount = new HashMap<>();
    private Map<String, ArrayList<String>> firstLastTime = new HashMap<>();
    private Map<String, Integer> avgDataLength = new HashMap<>();
    private Map<String, Integer> topPacketSenders = new HashMap<>();
    private Map<String, Long> topTimes = new HashMap<>();
    private Map<String, Integer> topAvgDataLength = new HashMap<>();

    public PcapModel(String fileName)  {
        this.fileName = fileName;
    }

    //Return an ArrayList of PCAP packets
    public PcapPacketArrayList parseFiles() throws Exception{

        //String buffer that catches error msgs
        final StringBuilder errbuf = new StringBuilder();

        //Open the PCAP file or store the error msg
        Pcap pcapFile = Pcap.openOffline(fileName, errbuf);

        //If the file isn't a PCAP or isn't there throw an exception
        if(pcapFile == null){
            throw new Exception(errbuf.toString());
        }

        //Packet handler that adds packets to the ArrayList
        PcapPacketHandler<PcapPacketArrayList> packetHandler = new PcapPacketHandler<PcapPacketArrayList>() {
            public void nextPacket(PcapPacket packet, PcapPacketArrayList PacketsList) {
                PacketsList.add(packet);
            }
        };

        try {
            //ArrayList that stores packets
            PcapPacketArrayList packets = new PcapPacketArrayList();
            //Takes paramters int, PcapPacketHandler<PcapPacketArrayList>, PcapPacketArrayList
            pcapFile.loop(Pcap.LOOP_INFINITE, packetHandler, packets);
            return packets;
        } finally {
            //Last thing to do is close the pcap handle
            pcapFile.close();
        }
    }

    public Map<String, Integer> createPacketCount(PcapPacketArrayList pcapList){
        Map<String, Integer> packetCount = new HashMap<>();

        //Iterate through Pcap List and capture IPv4 addresses
        for(int i = 0; i<pcapList.size(); i++){
            if(pcapList.get(i).hasHeader(ip4)){
                //Get Source IPv4 address in bytes and decode to String
                srcIP = pcapList.get(i).getHeader(ip4).source();
                String src = FormatUtils.ip(srcIP);

                //If the src IPv4 exists increase the packet count in the map else make a new map entry
                if(packetCount.containsKey(src)) {
                    int count = packetCount.get(src) + 1;
                    packetCount.put(src, count);
                } else {
                    packetCount.put(src, 1);
                }
            } else if (pcapList.get(i).hasHeader(ip6)){
                //Get Source IPv6 address in bytes and decode to String
                srcIP = pcapList.get(i).getHeader(ip6).source();
                String src = FormatUtils.asStringIp6(srcIP, true);

                //If the src IPv6 exists increase the packet count in the map else make a new map entry
                if(packetCount.containsKey(src)) {
                    int count = packetCount.get(src) + 1;
                    packetCount.put(src, count);
                } else {
                    packetCount.put(src, 1);
                }
            }
        }
        topPacketSenders(packetCount);
        return packetCount;
    }

    public Map<String, ArrayList<String>> createArrivalTimes (PcapPacketArrayList pcapList){
        Map<String, ArrayList<String>> firstLastTime = new HashMap<>();
        Map<String, ArrayList<Long>> arrivalTimes = new HashMap<>();

        for(int i = 0; i<pcapList.size(); i++) {
            PcapPacket tempPacket = pcapList.get(i);
            Long timestamp = tempPacket.getCaptureHeader().timestampInMillis();
            Date arrivalTime = new Date(timestamp);
            String formattedTime = simpleDateFormat.format(arrivalTime);
            ArrayList<String> times = new ArrayList<>();
            ArrayList<Long> timestamps = new ArrayList<>();

            if(tempPacket.hasHeader(ip4)){
                srcIP = pcapList.get(i).getHeader(ip4).source();
                String src = FormatUtils.ip(srcIP);

                //If the src IPv4 exists add the arrival time of the last packet to the list
                // else add the arrival time of the first packet to the list
                if(firstLastTime.containsKey(src)) {
                    firstLastTime.get(src).remove(1);
                    firstLastTime.get(src).add(formattedTime);

                    arrivalTimes.get(src).remove(1);
                    arrivalTimes.get(src).add(timestamp);
                } else {
                    times.add(formattedTime);
                    times.add(formattedTime);
                    firstLastTime.put(src, times);

                    timestamps.add(timestamp);
                    timestamps.add(timestamp);
                    arrivalTimes.put(src, timestamps);
                }
            } else if (tempPacket.hasHeader(ip6)){
                //If the src IPv6 exists add the arrival time of the last packet to the list
                // else add the arrival time of the first packet to the list
                srcIP = pcapList.get(i).getHeader(ip6).source();
                String src = FormatUtils.asStringIp6(srcIP, true);

                if(firstLastTime.containsKey(src)) {
                    firstLastTime.get(src).remove(1);
                    firstLastTime.get(src).add(formattedTime);

                    arrivalTimes.get(src).remove(1);
                    arrivalTimes.get(src).add(timestamp);
                } else {
                    times.add(formattedTime);
                    times.add(formattedTime);
                    firstLastTime.put(src, times);

                    timestamps.add(timestamp);
                    timestamps.add(timestamp);
                    arrivalTimes.put(src, timestamps);
                }
            }
        }
        topTimes(arrivalTimes);
        return firstLastTime;
    }


    public Map<String, Integer> createAvgDataLength (PcapPacketArrayList pcapList){
        Map<String, ArrayList<Integer>> allDataLength = new HashMap<>();
        Map<String, Integer> avgDataLength = new HashMap<>();

        for(int i = 0; i<pcapList.size(); i++) {
            PcapPacket tempPacket = pcapList.get(i);
            ArrayList<Integer> dataLengths = new ArrayList<>();

            if(tempPacket.hasHeader(ip4)){
                srcIP = pcapList.get(i).getHeader(ip4).source();
                String src = FormatUtils.ip(srcIP);
                Integer dataLength = tempPacket.getHeader(ip4).getPayloadLength();

                if(allDataLength.containsKey(src)) {
                    allDataLength.get(src).add(dataLength);
                } else {
                    dataLengths.add(dataLength);
                    allDataLength.put(src, dataLengths);
                }
            } else if (tempPacket.hasHeader(ip6)){
                srcIP = pcapList.get(i).getHeader(ip6).source();
                String src = FormatUtils.asStringIp6(srcIP, true);
                Integer dataLength = tempPacket.getHeader(ip6).getPayloadLength();

                if(allDataLength.containsKey(src)) {
                    allDataLength.get(src).add(dataLength);
                } else {
                    allDataLength.put(src, dataLengths);
                }
            }
        }

        Set<String> IPs = allDataLength.keySet();
        for(String tempIP : IPs){
            ArrayList<Integer> lengthsPerIP = allDataLength.get(tempIP);
            Integer sum = 0;
            for(int i = 0; i<lengthsPerIP.size(); i++){
                sum = sum + lengthsPerIP.get(i);
            }
            if(lengthsPerIP.size() != 0){
                Integer avgLength = sum/lengthsPerIP.size();
                avgDataLength.put(tempIP, avgLength);
            }
        }
        topAvgDataLength(avgDataLength);
        return avgDataLength;
    }

    public void topPacketSenders(Map<String, Integer> packetCount){
        Map<String, Integer> top5 = new HashMap<>();
        for(int i = 1; i <= 5; i++){
            String IP = "";
            int amount = 0;
            Set<String> IPs = packetCount.keySet();
            for(String tempIP : IPs){
                if(packetCount.get(tempIP) > amount && !(top5.containsKey(tempIP))){
                    amount = packetCount.get(tempIP);
                    IP = tempIP;
                }
            }
            top5.put(IP, amount);
        }
        topPacketSenders = top5;
    }

    public void topTimes(Map<String, ArrayList<Long>> arrivalTimes){
        Map<String, Long> top5 = new HashMap<>();
        for(int i = 1; i <= 5; i++){
            String IP = "";
            Long time = new Long(0);
            Set<String> IPs = arrivalTimes.keySet();
            for(String tempIP: IPs){
                Long newTime = arrivalTimes.get(tempIP).get(1) - arrivalTimes.get(tempIP).get(0);
                int outcome = time.compareTo(newTime);
                if(outcome <= 0 && !(top5.containsKey(tempIP))){
                    time = newTime;
                    IP = tempIP;
                }
            }
            top5.put(IP, time);
        }
        topTimes = top5;
    }

    public void topAvgDataLength(Map<String, Integer> avgDataLength){
        Map<String, Integer> top5 = new HashMap<>();
        for(int i = 1; i <= 5; i++){
            String IP = "";
            int dataLength = 0;
            Set<String> IPs = avgDataLength.keySet();
            for(String tempIP : IPs){
                if(avgDataLength.get(tempIP) > dataLength && !(top5.containsKey(tempIP))){
                    dataLength = avgDataLength.get(tempIP);
                    IP = tempIP;
                }
            }
            top5.put(IP, dataLength);
        }
        topAvgDataLength = top5;
    }

    public Map<String, Integer> getTopPacketSenders(){
        return topPacketSenders;
    }

    public Map<String, Long> getTopTimes(){
        return topTimes;
    }

    public Map<String, Integer> getTopAvgDataLength(){
        return topAvgDataLength;
    }
}