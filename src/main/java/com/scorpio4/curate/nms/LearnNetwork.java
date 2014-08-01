package com.scorpio4.curate.nms;

import com.scorpio4.fact.stream.FactStream;
import com.scorpio4.fact.stream.SinkStream;
import com.scorpio4.oops.FactException;
import com.scorpio4.util.DateXSD;
import com.scorpio4.util.Identifiable;
import com.scorpio4.util.IdentityHelper;
import com.scorpio4.util.map.MapUtil;
import com.scorpio4.vocab.COMMONS;
import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.*;
import net.sourceforge.jpcap.util.HexHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringWriter;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Map;


/**
 * Scorpio4 (c) 2013-2014
 * Module: com.scorpio4.learn
 * User  : lee
 * Date  : 13/11/2013
 * Time  : 10:23 AM
 */
public class LearnNetwork implements Runnable, Identifiable {
    private static final Logger log = LoggerFactory.getLogger(LearnNetwork.class);

    public static final String NS_IPv4 = NMSVOCAB.NS_IPv4;
    public static final String NS_IANA = NMSVOCAB.NS_IANA;
    public static final String NS_OUI = NMSVOCAB.NS_OUI;

    public static final String NS_PCAP = "urn:scorpio4:nms:pcap:";

    private static final String CONFIG_DEVICE = "scorpio4.learn.network.device";
    private static final String CONFIG_COUNT = "scorpio4.learn.network.count";
    private static final String CONFIG_FILTER = "scorpio4.learn.network.filter";

    private PacketCapture packetCapture = new PacketCapture();
    private String filter = "tcp", device, sessionURI = null;
    private int packetCount = 10;
    private FactStream learn = null;
    private Map config = null;
    private boolean isRunning = false;

    public LearnNetwork() throws CaptureDeviceNotFoundException {
        this.device = packetCapture.findDevice();
        this.packetCount = 10;
    }

    public LearnNetwork(Map config) {
        configure(config);
    }

    public LearnNetwork(String device, int packetCount, String filter) throws CaptureDeviceNotFoundException {
        this.device=device==null?packetCapture.findDevice():device;
        this.packetCount=packetCount;
        this.filter = filter;
    }

    public void configure(Map config) {
        this.config = config;
        try {
            this.device = MapUtil.getString(config, CONFIG_DEVICE, packetCapture.findDevice());
            this.packetCount = MapUtil.getInt(config, CONFIG_COUNT, 10);
            this.filter = MapUtil.getString(config, CONFIG_FILTER , "tcp");
            this.learn = new SinkStream();
        } catch (CaptureDeviceNotFoundException e) {
            log.error("urn:scorpio4:learn:Network:oops:device-not-found#", e);
        }
    }

    public Map getConfiguration() {
        return config;
    }

    public void setFilter(String filter) {
        this.filter = filter;
    }

    public String getFilter() {
        return this.filter;
    }

    public PacketCapture getCapture() {
        return this.packetCapture;
    }

    public CaptureStatistics getStatistics() {
        return this.packetCapture.getStatistics();
    }

    public void learn(final FactStream learn) throws FactException {
        this.learn = learn;
        this.sessionURI = IdentityHelper.uuid(NS_PCAP);
        log.debug("Learning: "+ filter);

        // Register a Listener for jpcap Packets
        packetCapture.addPacketListener(new PacketListener() {

            @Override
            public void packetArrived(Packet packet) {
                try {
                    captured(packet);
                } catch (FactException e) {
                    log.error("urn:scorpio4:learn:Network:oops:fact-stream#", e);
                }
            }
        });
        start();
    }

    protected void captured(Packet packet) throws FactException {
        String pktURI = IdentityHelper.uuid(NS_PCAP +"pkt:");
        learn.fact(pktURI, NS_PCAP + "session", sessionURI);
        if (packet instanceof IPPacket)     captured(pktURI,  (IPPacket)packet);
        if (packet instanceof TCPPacket)    captured(pktURI, (TCPPacket)packet);
        if (packet instanceof UDPPacket)    captured(pktURI, (UDPPacket)packet);
        if (packet instanceof ICMPPacket)   captured(pktURI,(ICMPPacket)packet);
        if (packet instanceof IGMPPacket)   captured(pktURI,(IGMPPacket)packet);
        if (packet instanceof ARPPacket)    captured(pktURI, (ARPPacket) packet);
    }

    protected void captured(String pktURI, ARPPacket packet) throws FactException {
        String today = DateXSD.today();
        String sourceAddress = packet.getSourceHwAddress();
        String destinationAddress = packet.getDestinationHwAddress();

        log.debug("ICMP: "+sourceAddress + " -> " + destinationAddress);
        learn.fact(pktURI, COMMONS.LABEL, packet.toString(), "string");
        learn.fact(pktURI, COMMONS.A, NS_PCAP +"ARP");

        learn.fact(pktURI, NS_PCAP + "capturedAt", today, "dateTime");

        learn.fact(pktURI, NS_PCAP + "operation",  NS_PCAP +"Operation_"+packet.getOperation());
        learn.fact(pktURI, NS_PCAP + "src", NS_IPv4+packet.getSourceProtoAddress());
        learn.fact(pktURI, NS_PCAP + "srcMAC", NS_OUI+sourceAddress);
        learn.fact(pktURI, NS_PCAP + "dst", NS_IPv4+packet.getDestinationProtoAddress());
        learn.fact(pktURI, NS_PCAP + "dstMAC", NS_OUI+destinationAddress);
    }


    protected void captured(String pktURI, IPPacket packet) throws FactException {
        String today = DateXSD.today();
        String sourceAddress = packet.getSourceAddress();
        String destinationAddress = packet.getDestinationAddress();

        learn.fact(pktURI, COMMONS.LABEL, packet.toString(), "string");
        learn.fact(pktURI, COMMONS.COMMENT, packet.toColoredVerboseString(false), "string");
        learn.fact(pktURI, COMMONS.A, NS_PCAP +"IP");

        learn.fact(pktURI, NS_PCAP + "capturedAt", today, "dateTime");
        learn.fact(pktURI, NS_PCAP + "length", packet.getLength(), "integer");
        learn.fact(pktURI, NS_PCAP + "checksum", packet.getChecksum(), "string");
        learn.fact(pktURI, NS_PCAP + "protocol", NS_PCAP +"Protocol_"+packet.getProtocol());
        learn.fact(pktURI, NS_PCAP + "protocolIP", NS_PCAP +"IPProtocol_"+packet.getIPProtocol());

        learn.fact(pktURI, NS_PCAP + "src", NS_IPv4 + sourceAddress);
        learn.fact(pktURI, NS_PCAP + "dst", NS_IPv4 + destinationAddress);

        learn.fact(pktURI, NS_PCAP + "serviceType", NS_PCAP +"ServiceType_"+packet.getTypeOfService(), "integer");
        learn.fact(pktURI, NS_PCAP + "srcMAC", NS_OUI+packet.getSourceHwAddress());
        learn.fact(pktURI, NS_PCAP + "dstMAC", NS_OUI+packet.getDestinationHwAddress());

        learn.fact(NS_OUI+packet.getSourceHwAddress(), COMMONS.RDFS_SUBCLASS, NS_OUI+packet.getSourceHwAddress().substring(0,8));
        learn.fact(NS_OUI+packet.getDestinationHwAddress(), COMMONS.RDFS_SUBCLASS, NS_OUI+packet.getDestinationHwAddress().substring(0,8));
        log.trace("<" + pktURI + "> " + packet.toColoredString(true));
    }

    protected void captured(String pktURI, UDPPacket packet) throws FactException {
        int sourcePort = packet.getSourcePort();
        int destinationPort = packet.getDestinationPort();

        learn.fact(pktURI, COMMONS.A, NS_PCAP +"UDP");
        learn.fact(pktURI, NS_PCAP + "srcPort", NS_IANA + sourcePort);
        learn.fact(pktURI, NS_PCAP + "dstPort", NS_IANA + destinationPort);
    }

    protected void captured(String pktURI, ICMPPacket packet) throws FactException {

        learn.fact(pktURI, COMMONS.LABEL, packet.toString(), "string");
        learn.fact(pktURI, COMMONS.A, NS_PCAP +"ICMP");
        learn.fact(pktURI, NS_PCAP +"messageCode", NS_PCAP +"MessageCode_"+packet.getMessageCode());
        learn.fact(pktURI, NS_PCAP +"messageType", NS_PCAP +"MessageType_"+packet.getMessageType());
    }

    protected void captured(String pktURI, TCPPacket packet) throws FactException, FactException {
        String sourceAddress = packet.getSourceAddress();
        String destinationAddress = packet.getDestinationAddress();
        int sourcePort = packet.getSourcePort();
        int destinationPort = packet.getDestinationPort();

        log.debug("TCP: "+sourceAddress + ":" + sourcePort + " -> " + destinationAddress + ":" + destinationPort);
        learn.fact(pktURI, COMMONS.A, NS_PCAP + "TCP");
        learn.fact(pktURI, NS_PCAP + "sequence", packet.getSequenceNumber(), "integer");
        learn.fact(pktURI, NS_PCAP + "window", packet.getWindowSize(), "integer");
        learn.fact(pktURI, NS_PCAP + "urgent", NS_PCAP +"Urgent_"+packet.getUrgentPointer(), "integer");
//                        learn.fact(pktURI, NS_SNIFF + "fragFlags", NS_SNIFF+"fragFlags#"+tcpPacket.getFragmentFlags(), "integer");

        learn.fact(pktURI, NS_PCAP + "srcPort", NS_IANA + sourcePort);
        learn.fact(pktURI, NS_PCAP + "dstPort", NS_IANA + destinationPort);
    }

    @Override
    public void run() {
        if (!isRunning()) start();

        try {
            packetCapture.capture(packetCount);
        } catch (CapturePacketException e) {
            log.error("Capture Failed: " + e.getMessage(), e);
        }
        if (isRunning()) stop();
    }

    public void start() {
        try {
            this.sessionURI = IdentityHelper.uuid(NS_PCAP);

            // Open Device for Capturing (requires root)
            packetCapture.open(device, true);
            isRunning = true;
            // Add a BPF Filter (see tcpdump documentation)
            if (filter!=null) packetCapture.setFilter(filter, true);

            String today = DateXSD.today();
            learn.fact(sessionURI, NS_PCAP + "capturedAt", today, "dateTime");

            learn.fact(sessionURI, NS_PCAP +"filter", filter, "string");
            learn.fact(sessionURI, NS_PCAP +"device", device, "string");
            learn.fact(sessionURI, NS_PCAP +"count", packetCount, "integer");

            learn.fact(sessionURI, NS_PCAP +"netmask", getNetmask(), "string");
            learn.fact(sessionURI, NS_PCAP +"network", NS_IPv4+getNetworkAddress());
            learn.fact(sessionURI, NS_PCAP +"linkType", NS_PCAP+"LinkType_"+packetCapture.getLinkLayerType());

            InetAddress inetAddress = InetAddress.getLocalHost();
            learn.fact(sessionURI, NS_PCAP+"endpoint", NS_IPv4+inetAddress.getHostAddress() );

            NetworkInterface network = NetworkInterface.getByInetAddress(inetAddress);
            byte[] macAddress = network.getHardwareAddress();
            learn.fact(sessionURI, NS_PCAP + "sparqMAC", NS_OUI + toString(macAddress,":"));
        } catch (CaptureDeviceOpenException e) {
            log.error("urn:scorpio4:learn:Network:oops:open-device#", e);
        } catch (InvalidFilterException e) {
            log.error("urn:scorpio4:learn:Network:oops:invalid-filter#", e);
        } catch (CaptureConfigurationException e) {
            log.error("urn:scorpio4:learn:Network:oops:capture-config#", e);
        } catch (FactException e) {
            log.error("urn:scorpio4:learn:Network:oops:fact-stream#", e);
        } catch (UnknownHostException e) {
            log.error("urn:scorpio4:learn:Network:oops:unknown-host#", e);
        } catch (SocketException e) {
            log.error("urn:scorpio4:learn:Network:oops:socket-failed#", e);
        }

    }

    public void stop() {
        CaptureStatistics stats = packetCapture.getStatistics();
        try {
            learn.fact(sessionURI, NS_PCAP +"droppedCount", stats.getDroppedCount(), "integer");
            learn.fact(sessionURI, NS_PCAP +"receivedCount", stats.getReceivedCount(), "integer");
            packetCapture.endCapture();
            packetCapture.close();
        } catch (FactException e) {
            log.error("urn:scorpio4:learn:Network:oops:fact-stream#", e);
        }
        isRunning = false;
    }

    public String getNetmask() {
        try {
            return HexHelper.toQuadString(packetCapture.getNetmask(device));
        } catch (CaptureConfigurationException e) {
            return null;
        }
    }

    public String getNetworkAddress() {
        try {
            return HexHelper.toQuadString(packetCapture.getNetwork(device));
        } catch (CaptureConfigurationException e) {
            return null;
        }
    }

    public boolean isRunning() {
        return isRunning;
    }

    public static String toString(byte [] bytes, String separator) {
        StringWriter sw = new StringWriter();
        if (bytes==null) return null;
        int length = bytes.length;
        if(length > 0) {
            for(int i = 0; i < length; i++) {
                sw.write(HexHelper.toString(bytes[i]));
                if(i != length - 1)
                    sw.write(separator);
            }
        }
        return(sw.toString());
    }

    @Override
    public String getIdentity() {
        return this.sessionURI;
    }

    public String toString() {
        return getIdentity()+"->"+filter+" @ "+device;
    }
}
