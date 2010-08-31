package com.google.code.rfc3263;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.easymock.EasyMock;
import org.junit.Before;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

public class ExhaustiveAddressServiceTest extends ExhaustiveAddressTest {
	private static Map<String, String> transportMap;
	private Locator locator;
	
	static {
		transportMap = new HashMap<String, String>();
		
		transportMap.put("sips:example.org;transport=tcp;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sips:example.org;transport=tcp", "192.168.0.8:5061/TLS");
		transportMap.put("sips:example.org;transport=sctp;maddr=example.net", "192.168.0.14:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=sctp", "192.168.0.9:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=tls;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sips:example.org;transport=tls", "192.168.0.8:5061/TLS");
		transportMap.put("sips:example.org;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sips:example.org", "192.168.0.8:5061/TLS");
		
		transportMap.put("sip:example.org;transport=udp;maddr=example.net", "192.168.0.10:5060/UDP");
		transportMap.put("sip:example.org;transport=udp", "192.168.0.5:5060/UDP");
		transportMap.put("sip:example.org;transport=tcp;maddr=example.net", "192.168.0.11:5060/TCP");
		transportMap.put("sip:example.org;transport=tcp", "192.168.0.6:5060/TCP");
		transportMap.put("sip:example.org;transport=sctp;maddr=example.net", "192.168.0.12:5060/SCTP");
		transportMap.put("sip:example.org;transport=sctp", "192.168.0.7:5060/SCTP");
		transportMap.put("sip:example.org;transport=tls;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sip:example.org;transport=tls", "192.168.0.8:5061/TLS");
		transportMap.put("sip:example.org;maddr=example.net", "192.168.0.10:5060/UDP");
		transportMap.put("sip:example.org", "192.168.0.5:5060/UDP");
		
		transportMap.put("sips:192.168.0.1;transport=tcp;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=sctp;maddr=example.net", "192.168.0.14:5061/TLS-SCTP");
		transportMap.put("sips:192.168.0.1;transport=tls;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sips:192.168.0.1;maddr=example.net", "192.168.0.13:5061/TLS");
		
		transportMap.put("sip:192.168.0.1;transport=udp;maddr=example.net", "192.168.0.10:5060/UDP");
		transportMap.put("sip:192.168.0.1;transport=tcp;maddr=example.net", "192.168.0.11:5060/TCP");
		transportMap.put("sip:192.168.0.1;transport=sctp;maddr=example.net", "192.168.0.12:5060/SCTP");
		transportMap.put("sip:192.168.0.1;transport=tls;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sip:192.168.0.1;maddr=example.net", "192.168.0.10:5060/UDP");
		
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net", "192.168.0.14:5061/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net", "192.168.0.13:5061/TLS");
		
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=example.net", "192.168.0.10:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net", "192.168.0.11:5060/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net", "192.168.0.12:5060/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net", "192.168.0.13:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net", "192.168.0.10:5060/UDP");
	}
	
	@Before
	public void setUp() throws Exception {
		
		final Resolver resolver = EasyMock.createMock(Resolver.class);
		
		final Set<AddressRecord> orgAddresses = new HashSet<AddressRecord>();
		orgAddresses.add(new AddressRecord("example.org.", InetAddress.getByName("192.168.0.3")));
		final Set<AddressRecord> orgAddressesA = new HashSet<AddressRecord>();
		orgAddressesA.add(new AddressRecord("a.example.org.", InetAddress.getByName("192.168.0.5")));
		final Set<AddressRecord> orgAddressesB = new HashSet<AddressRecord>();
		orgAddressesB.add(new AddressRecord("b.example.org.", InetAddress.getByName("192.168.0.6")));
		final Set<AddressRecord> orgAddressesC = new HashSet<AddressRecord>();
		orgAddressesC.add(new AddressRecord("c.example.org.", InetAddress.getByName("192.168.0.7")));
		final Set<AddressRecord> orgAddressesD = new HashSet<AddressRecord>();
		orgAddressesD.add(new AddressRecord("d.example.org.", InetAddress.getByName("192.168.0.8")));
		final Set<AddressRecord> orgAddressesE = new HashSet<AddressRecord>();
		orgAddressesE.add(new AddressRecord("e.example.org.", InetAddress.getByName("192.168.0.9")));
		final Set<AddressRecord> netAddresses = new HashSet<AddressRecord>();
		netAddresses.add(new AddressRecord("example.net.", InetAddress.getByName("192.168.0.4")));
		final Set<AddressRecord> netAddressesA = new HashSet<AddressRecord>();
		netAddressesA.add(new AddressRecord("a.example.net.", InetAddress.getByName("192.168.0.10")));
		final Set<AddressRecord> netAddressesB = new HashSet<AddressRecord>();
		netAddressesB.add(new AddressRecord("b.example.net.", InetAddress.getByName("192.168.0.11")));
		final Set<AddressRecord> netAddressesC = new HashSet<AddressRecord>();
		netAddressesC.add(new AddressRecord("c.example.net.", InetAddress.getByName("192.168.0.12")));
		final Set<AddressRecord> netAddressesD = new HashSet<AddressRecord>();
		netAddressesD.add(new AddressRecord("d.example.net.", InetAddress.getByName("192.168.0.13")));
		final Set<AddressRecord> netAddressesE = new HashSet<AddressRecord>();
		netAddressesE.add(new AddressRecord("e.example.net.", InetAddress.getByName("192.168.0.14")));
		
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(orgAddresses).anyTimes();
		expect(resolver.lookupAddressRecords("a.example.org.")).andReturn(orgAddressesA).anyTimes();
		expect(resolver.lookupAddressRecords("b.example.org.")).andReturn(orgAddressesB).anyTimes();
		expect(resolver.lookupAddressRecords("c.example.org.")).andReturn(orgAddressesC).anyTimes();
		expect(resolver.lookupAddressRecords("d.example.org.")).andReturn(orgAddressesD).anyTimes();
		expect(resolver.lookupAddressRecords("e.example.org.")).andReturn(orgAddressesE).anyTimes();
		expect(resolver.lookupAddressRecords("example.net.")).andReturn(netAddresses).anyTimes();
		expect(resolver.lookupAddressRecords("a.example.net.")).andReturn(netAddressesA).anyTimes();
		expect(resolver.lookupAddressRecords("b.example.net.")).andReturn(netAddressesB).anyTimes();
		expect(resolver.lookupAddressRecords("c.example.net.")).andReturn(netAddressesC).anyTimes();
		expect(resolver.lookupAddressRecords("d.example.net.")).andReturn(netAddressesD).anyTimes();
		expect(resolver.lookupAddressRecords("e.example.net.")).andReturn(netAddressesE).anyTimes();
		
		final List<ServiceRecord> orgSipUdpServices = new ArrayList<ServiceRecord>();
		orgSipUdpServices.add(new ServiceRecord("_sip._udp.example.org.", 0, 0, 5060, "a.example.org."));
		final List<ServiceRecord> orgSipTcpServices = new ArrayList<ServiceRecord>();
		orgSipTcpServices.add(new ServiceRecord("_sip._tcp.example.org.", 0, 0, 5060, "b.example.org."));
		final List<ServiceRecord> orgSipSctpServices = new ArrayList<ServiceRecord>();
		orgSipSctpServices.add(new ServiceRecord("_sip._sctp.example.org.", 0, 0, 5060, "c.example.org."));
		final List<ServiceRecord> orgSipsTcpServices = new ArrayList<ServiceRecord>();
		orgSipsTcpServices.add(new ServiceRecord("_sips._tcp.example.org.", 0, 0, 5061, "d.example.org."));
		final List<ServiceRecord> orgSipsSctpServices = new ArrayList<ServiceRecord>();
		orgSipsSctpServices.add(new ServiceRecord("_sips._sctp.example.org.", 0, 0, 5061, "e.example.org."));
		final List<ServiceRecord> netSipUdpServices = new ArrayList<ServiceRecord>();
		netSipUdpServices.add(new ServiceRecord("_sip._udp.example.net.", 0, 0, 5060, "a.example.net."));
		final List<ServiceRecord> netSipTcpServices = new ArrayList<ServiceRecord>();
		netSipTcpServices.add(new ServiceRecord("_sip._tcp.example.net.", 0, 0, 5060, "b.example.net."));
		final List<ServiceRecord> netSipSctpServices = new ArrayList<ServiceRecord>();
		netSipSctpServices.add(new ServiceRecord("_sip._sctp.example.net.", 0, 0, 5060, "c.example.net."));
		final List<ServiceRecord> netSipsTcpServices = new ArrayList<ServiceRecord>();
		netSipsTcpServices.add(new ServiceRecord("_sips._tcp.example.net.", 0, 0, 5061, "d.example.net."));
		final List<ServiceRecord> netSipsSctpServices = new ArrayList<ServiceRecord>();
		netSipsSctpServices.add(new ServiceRecord("_sips._sctp.example.net.", 0, 0, 5061, "e.example.net."));
		
		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(orgSipUdpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._tcp.example.org.")).andReturn(orgSipTcpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._sctp.example.org.")).andReturn(orgSipSctpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._tcp.example.org.")).andReturn(orgSipsTcpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._sctp.example.org.")).andReturn(orgSipsSctpServices).anyTimes();
		
		expect(resolver.lookupServiceRecords("_sip._udp.example.net.")).andReturn(netSipUdpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._tcp.example.net.")).andReturn(netSipTcpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._sctp.example.net.")).andReturn(netSipSctpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._tcp.example.net.")).andReturn(netSipsTcpServices).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._sctp.example.net.")).andReturn(netSipsSctpServices).anyTimes();
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(Collections.<PointerRecord>emptyList()).anyTimes();
		expect(resolver.lookupPointerRecords("example.net.")).andReturn(Collections.<PointerRecord>emptyList()).anyTimes();
		
		replay(resolver);
		locator = new Locator(resolver, Arrays.asList("UDP", "TCP", "TLS", "SCTP", "TLS-SCTP"));
	}
	
	public ExhaustiveAddressServiceTest(String uriString) {
		super(uriString);
	}

	public String getHop(String uri) throws Exception {
		if (transportMap.containsKey(uri)) {
			return transportMap.get(uri);
		} else {
			return super.getHop(uri);
		}
	}

	@Override
	public Locator getLocator() {
		return locator;
	}
}
