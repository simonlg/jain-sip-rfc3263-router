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
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.SRVRecord;

import com.google.code.rfc3263.dns.Resolver;

public class ExhaustiveAddressServiceEnvironmentTest extends ExhaustiveAddressEnvironmentTest {
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
		
		final Set<ARecord> orgAddresses = new HashSet<ARecord>();
		orgAddresses.add(new ARecord(new Name("example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.3")));
		final Set<ARecord> orgAddressesA = new HashSet<ARecord>();
		orgAddressesA.add(new ARecord(new Name("a.example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.5")));
		final Set<ARecord> orgAddressesB = new HashSet<ARecord>();
		orgAddressesB.add(new ARecord(new Name("b.example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.6")));
		final Set<ARecord> orgAddressesC = new HashSet<ARecord>();
		orgAddressesC.add(new ARecord(new Name("c.example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.7")));
		final Set<ARecord> orgAddressesD = new HashSet<ARecord>();
		orgAddressesD.add(new ARecord(new Name("d.example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.8")));
		final Set<ARecord> orgAddressesE = new HashSet<ARecord>();
		orgAddressesE.add(new ARecord(new Name("e.example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.9")));
		final Set<ARecord> netAddresses = new HashSet<ARecord>();
		netAddresses.add(new ARecord(new Name("example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.4")));
		final Set<ARecord> netAddressesA = new HashSet<ARecord>();
		netAddressesA.add(new ARecord(new Name("a.example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.10")));
		final Set<ARecord> netAddressesB = new HashSet<ARecord>();
		netAddressesB.add(new ARecord(new Name("b.example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.11")));
		final Set<ARecord> netAddressesC = new HashSet<ARecord>();
		netAddressesC.add(new ARecord(new Name("c.example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.12")));
		final Set<ARecord> netAddressesD = new HashSet<ARecord>();
		netAddressesD.add(new ARecord(new Name("d.example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.13")));
		final Set<ARecord> netAddressesE = new HashSet<ARecord>();
		netAddressesE.add(new ARecord(new Name("e.example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.14")));
		
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(orgAddresses).anyTimes();
		expect(resolver.lookupARecords(new Name("a.example.org."))).andReturn(orgAddressesA).anyTimes();
		expect(resolver.lookupARecords(new Name("b.example.org."))).andReturn(orgAddressesB).anyTimes();
		expect(resolver.lookupARecords(new Name("c.example.org."))).andReturn(orgAddressesC).anyTimes();
		expect(resolver.lookupARecords(new Name("d.example.org."))).andReturn(orgAddressesD).anyTimes();
		expect(resolver.lookupARecords(new Name("e.example.org."))).andReturn(orgAddressesE).anyTimes();
		expect(resolver.lookupARecords(new Name("example.net."))).andReturn(netAddresses).anyTimes();
		expect(resolver.lookupARecords(new Name("a.example.net."))).andReturn(netAddressesA).anyTimes();
		expect(resolver.lookupARecords(new Name("b.example.net."))).andReturn(netAddressesB).anyTimes();
		expect(resolver.lookupARecords(new Name("c.example.net."))).andReturn(netAddressesC).anyTimes();
		expect(resolver.lookupARecords(new Name("d.example.net."))).andReturn(netAddressesD).anyTimes();
		expect(resolver.lookupARecords(new Name("e.example.net."))).andReturn(netAddressesE).anyTimes();
		
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("a.example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("b.example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("c.example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("d.example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("e.example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("a.example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("b.example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("c.example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("d.example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("e.example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		
		final List<SRVRecord> orgSipUdpServices = new ArrayList<SRVRecord>();
		orgSipUdpServices.add(new SRVRecord(new Name("_sip._udp.example.org."), DClass.IN, 1000L, 0, 0, 5060, new Name("a.example.org.")));
		final List<SRVRecord> orgSipTcpServices = new ArrayList<SRVRecord>();
		orgSipTcpServices.add(new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 0, 0, 5060, new Name("b.example.org.")));
		final List<SRVRecord> orgSipSctpServices = new ArrayList<SRVRecord>();
		orgSipSctpServices.add(new SRVRecord(new Name("_sip._sctp.example.org."), DClass.IN, 1000L, 0, 0, 5060, new Name("c.example.org.")));
		final List<SRVRecord> orgSipsTcpServices = new ArrayList<SRVRecord>();
		orgSipsTcpServices.add(new SRVRecord(new Name("_sips._tcp.example.org."), DClass.IN, 1000L, 0, 0, 5061, new Name("d.example.org.")));
		final List<SRVRecord> orgSipsSctpServices = new ArrayList<SRVRecord>();
		orgSipsSctpServices.add(new SRVRecord(new Name("_sips._sctp.example.org."), DClass.IN, 1000L, 0, 0, 5061, new Name("e.example.org.")));
		final List<SRVRecord> netSipUdpServices = new ArrayList<SRVRecord>();
		netSipUdpServices.add(new SRVRecord(new Name("_sip._udp.example.net."), DClass.IN, 1000L, 0, 0, 5060, new Name("a.example.net.")));
		final List<SRVRecord> netSipTcpServices = new ArrayList<SRVRecord>();
		netSipTcpServices.add(new SRVRecord(new Name("_sip._tcp.example.net."), DClass.IN, 1000L, 0, 0, 5060, new Name("b.example.net.")));
		final List<SRVRecord> netSipSctpServices = new ArrayList<SRVRecord>();
		netSipSctpServices.add(new SRVRecord(new Name("_sip._sctp.example.net."), DClass.IN, 1000L, 0, 0, 5060, new Name("c.example.net.")));
		final List<SRVRecord> netSipsTcpServices = new ArrayList<SRVRecord>();
		netSipsTcpServices.add(new SRVRecord(new Name("_sips._tcp.example.net."), DClass.IN, 1000L, 0, 0, 5061, new Name("d.example.net.")));
		final List<SRVRecord> netSipsSctpServices = new ArrayList<SRVRecord>();
		netSipsSctpServices.add(new SRVRecord(new Name("_sips._sctp.example.net."), DClass.IN, 1000L, 0, 0, 5061, new Name("e.example.net.")));
		
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.org."))).andReturn(orgSipUdpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.org."))).andReturn(orgSipTcpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._sctp.example.org."))).andReturn(orgSipSctpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._tcp.example.org."))).andReturn(orgSipsTcpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._sctp.example.org."))).andReturn(orgSipsSctpServices).anyTimes();
		
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.net."))).andReturn(netSipUdpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.net."))).andReturn(netSipTcpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._sctp.example.net."))).andReturn(netSipSctpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._tcp.example.net."))).andReturn(netSipsTcpServices).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._sctp.example.net."))).andReturn(netSipsSctpServices).anyTimes();

		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(Collections.<NAPTRRecord>emptyList()).anyTimes();
		expect(resolver.lookupNAPTRRecords(new Name("example.net."))).andReturn(Collections.<NAPTRRecord>emptyList()).anyTimes();
		
		replay(resolver);
		locator = new Locator(Arrays.asList("UDP", "TCP", "TLS", "SCTP", "TLS-SCTP"), resolver);
	}
	
	public ExhaustiveAddressServiceEnvironmentTest(String uriString) {
		super(uriString);
	}

	@Override
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
