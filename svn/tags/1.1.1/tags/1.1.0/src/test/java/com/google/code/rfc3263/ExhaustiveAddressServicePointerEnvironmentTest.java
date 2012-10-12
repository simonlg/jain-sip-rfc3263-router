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

public class ExhaustiveAddressServicePointerEnvironmentTest extends ExhaustiveAddressServiceEnvironmentTest {
	private static Map<String, String> transportMap;
	private Locator locator;
	
	static {
		transportMap = new HashMap<String, String>();
		
		transportMap.put("sips:example.org;transport=tcp;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sips:example.org;transport=tcp", "192.168.0.16:5061/TLS");
		transportMap.put("sips:example.org;transport=sctp;maddr=example.net", "192.168.0.18:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=sctp", "192.168.0.16:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=tls;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sips:example.org;transport=tls", "192.168.0.16:5061/TLS");
		transportMap.put("sips:example.org;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sips:example.org", "192.168.0.16:5061/TLS");
		
		transportMap.put("sip:example.org;transport=udp;maddr=example.net", "192.168.0.17:5060/UDP");
		transportMap.put("sip:example.org;transport=udp", "192.168.0.15:5060/UDP");
		transportMap.put("sip:example.org;transport=tcp;maddr=example.net", "192.168.0.17:5060/TCP");
		transportMap.put("sip:example.org;transport=tcp", "192.168.0.15:5060/TCP");
		transportMap.put("sip:example.org;transport=sctp;maddr=example.net", "192.168.0.17:5060/SCTP");
		transportMap.put("sip:example.org;transport=sctp", "192.168.0.15:5060/SCTP");
		transportMap.put("sip:example.org;transport=tls;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sip:example.org;transport=tls", "192.168.0.16:5061/TLS");
		transportMap.put("sip:example.org;maddr=example.net", "192.168.0.17:5060/UDP");
		transportMap.put("sip:example.org", "192.168.0.15:5060/UDP");
		
		transportMap.put("sips:192.168.0.1;transport=tcp;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=sctp;maddr=example.net", "192.168.0.18:5061/TLS-SCTP");
		transportMap.put("sips:192.168.0.1;transport=tls;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sips:192.168.0.1;maddr=example.net", "192.168.0.18:5061/TLS");
		
		transportMap.put("sip:192.168.0.1;transport=udp;maddr=example.net", "192.168.0.17:5060/UDP");
		transportMap.put("sip:192.168.0.1;transport=tcp;maddr=example.net", "192.168.0.17:5060/TCP");
		transportMap.put("sip:192.168.0.1;transport=sctp;maddr=example.net", "192.168.0.17:5060/SCTP");
		transportMap.put("sip:192.168.0.1;transport=tls;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sip:192.168.0.1;maddr=example.net", "192.168.0.17:5060/UDP");
		
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net", "192.168.0.18:5061/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net", "192.168.0.18:5061/TLS");
		
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=example.net", "192.168.0.17:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net", "192.168.0.17:5060/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net", "192.168.0.17:5060/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net", "192.168.0.18:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net", "192.168.0.17:5060/UDP");
	}
	
	@Before
	public void setUp() throws Exception {
		
final Resolver resolver = EasyMock.createMock(Resolver.class);
		
		final Set<ARecord> orgAddresses = new HashSet<ARecord>();
		orgAddresses.add(new ARecord(new Name("example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.3")));
		final Set<ARecord> orgAddressesInsecure = new HashSet<ARecord>();
		orgAddressesInsecure.add(new ARecord(new Name("sip.example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.15")));
		final Set<ARecord> orgAddressesSecure = new HashSet<ARecord>();
		orgAddressesSecure.add(new ARecord(new Name("sips.example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.16")));
		final Set<ARecord> netAddresses = new HashSet<ARecord>();
		netAddresses.add(new ARecord(new Name("example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.4")));
		final Set<ARecord> netAddressesInsecure = new HashSet<ARecord>();
		netAddressesInsecure.add(new ARecord(new Name("sip.example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.17")));
		final Set<ARecord> netAddressesSecure = new HashSet<ARecord>();
		netAddressesSecure.add(new ARecord(new Name("sips.example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.18")));
		
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(orgAddresses).anyTimes();
		expect(resolver.lookupARecords(new Name("sip.example.org."))).andReturn(orgAddressesInsecure).anyTimes();
		expect(resolver.lookupARecords(new Name("sips.example.org."))).andReturn(orgAddressesSecure).anyTimes();
		expect(resolver.lookupARecords(new Name("example.net."))).andReturn(netAddresses).anyTimes();
		expect(resolver.lookupARecords(new Name("sip.example.net."))).andReturn(netAddressesInsecure).anyTimes();
		expect(resolver.lookupARecords(new Name("sips.example.net."))).andReturn(netAddressesSecure).anyTimes();
		
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("sip.example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("sips.example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("sip.example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("sips.example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		
		final List<SRVRecord> orgSipUdpServices = new ArrayList<SRVRecord>();
		orgSipUdpServices.add(new SRVRecord(new Name("_sip._udp.example.org."), DClass.IN, 1000L, 0, 0, 5060, new Name("sip.example.org.")));
		final List<SRVRecord> orgSipTcpServices = new ArrayList<SRVRecord>();
		orgSipTcpServices.add(new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 0, 5060, new Name("sip.example.org.")));
		final List<SRVRecord> orgSipSctpServices = new ArrayList<SRVRecord>();
		orgSipSctpServices.add(new SRVRecord(new Name("_sip._sctp.example.org."), DClass.IN, 1000L, 2, 0, 5060, new Name("sip.example.org.")));
		final List<SRVRecord> orgSipsTcpServices = new ArrayList<SRVRecord>();
		orgSipsTcpServices.add(new SRVRecord(new Name("_sips._tcp.example.org."), DClass.IN, 1000L, 3, 0, 5061, new Name("sips.example.org.")));
		final List<SRVRecord> orgSipsSctpServices = new ArrayList<SRVRecord>();
		orgSipsSctpServices.add(new SRVRecord(new Name("_sips._sctp.example.org."), DClass.IN, 1000L, 4, 0, 5061, new Name("sips.example.org.")));
		final List<SRVRecord> netSipUdpServices = new ArrayList<SRVRecord>();
		netSipUdpServices.add(new SRVRecord(new Name("_sip._udp.example.net."), DClass.IN, 1000L, 0, 0, 5060, new Name("sip.example.net.")));
		final List<SRVRecord> netSipTcpServices = new ArrayList<SRVRecord>();
		netSipTcpServices.add(new SRVRecord(new Name("_sip._tcp.example.net."), DClass.IN, 1000L, 1, 0, 5060, new Name("sip.example.net.")));
		final List<SRVRecord> netSipSctpServices = new ArrayList<SRVRecord>();
		netSipSctpServices.add(new SRVRecord(new Name("_sip._sctp.example.net."), DClass.IN, 1000L, 2, 0, 5060, new Name("sip.example.net.")));
		final List<SRVRecord> netSipsTcpServices = new ArrayList<SRVRecord>();
		netSipsTcpServices.add(new SRVRecord(new Name("_sips._tcp.example.net."), DClass.IN, 1000L, 3, 0, 5061, new Name("sips.example.net.")));
		final List<SRVRecord> netSipsSctpServices = new ArrayList<SRVRecord>();
		netSipsSctpServices.add(new SRVRecord(new Name("_sips._sctp.example.net."), DClass.IN, 1000L, 4, 0, 5061, new Name("sips.example.net.")));
		
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
		
		final List<NAPTRRecord> orgPointers = new ArrayList<NAPTRRecord>();
		orgPointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2U", "", new Name("_sip._udp.example.org.")));
		orgPointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2T", "", new Name("_sip._tcp.example.org.")));
		orgPointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2S", "", new Name("_sip._sctp.example.org.")));
		orgPointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIPS+D2T", "", new Name("_sips._tcp.example.org.")));
		orgPointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIPS+D2S", "", new Name("_sips._sctp.example.org.")));
		final List<NAPTRRecord> netPointers = new ArrayList<NAPTRRecord>();
		netPointers.add(new NAPTRRecord(new Name("example.net."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2U", "", new Name("_sip._udp.example.net.")));
		netPointers.add(new NAPTRRecord(new Name("example.net."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2T", "", new Name("_sip._tcp.example.net.")));
		netPointers.add(new NAPTRRecord(new Name("example.net."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2S", "", new Name("_sip._sctp.example.net.")));
		netPointers.add(new NAPTRRecord(new Name("example.net."), DClass.IN, 1000L, 0, 0, "s", "SIPS+D2T", "", new Name("_sips._tcp.example.net.")));
		netPointers.add(new NAPTRRecord(new Name("example.net."), DClass.IN, 1000L, 0, 0, "s", "SIPS+D2S", "", new Name("_sips._sctp.example.net.")));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(orgPointers).anyTimes();
		expect(resolver.lookupNAPTRRecords(new Name("example.net."))).andReturn(netPointers).anyTimes();
		
		replay(resolver);
		locator = new Locator(resolver, Arrays.asList("UDP", "TCP", "TLS", "SCTP", "TLS-SCTP"));
	}
	
	public ExhaustiveAddressServicePointerEnvironmentTest(String uriString) {
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
