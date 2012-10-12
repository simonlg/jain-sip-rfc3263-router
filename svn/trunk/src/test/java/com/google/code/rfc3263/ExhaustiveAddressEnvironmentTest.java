package com.google.code.rfc3263;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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

public class ExhaustiveAddressEnvironmentTest extends ExhaustiveNoEnvironmentTest {
	private static Map<String, String> transportMap;
	private Locator locator;
	
	static {
		transportMap = new HashMap<String, String>();
		
		transportMap.put("sips:example.org;transport=udp;maddr=example.net", null);
		transportMap.put("sips:example.org;transport=udp", null);
		transportMap.put("sips:example.org;transport=tcp;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sips:example.org;transport=tcp", "192.168.0.3:5061/TLS");
		transportMap.put("sips:example.org;transport=sctp;maddr=example.net", "192.168.0.4:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=sctp", "192.168.0.3:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=tls;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sips:example.org;transport=tls", "192.168.0.3:5061/TLS");
		transportMap.put("sips:example.org;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sips:example.org", "192.168.0.3:5061/TLS");
		transportMap.put("sip:example.org;transport=udp;maddr=example.net", "192.168.0.4:5060/UDP");
		transportMap.put("sip:example.org;transport=udp", "192.168.0.3:5060/UDP");
		transportMap.put("sip:example.org;transport=tcp;maddr=example.net", "192.168.0.4:5060/TCP");
		transportMap.put("sip:example.org;transport=tcp", "192.168.0.3:5060/TCP");
		transportMap.put("sip:example.org;transport=sctp;maddr=example.net", "192.168.0.4:5060/SCTP");
		transportMap.put("sip:example.org;transport=sctp", "192.168.0.3:5060/SCTP");
		transportMap.put("sip:example.org;transport=tls;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sip:example.org;transport=tls", "192.168.0.3:5061/TLS");
		transportMap.put("sip:example.org;maddr=example.net", "192.168.0.4:5060/UDP");
		transportMap.put("sip:example.org", "192.168.0.3:5060/UDP");
		transportMap.put("sips:example.org:1234;transport=udp;maddr=example.net", null);
		transportMap.put("sips:example.org:1234;transport=udp", null);
		transportMap.put("sips:example.org:1234;transport=tcp;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sips:example.org:1234;transport=tcp", "192.168.0.3:1234/TLS");
		transportMap.put("sips:example.org:1234;transport=sctp;maddr=example.net", "192.168.0.4:1234/TLS-SCTP");
		transportMap.put("sips:example.org:1234;transport=sctp", "192.168.0.3:1234/TLS-SCTP");
		transportMap.put("sips:example.org:1234;transport=tls;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sips:example.org:1234;transport=tls", "192.168.0.3:1234/TLS");
		transportMap.put("sips:example.org:1234;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sips:example.org:1234", "192.168.0.3:1234/TLS");
		transportMap.put("sip:example.org:1234;transport=udp;maddr=example.net", "192.168.0.4:1234/UDP");
		transportMap.put("sip:example.org:1234;transport=udp", "192.168.0.3:1234/UDP");
		transportMap.put("sip:example.org:1234;transport=tcp;maddr=example.net", "192.168.0.4:1234/TCP");
		transportMap.put("sip:example.org:1234;transport=tcp", "192.168.0.3:1234/TCP");
		transportMap.put("sip:example.org:1234;transport=sctp;maddr=example.net", "192.168.0.4:1234/SCTP");
		transportMap.put("sip:example.org:1234;transport=sctp", "192.168.0.3:1234/SCTP");
		transportMap.put("sip:example.org:1234;transport=tls;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sip:example.org:1234;transport=tls", "192.168.0.3:1234/TLS");
		transportMap.put("sip:example.org:1234;maddr=example.net", "192.168.0.4:1234/UDP");
		transportMap.put("sip:example.org:1234", "192.168.0.3:1234/UDP");
		transportMap.put("sips:192.168.0.1;transport=udp;maddr=example.net", null);
		transportMap.put("sips:192.168.0.1;transport=tcp;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=sctp;maddr=example.net", "192.168.0.4:5061/TLS-SCTP");
		transportMap.put("sips:192.168.0.1;transport=tls;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sips:192.168.0.1;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sip:192.168.0.1;transport=udp;maddr=example.net", "192.168.0.4:5060/UDP");
		transportMap.put("sip:192.168.0.1;transport=tcp;maddr=example.net", "192.168.0.4:5060/TCP");
		transportMap.put("sip:192.168.0.1;transport=sctp;maddr=example.net", "192.168.0.4:5060/SCTP");
		transportMap.put("sip:192.168.0.1;transport=tls;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sip:192.168.0.1;maddr=example.net", "192.168.0.4:5060/UDP");
		transportMap.put("sips:192.168.0.1:1234;transport=udp;maddr=example.net", null);
		transportMap.put("sips:192.168.0.1:1234;transport=tcp;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;transport=sctp;maddr=example.net", "192.168.0.4:1234/TLS-SCTP");
		transportMap.put("sips:192.168.0.1:1234;transport=tls;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sip:192.168.0.1:1234;transport=udp;maddr=example.net", "192.168.0.4:1234/UDP");
		transportMap.put("sip:192.168.0.1:1234;transport=tcp;maddr=example.net", "192.168.0.4:1234/TCP");
		transportMap.put("sip:192.168.0.1:1234;transport=sctp;maddr=example.net", "192.168.0.4:1234/SCTP");
		transportMap.put("sip:192.168.0.1:1234;transport=tls;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sip:192.168.0.1:1234;maddr=example.net", "192.168.0.4:1234/UDP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=example.net", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net", "192.168.0.4:5061/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=example.net", "192.168.0.4:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net", "192.168.0.4:5060/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net", "192.168.0.4:5060/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net", "192.168.0.4:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net", "192.168.0.4:5060/UDP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=example.net", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=example.net", "192.168.0.4:1234/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=example.net", "192.168.0.4:1234/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=example.net", "192.168.0.4:1234/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=example.net", "192.168.0.4:1234/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=example.net", "192.168.0.4:1234/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=example.net", "192.168.0.4:1234/UDP");
	}
	
	@Before
	public void setUp() throws Exception {
		
		final Resolver resolver = EasyMock.createMock(Resolver.class);
		
		final Set<ARecord> orgAddresses = new HashSet<ARecord>();
		orgAddresses.add(new ARecord(new Name("example.org."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.3")));
		final Set<ARecord> netAddresses = new HashSet<ARecord>();
		netAddresses.add(new ARecord(new Name("example.net."), DClass.IN, 1000L, InetAddress.getByName("192.168.0.4")));
		
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(orgAddresses).anyTimes();
		expect(resolver.lookupARecords(new Name("example.net."))).andReturn(netAddresses).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		expect(resolver.lookupAAAARecords(new Name("example.net."))).andReturn(Collections.<AAAARecord>emptySet()).anyTimes();
		
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.org."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.org."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._sctp.example.org."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._tcp.example.org."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._sctp.example.org."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.net."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.net."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sip._sctp.example.net."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._tcp.example.net."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupSRVRecords(new Name("_sips._sctp.example.net."))).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(Collections.<NAPTRRecord>emptyList()).anyTimes();
		expect(resolver.lookupNAPTRRecords(new Name("example.net."))).andReturn(Collections.<NAPTRRecord>emptyList()).anyTimes();
		
		replay(resolver);
		locator = new Locator(Arrays.asList("UDP", "TCP", "TLS", "SCTP", "TLS-SCTP"), resolver);
	}
	
	public ExhaustiveAddressEnvironmentTest(String uriString) {
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
