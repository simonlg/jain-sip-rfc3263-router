package com.google.code.rfc3263;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import javax.sip.PeerUnavailableException;
import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TextParseException;

import com.google.code.rfc3263.dns.Resolver;

/**
 * This test checks that only the expected DNS lookups take place. 
 */
public class LocatorTest {
	private AddressFactory addressFactory;
	private Resolver resolver;
	
	@Before
	public void setUp() throws PeerUnavailableException {
		addressFactory = SipFactory.getInstance().createAddressFactory();
		resolver = createMock(Resolver.class);
	}
	
	@After
	public void tearDown() {
		verify(resolver);
	}
	
	@Test
	public void testShouldUseTcpTransportParameter() throws ParseException {
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setTransportParam("tcp");
		
		Locator locator = new Locator(resolver, Collections.singletonList("TCP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TCP"));
	}
	
	@Test
	public void testShouldUseUdpTransportParameter() throws ParseException {
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setTransportParam("udp");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("UDP"));
	}
	
	@Test
	public void testShouldUseUdpIfNumericAndIsInsecure() throws ParseException {
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("UDP"));
	}
	
	@Test
	public void testShouldUseTlsIfNumericAndIsSecure() throws ParseException {
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setSecure(true);
		
		Locator locator = new Locator(resolver, Collections.singletonList("TCP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TLS"));
	}
	
	@Test
	public void testShouldUseTlsIfNonNumericHasPortAndIsSecure() throws ParseException {
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setSecure(true);
		uri.setPort(5061);
		
		Locator locator = new Locator(resolver, Collections.singletonList("TCP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TLS"));
	}
	
	@Test
	public void testShouldUseUdpIfNonNumericHasPortAndIsInsecure() throws ParseException {
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setPort(5060);
		
		Locator locator = new Locator(resolver, Collections.singletonList("TCP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("UDP"));
	}
	
	@Test
	public void testShouldUseTlsIfNonNumericSomeNaptrRecordsNoSrvRecordsAndIsSecure() throws ParseException, UnknownHostException, TextParseException {
		List<NAPTRRecord> pointers = new ArrayList<NAPTRRecord>();
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000, 0, 0, "s", "SIPS+D2T", "", new Name("_sips._tcp.example.org.")));
		
		Set<ARecord> addresses = new HashSet<ARecord>();
		addresses.add(new ARecord(new Name("example.org."), DClass.IN, 1000L, InetAddress.getLocalHost()));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(pointers);
		expect(resolver.lookupSRVRecords(new Name("_sips._tcp.example.org."))).andReturn(Collections.<SRVRecord>emptyList());
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(addresses);
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		uri.setSecure(true);
		
		Locator locator = new Locator(resolver, Collections.singletonList("TLS"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TLS"));
	}
	
	@Test
	public void testShouldUseUdpIfNonNumericSomeNaptrRecordsNoSrvRecordsAndIsInsecure() throws ParseException, UnknownHostException, TextParseException {
		List<NAPTRRecord> pointers = new ArrayList<NAPTRRecord>();
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2U", "", new Name("_sip._udp.example.org.")));
		
		Set<ARecord> addresses = new HashSet<ARecord>();
		addresses.add(new ARecord(new Name("example.org."), DClass.IN, 1000L, InetAddress.getLocalHost()));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(pointers);
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.org."))).andReturn(Collections.<SRVRecord>emptyList());
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(addresses);
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("UDP"));
	}
	
	@Test
	public void testShouldUseTransportFromSrvIfNonNumericSomeNaptrRecordsSomeSrvRecordsAndIsInsecure() throws ParseException, UnknownHostException, TextParseException {
		List<NAPTRRecord> pointers = new ArrayList<NAPTRRecord>();
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2T", "", new Name("_sip._tcp.example.org.")));
		
		List<SRVRecord> services = new ArrayList<SRVRecord>();
		services.add(new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 0, 0, 5060, new Name("example.org.")));
		
		Set<ARecord> addresses = new HashSet<ARecord>();
		addresses.add(new ARecord(new Name("example.org."), DClass.IN, 1000L, InetAddress.getLocalHost()));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(pointers);
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.org."))).andReturn(services);
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(addresses);
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Arrays.asList("TCP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TCP"));
	}
	
	@Test
	public void testShouldUseTransportFromSrvIfNonNumericNoNaptrRecordsSomeSrvRecordsAndIsInsecure() throws ParseException, UnknownHostException, TextParseException {
		List<SRVRecord> services = new ArrayList<SRVRecord>();
		services.add(new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 0, 0, 5060, new Name("example.org.")));
		
		Set<ARecord> addresses = new HashSet<ARecord>();
		addresses.add(new ARecord(new Name("example.org."), DClass.IN, 1000L, InetAddress.getLocalHost()));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(Collections.<NAPTRRecord>emptyList());
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.org."))).andReturn(services);
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(addresses);
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Arrays.asList("TCP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TCP"));
	}
	
	@Test
	public void testShouldNotLookupNumericHost() throws ParseException {
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldNotLookupNumericHostIPv6() throws ParseException {
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "[2001:db8:85a3::8a2e:370:7334]");
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		Queue<Hop> hops = locator.locate(uri);
		
		Hop expected = new HopImpl("2001:db8:85a3::8a2e:370:7334", 5060, "UDP");
		Hop actual = hops.peek();
		
		assertEquals(expected, actual);
	}
	
	@Test
	public void testShouldLookupAddressWhenPortPresent() throws ParseException, UnknownHostException, TextParseException {
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(new HashSet<ARecord>());
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		uri.setPort(5060);
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldLookupDefaultSrvWhenNoNaptr() throws ParseException, UnknownHostException, TextParseException {
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(new ArrayList<NAPTRRecord>());
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.org."))).andReturn(new ArrayList<SRVRecord>());
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(new HashSet<ARecord>());
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldLookupSrvFromNaptrReplacement() throws ParseException, UnknownHostException, TextParseException {
		List<NAPTRRecord> pointers = new ArrayList<NAPTRRecord>();
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2U", "", new Name("_sip._udp.example.net.")));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(pointers);
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.net."))).andReturn(new ArrayList<SRVRecord>());
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(new HashSet<ARecord>());
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldUseLowestOrderNaptr() throws ParseException, UnknownHostException, TextParseException {
		List<NAPTRRecord> pointers = new ArrayList<NAPTRRecord>();
		// TCP is a lower order, so should be used first.
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 1, 0, "s", "SIP+D2U", "", new Name("_sip._udp.example.net.")));
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2T", "", new Name("_sip._tcp.example.net.")));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(pointers);
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.net."))).andReturn(new ArrayList<SRVRecord>());
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(new HashSet<ARecord>());
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Arrays.asList("UDP", "TCP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldUseLowestPreferenceNaptr() throws ParseException, UnknownHostException, TextParseException {
		List<NAPTRRecord> pointers = new ArrayList<NAPTRRecord>();
		// UDP and TCP have the same order, but TCP is a lower preference, so should be used first.
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 1, "s", "SIP+D2U", "", new Name("_sip._udp.example.net.")));
		pointers.add(new NAPTRRecord(new Name("example.org."), DClass.IN, 1000L, 0, 0, "s", "SIP+D2T", "", new Name("_sip._tcp.example.net.")));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(pointers);
		expect(resolver.lookupSRVRecords(new Name("_sip._tcp.example.net."))).andReturn(new ArrayList<SRVRecord>());
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.net."))).andReturn(new ArrayList<SRVRecord>());
		expect(resolver.lookupARecords(new Name("example.org."))).andReturn(new HashSet<ARecord>());
		expect(resolver.lookupAAAARecords(new Name("example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Arrays.asList("UDP", "TCP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldLookupAddressFromSrvTarget() throws ParseException, UnknownHostException, TextParseException {
		List<SRVRecord> services = new ArrayList<SRVRecord>();
		services.add(new SRVRecord(new Name("_sip._udp.example.org."), DClass.IN, 1000L, 0, 0, 5060, new Name("sip.example.org.")));
		
		expect(resolver.lookupNAPTRRecords(new Name("example.org."))).andReturn(new ArrayList<NAPTRRecord>());
		expect(resolver.lookupSRVRecords(new Name("_sip._udp.example.org."))).andReturn(services);
		expect(resolver.lookupARecords(new Name("sip.example.org."))).andReturn(new HashSet<ARecord>());
		expect(resolver.lookupAAAARecords(new Name("sip.example.org."))).andReturn(Collections.<AAAARecord>emptySet());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
}
