package com.google.code.rfc3263;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.hamcrest.CoreMatchers.is;
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

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

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
	public void testShouldUseTlsIfNonNumericSomeNaptrRecordsNoSrvRecordsAndIsSecure() throws ParseException, UnknownHostException {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		pointers.add(new PointerRecord("example.org.", 0, 0, "s", "SIPS+D2T", "", "_sips._tcp.example.org."));
		
		Set<AddressRecord> addresses = new HashSet<AddressRecord>();
		addresses.add(new AddressRecord("example.org.", InetAddress.getLocalHost()));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(pointers);
		expect(resolver.lookupServiceRecords("_sips._tcp.example.org.")).andReturn(Collections.<ServiceRecord>emptyList());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(addresses);
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		uri.setSecure(true);
		
		Locator locator = new Locator(resolver, Collections.singletonList("TLS"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TLS"));
	}
	
	@Test
	public void testShouldUseUdpIfNonNumericSomeNaptrRecordsNoSrvRecordsAndIsInsecure() throws ParseException, UnknownHostException {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		pointers.add(new PointerRecord("example.org.", 0, 0, "s", "SIP+D2U", "", "_sip._udp.example.org."));
		
		Set<AddressRecord> addresses = new HashSet<AddressRecord>();
		addresses.add(new AddressRecord("example.org.", InetAddress.getLocalHost()));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(pointers);
		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(Collections.<ServiceRecord>emptyList());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(addresses);
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("UDP"));
	}
	
	@Test
	public void testShouldUseTransportFromSrvIfNonNumericSomeNaptrRecordsSomeSrvRecordsAndIsInsecure() throws ParseException, UnknownHostException {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		pointers.add(new PointerRecord("example.org.", 0, 0, "s", "SIP+D2T", "", "_sip._tcp.example.org."));
		
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		services.add(new ServiceRecord("_sip._tcp.example.org.", 0, 0, 5060, "example.org."));
		
		Set<AddressRecord> addresses = new HashSet<AddressRecord>();
		addresses.add(new AddressRecord("example.org.", InetAddress.getLocalHost()));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(pointers);
		expect(resolver.lookupServiceRecords("_sip._tcp.example.org.")).andReturn(services);
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(addresses);
		replay(resolver);
		
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Arrays.asList("TCP"));
		Queue<Hop> hops = locator.locate(uri);
		Hop hop = hops.peek();
		
		assertThat(hop.getTransport(), is("TCP"));
	}
	
	@Test
	public void testShouldUseTransportFromSrvIfNonNumericNoNaptrRecordsSomeSrvRecordsAndIsInsecure() throws ParseException, UnknownHostException {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		services.add(new ServiceRecord("_sip._tcp.example.org.", 0, 0, 5060, "example.org."));
		
		Set<AddressRecord> addresses = new HashSet<AddressRecord>();
		addresses.add(new AddressRecord("example.org.", InetAddress.getLocalHost()));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(Collections.<PointerRecord>emptyList());
		expect(resolver.lookupServiceRecords("_sip._tcp.example.org.")).andReturn(services);
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(addresses);
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
	public void testShouldLookupAddressWhenPortPresent() throws ParseException, UnknownHostException {
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		uri.setPort(5060);
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldLookupDefaultSrvWhenNoNaptr() throws ParseException, UnknownHostException {
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(new ArrayList<PointerRecord>());
		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(new ArrayList<ServiceRecord>());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldLookupSrvFromNaptrReplacement() throws ParseException, UnknownHostException {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		pointers.add(new PointerRecord("example.org.", 0, 0, "s", "SIP+D2U", "", "_sip._udp.example.net."));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(pointers);
		expect(resolver.lookupServiceRecords("_sip._udp.example.net.")).andReturn(new ArrayList<ServiceRecord>());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldUseLowestOrderNaptr() throws ParseException, UnknownHostException {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		// TCP is a lower order, so should be used first.
		pointers.add(new PointerRecord("example.org.", 1, 0, "s", "SIP+D2U", "", "_sip._udp.example.net."));
		pointers.add(new PointerRecord("example.org.", 0, 0, "s", "SIP+D2T", "", "_sip._tcp.example.net."));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(pointers);
		expect(resolver.lookupServiceRecords("_sip._tcp.example.net.")).andReturn(new ArrayList<ServiceRecord>());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Arrays.asList("UDP", "TCP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldUseLowestPreferenceNaptr() throws ParseException, UnknownHostException {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		// UDP and TCP have the same order, but TCP is a lower preference, so should be used first.
		pointers.add(new PointerRecord("example.org.", 0, 1, "s", "SIP+D2U", "", "_sip._udp.example.net."));
		pointers.add(new PointerRecord("example.org.", 0, 0, "s", "SIP+D2T", "", "_sip._tcp.example.net."));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(pointers);
		expect(resolver.lookupServiceRecords("_sip._tcp.example.net.")).andReturn(new ArrayList<ServiceRecord>());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Arrays.asList("UDP", "TCP"));
		locator.locate(uri);
	}
	
	@Test
	public void testShouldLookupAddressFromSrvTarget() throws ParseException, UnknownHostException {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		services.add(new ServiceRecord("_sip._udp.example.org", 0, 0, 5060, "sip.example.org."));
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(new ArrayList<PointerRecord>());
		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(services);
		expect(resolver.lookupAddressRecords("sip.example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
	}
}
