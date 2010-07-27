package com.google.code.rfc3263;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import javax.sip.PeerUnavailableException;
import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;

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
	
	@Before
	public void setUp() throws PeerUnavailableException {
		SipFactory factory = SipFactory.getInstance();
		addressFactory = factory.createAddressFactory();
	}
	
	@Test
	public void testShouldNotLookupNumericHost() throws ParseException, UnknownHostException {
		Resolver resolver = createMock(Resolver.class);
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
		
		verify(resolver);
	}
	
	@Test
	public void testShouldLookupAddressWhenPortPresent() throws ParseException, UnknownHostException {
		Resolver resolver = createMock(Resolver.class);
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		uri.setPort(5060);
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
		
		verify(resolver);
	}
	
	@Test
	public void testShouldLookupDefaultSrvWhenNoNaptr() throws ParseException, UnknownHostException {
		Resolver resolver = createMock(Resolver.class);
		expect(resolver.lookupPointerRecords("example.org")).andReturn(new ArrayList<PointerRecord>());
		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(new ArrayList<ServiceRecord>());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
		
		verify(resolver);
	}
	
	@Test
	public void testShouldLookupSrvFromNaptrReplacement() throws ParseException, UnknownHostException {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		pointers.add(new PointerRecord("example.org.", 0, 0, "s", "SIP+D2U", "", "_sip._udp.example.net."));
		
		Resolver resolver = createMock(Resolver.class);
		expect(resolver.lookupPointerRecords("example.org")).andReturn(pointers);
		expect(resolver.lookupServiceRecords("_sip._udp.example.net.")).andReturn(new ArrayList<ServiceRecord>());
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
		
		verify(resolver);
	}
	
	@Test
	public void testShouldLookupAddressFromSrvTarget() throws ParseException, UnknownHostException {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		services.add(new ServiceRecord("_sip._udp.example.org", 0, 0, 5060, "sip.example.org."));
		
		Resolver resolver = createMock(Resolver.class);
		expect(resolver.lookupPointerRecords("example.org")).andReturn(new ArrayList<PointerRecord>());
		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(services);
		expect(resolver.lookupAddressRecords("sip.example.org.")).andReturn(new HashSet<AddressRecord>());
		replay(resolver);

		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Locator locator = new Locator(resolver, Collections.singletonList("UDP"));
		locator.locate(uri);
		
		verify(resolver);
	}
}
