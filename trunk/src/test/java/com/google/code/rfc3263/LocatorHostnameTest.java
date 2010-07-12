package com.google.code.rfc3263;


import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;

import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

public class LocatorHostnameTest {
	private Locator fixture;
	private Resolver resolver;
	private AddressFactory addrFactory;

	@Before
	public void setUp() throws Exception {
		resolver = EasyMock.createMock(Resolver.class);
		
		SortedSet<PointerRecord> pointers = new TreeSet<PointerRecord>();
		pointers.add(new PointerRecord("example.org", 1, 1, "s", "SIP+D2U", "", "_sip._udp.example.org."));
		pointers.add(new PointerRecord("example.org", 1, 1, "s", "SIP+D2T", "", "_sip._tcp.example.org."));
		pointers.add(new PointerRecord("example.org", 1, 1, "s", "SIPS+D2T", "", "_sips._tcp.example.org."));
		EasyMock.expect(resolver.lookupPointerRecords("example.org")).andReturn(pointers).anyTimes();
		
		SortedSet<ServiceRecord> udpServices = new TreeSet<ServiceRecord>();
		udpServices.add(new ServiceRecord("_sip._udp.example.org.", 1, 1, 5060, "sip.example.org."));
		EasyMock.expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(udpServices).anyTimes();
		
		SortedSet<ServiceRecord> tcpServices = new TreeSet<ServiceRecord>();
		tcpServices.add(new ServiceRecord("_sip._tcp.example.org.", 1, 1, 5060, "sip.example.org."));
		EasyMock.expect(resolver.lookupServiceRecords("_sip._tcp.example.org.")).andReturn(tcpServices).anyTimes();
		
		SortedSet<ServiceRecord> tlsServices = new TreeSet<ServiceRecord>();
		tlsServices.add(new ServiceRecord("_sips._tcp.example.org.", 1, 1, 5061, "sip.example.org."));
		EasyMock.expect(resolver.lookupServiceRecords("_sips._tcp.example.org.")).andReturn(tlsServices).anyTimes();
		
		Set<AddressRecord> addresses = new HashSet<AddressRecord>();
		addresses.add(new AddressRecord("sip.example.org.", InetAddress.getByName("192.168.0.1")));
		EasyMock.expect(resolver.lookupAddressRecords("sip.example.org.")).andReturn(addresses).anyTimes();
		
		EasyMock.replay(resolver);
		
		final SipFactory factory = SipFactory.getInstance();
		addrFactory = factory.createAddressFactory();
		
		final List<String> transports = new ArrayList<String>();
		transports.add("UDP");
		transports.add("TLS");
		transports.add("TCP");
		
		fixture = new Locator(resolver, transports);
	}
	
	@After
	public void tearDown() {
		EasyMock.verify(resolver);
	}
	
	@Test
	public void testHost() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "example.org");
		
		fixture.locate(uri);
	}

}
