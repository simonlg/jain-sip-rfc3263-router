package com.google.code.rfc3263;

import static org.junit.Assert.fail;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.sip.PeerUnavailableException;
import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;

import org.junit.Before;
import org.junit.Test;

import com.google.code.rfc3263.dns.DefaultResolver;

public class LocatorTest {
	private Locator fixture;
	private AddressFactory addrFactory;
	
	@Before
	public void setUp() throws PeerUnavailableException {
		SipFactory factory = SipFactory.getInstance();
		
		addrFactory = factory.createAddressFactory();
		final List<String> transports = new ArrayList<String>();
		transports.add("UDP");
		transports.add("TLS");
		transports.add("TCP");
		
		fixture = new Locator(new DefaultResolver(), transports);
	}

	@Test
	public void testSelectTransport() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "cisco.com");
		fixture.locate(uri);
	}

	@Test
	public void testGetTarget() {
		fail("Not yet implemented");
	}

	@Test
	public void testIsNumeric() {
		fail("Not yet implemented");
	}

}
