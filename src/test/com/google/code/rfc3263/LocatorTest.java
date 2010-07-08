package com.google.code.rfc3263;

import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import javax.sip.PeerUnavailableException;
import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;

import junit.framework.Assert;

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
	
	// Numeric Hosts

	@Test
	public void testSelectTransportNumericHostWithNonStandardPortAndTransportFlag() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setPort(1234);
		uri.setTransportParam("tcp");
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 1234, "TCP"), fixture.locate(uri).poll());
	}
	
	@Test
	public void testSelectTransportNumericHostWithNonStandardPortAndTransportFlagSecure() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setPort(1234);
		uri.setTransportParam("tcp");
		uri.setSecure(true);
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 1234, "TLS"), fixture.locate(uri).poll());
	}
	
	@Test
	public void testSelectTransportNumericHostWithStandardPortAndNoTransportFlag() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setPort(5060);
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 5060, "UDP"), fixture.locate(uri).poll());
	}
	
	@Test
	public void testSelectTransportNumericHostWithStandardPortAndNoTransportFlagSecure() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setPort(5060);
		uri.setSecure(true);
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 5060, "TLS"), fixture.locate(uri).poll());
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndTransportFlag() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setTransportParam("tcp");
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 5060, "TCP"), fixture.locate(uri).poll());
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndTransportFlagSecure() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setTransportParam("tcp");
		uri.setSecure(true);
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 5061, "TLS"), fixture.locate(uri).poll());
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndNoTransportFlag() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 5060, "UDP"), fixture.locate(uri).poll());
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndNoTransportFlagSecure() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setSecure(true);
		
		Assert.assertEquals(new HopImpl("192.168.0.1", 5061, "TLS"), fixture.locate(uri).poll());
	}
	
	// TARGET

	@Test
	public void testGetTargetMaddr() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		uri.setMAddrParam("192.168.0.2");
		
		Assert.assertEquals("192.168.0.2", fixture.getTarget(uri));
	}
	
	@Test
	public void testGetTargetNoMaddr() throws Exception {
		SipURI uri = addrFactory.createSipURI(null, "192.168.0.1");
		
		Assert.assertEquals("192.168.0.1", fixture.getTarget(uri));
	}
	
	// Is Numeric

	@Test
	public void testIsNumericIPv4() {
		Assert.assertTrue(fixture.isNumeric("192.168.0.1"));
	}
	
	@Test
	public void testIsNumericIPv6() {
		Assert.assertTrue(fixture.isNumeric("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6NoLeadingZeroes() {
		Assert.assertTrue(fixture.isNumeric("2001:db8:85a3:0:0:8a2e:370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6GroupedZeroes() {
		Assert.assertTrue(fixture.isNumeric("2001:db8:85a3::8a2e:370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6Loopback() {
		Assert.assertTrue(fixture.isNumeric("::1"));
	}
	
	@Test
	public void testIsNumericIPv6Unspecified() {
		Assert.assertTrue(fixture.isNumeric("::"));
	}
	
	@Test
	public void testIsNumericIPv6IPv4Mapping() {
		Assert.assertTrue(fixture.isNumeric("::ffff:192.0.2.128"));
	}
	
	@Test
	public void testIsNumericHost() {
		Assert.assertFalse(fixture.isNumeric("example.org"));
	}

}
