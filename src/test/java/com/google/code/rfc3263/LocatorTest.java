package com.google.code.rfc3263;

import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import javax.sip.PeerUnavailableException;
import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
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
	
	private void test(Queue<Hop> expectedQueue, SipURI uri) throws UnknownHostException {
		Queue<Hop> actualQueue = fixture.locate(uri);
		
		Assert.assertSame("Hop count mismatch for " + uri, expectedQueue.size(), actualQueue.size());
		
		int i = 0;
		while (expectedQueue.isEmpty() != true) {
			Hop expected = expectedQueue.poll();
			Hop actual = actualQueue.poll();
			
			Assert.assertEquals("Unexpected hop at offset " + i + " for " + uri, expected, actual);
			i++;
		}
	}
	
	private void test(Hop expected, SipURI uri) throws UnknownHostException {
		final Queue<Hop> hops = new LinkedList<Hop>();
		hops.add(expected);
		
		test(hops, uri);
	}
	
	// Expected to fail.
	@Test(expected = IllegalArgumentException.class)
	public void testSelectTransportNumericHostWithNonStandardPortAndUDPSecure() throws Exception {
		SipURI uri = createURI("192.168.0.1", "udp", true);
		
		test(new HopImpl("192.168.0.1", 1234, "UDP"), uri);
	}

	@Test
	public void testSelectTransportNumericHostWithNonStandardPortAndTransportFlag() throws Exception {
		SipURI uri = createURI("192.168.0.1", "tcp", 1234);
		
		test(new HopImpl("192.168.0.1", 1234, "TCP"), uri);
	}
	
	@Test
	public void testSelectTransportNumericHostWithNonStandardPortAndTransportFlagSecure() throws Exception {
		SipURI uri = createURI("192.168.0.1", "tcp", 1234, true);
		
		test(new HopImpl("192.168.0.1", 1234, "TLS"), uri);
	}
	
	@Test
	public void testSelectTransportNumericHostWithStandardPortAndNoTransportFlag() throws Exception {
		SipURI uri = createURI("192.168.0.1", 5060);
		
		test(new HopImpl("192.168.0.1", 5060, "UDP"), uri);
	}
	
	@Test
	public void testSelectTransportNumericHostWithStandardPortAndNoTransportFlagSecure() throws Exception {
		SipURI uri = createURI("192.168.0.1", 5060, true);
		
		test(new HopImpl("192.168.0.1", 5060, "TLS"), uri);
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndTransportFlag() throws Exception {
		SipURI uri = createURI("192.168.0.1", "tcp");
		
		test(new HopImpl("192.168.0.1", 5060, "TCP"), uri);
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndTransportFlagSecure() throws Exception {
		SipURI uri = createURI("192.168.0.1", "tcp", true); 
		
		test(new HopImpl("192.168.0.1", 5061, "TLS"), uri);
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndNoTransportFlag() throws Exception {
		SipURI uri = createURI("192.168.0.1");
		
		test(new HopImpl("192.168.0.1", 5060, "UDP"), uri);
	}
	
	@Test
	public void testSelectTransportNumericHostWithNoPortAndNoTransportFlagSecure() throws Exception {
		SipURI uri = createURI("192.168.0.1", true);
		
		test(new HopImpl("192.168.0.1", 5061, "TLS"), uri);
	}
	
	private SipURI createURI(String host) throws ParseException {
		return createURI(host, null, -1, false);
	}
	
	private SipURI createURI(String host, int port) throws ParseException {
		return createURI(host, null, port, false);
	}
	
	private SipURI createURI(String host, String transport) throws ParseException {
		return createURI(host, transport, -1, false);
	}
	
	private SipURI createURI(String host, boolean isSecure) throws ParseException {
		return createURI(host, null, -1, isSecure);
	}
	
	private SipURI createURI(String host, String transport, boolean isSecure) throws ParseException {
		return createURI(host, transport, -1, isSecure);
	}
	
	private SipURI createURI(String host, int port, boolean isSecure) throws ParseException {
		return createURI(host, null, port, isSecure);
	}
	
	private SipURI createURI(String host, String transport, int port) throws ParseException {
		return createURI(host, transport, port, false);
	}
	
	private SipURI createURI(String host, String transport, int port, boolean isSecure) throws ParseException {
		SipURI uri = addrFactory.createSipURI(null, host);
		if (transport != null) {
			uri.setTransportParam(transport);
		}
		if (port != -1) {
			uri.setPort(port);
		}
		uri.setSecure(isSecure);
		
		return uri;
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
}
