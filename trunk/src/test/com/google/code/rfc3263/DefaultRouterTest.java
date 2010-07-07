package com.google.code.rfc3263;

import java.text.ParseException;
import java.util.Properties;

import javax.sip.InvalidArgumentException;
import javax.sip.ListeningPoint;
import javax.sip.PeerUnavailableException;
import javax.sip.SipFactory;
import javax.sip.SipStack;
import javax.sip.TransportNotSupportedException;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

public class DefaultRouterTest {
	private DefaultRouter fixture;
	private AddressFactory addressFactory;
	private ListeningPoint tcp;
	private ListeningPoint udp;
	private ListeningPoint tls;
	
	@Before
	public void setUp() throws PeerUnavailableException, TransportNotSupportedException, InvalidArgumentException {
		final SipFactory sf = SipFactory.getInstance();
		final Properties properties = new Properties();
		properties.setProperty("javax.sip.STACK_NAME", "JUnit");
		final SipStack sipStack = sf.createSipStack(properties);
		tcp = sipStack.createListeningPoint("192.168.30.138", 5060, "TCP");
		udp = sipStack.createListeningPoint("192.168.30.138", 5060, "UDP");
		tls = sipStack.createListeningPoint("192.168.30.138", 5061, "TLS");
		
		addressFactory = sf.createAddressFactory();
		fixture = new DefaultRouter(sipStack, null);
	}

	@Test
	public void testSelectTransport() throws ParseException {
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		fixture.selectTransport(uri);
	}

	@Test
	public void testGetTarget() throws ParseException {
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		
		Assert.assertEquals("example.org", fixture.getTarget(uri));
	}
	
	@Test
	public void testGetTargetMaddr() throws ParseException {
		SipURI uri = addressFactory.createSipURI(null, "example.org");
		uri.setMAddrParam("sip.mcast.net");
		
		Assert.assertEquals("sip.mcast.net", fixture.getTarget(uri));
	}

	@Test
	public void testIsNumericHost() {
		Assert.assertFalse(fixture.isNumeric("example.org"));
	}
	
	@Test
	public void testIsNumericHostInvalid() {
		Assert.assertFalse(fixture.isNumeric("example.invalid"));
	}
	
	@Test
	public void testIsNumericIPv4() {
		Assert.assertTrue(fixture.isNumeric("192.0.32.10"));
	}
	
	@Test
	public void testIsNumericIPv6() {
		Assert.assertTrue(fixture.isNumeric("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6GroupsOfZeroes() {
		Assert.assertTrue(fixture.isNumeric("2001:db8:85a3::8a2e:370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6DottedQuad() {
		Assert.assertTrue(fixture.isNumeric("::ffff:192.0.2.128"));
	}
}
