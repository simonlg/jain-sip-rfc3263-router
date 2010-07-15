package com.google.code.rfc3263;

import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.List;

import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.apache.log4j.BasicConfigurator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.rfc3263.dns.Resolver;

public abstract class AbstractResolverTest {
	public final static String TEST_USER = "alice";
	public final static String TEST_HOST = "atlanta.com";
	public final static String TEST_ADDRESS = "192.168.0.1";
	public final static String TEST_RESOLVED_ADDRESS = "192.168.0.2";
	public final static String TEST_RESOLVED_SERVICE_ADDRESS = "192.168.0.3";
	public final static String TEST_TRANSPORT = "TCP";
	public final static String TEST_SECURE_TRANSPORT = "TLS";
	public final static int TEST_PORT = 15060;
	
	private final Resolver resolver;
	private Locator locator;
	private AddressFactory addressFactory;
	
	public AbstractResolverTest(Resolver resolver) {
		this.resolver = resolver;
	}
	
	@BeforeClass
	public static void configureLogging() {
		BasicConfigurator.configure();
	}
	
	@Before
	public void setUp() throws Exception {
		SipFactory factory = SipFactory.getInstance();
		addressFactory = factory.createAddressFactory();
		locator = new Locator(resolver, getTransports());
	}
	
	private void test(Hop expected, SipURI uri) throws UnknownHostException {
		Assert.assertEquals(expected, locator.locate(uri));
	}
	
	private SipURI getNumericURI() throws ParseException {
		return addressFactory.createSipURI(null, TEST_ADDRESS);
	}
	
	private SipURI getNonNumericURI() throws ParseException {
		return addressFactory.createSipURI(TEST_USER, TEST_HOST);
	}
	
	@Test
	public void testNumericHost() throws Exception {
		final SipURI uri = getNumericURI();
		
		test(getHopForNumericHost(), uri);
	}
	
	@Test
	public void testNumericHostWithPortAndTransport() throws Exception {
		final SipURI uri = getNumericURI();
		uri.setPort(TEST_PORT);
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForNumericHostWithTransportAndPort(), uri);
	}
	
	@Test
	public void testNumericHostWithPort() throws Exception {
		final SipURI uri = getNumericURI();
		uri.setPort(TEST_PORT);
		
		test(getHopForNumericHostWithPort(), uri);
	}

	@Test
	public void testNumericHostWithTransport() throws Exception {
		final SipURI uri = getNumericURI();
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForNumericHostWithTransport(), uri);
	}
	
	@Test
	public void testSecureNumericHost() throws Exception {
		final SipURI uri = getNumericURI();
		uri.setSecure(true);
		
		test(getHopForSecureNumericHost(), uri);
	}
	
	@Test
	public void testSecureNumericHostWithPortAndTransport() throws Exception {
		final SipURI uri = getNumericURI();
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForSecureNumericHostWithTransportAndPort(), uri);
	}
	
	@Test
	public void testSecureNumericHostWithPort() throws Exception {
		final SipURI uri = getNumericURI();
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		
		test(getHopForSecureNumericHostWithPort(), uri);
	}

	@Test
	public void testSecureNumericHostWithTransport() throws Exception {
		final SipURI uri = getNumericURI();
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForSecureNumericHostWithTransport(), uri);
	}
	
	@Test
	public void testHost() throws Exception {
		final SipURI uri = getNonNumericURI();
		
		test(getHopForHost(), uri);
	}
	
	@Test
	public void testHostWithPortAndTransport() throws Exception {
		final SipURI uri = getNonNumericURI();
		uri.setPort(TEST_PORT);
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForHostWithTransportAndPort(), uri);
	}
	
	@Test
	public void testHostWithPort() throws Exception {
		final SipURI uri = getNonNumericURI();
		uri.setPort(TEST_PORT);
		
		test(getHopForHostWithPort(), uri);
	}

	@Test
	public void testHostWithTransport() throws Exception {
		final SipURI uri = getNonNumericURI();
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForHostWithTransport(), uri);
	}
	
	@Test
	public void testSecureHost() throws Exception {
		final SipURI uri = getNonNumericURI();
		uri.setSecure(true);
		
		test(getHopForSecureHost(), uri);
	}
	
	@Test
	public void testSecureHostWithPortAndTransport() throws Exception {
		final SipURI uri = getNonNumericURI();
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForSecureHostWithTransportAndPort(), uri);
	}
	
	@Test
	public void testSecureHostWithPort() throws Exception {
		final SipURI uri = getNonNumericURI();
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		
		test(getHopForSecureHostWithPort(), uri);
	}

	@Test
	public void testSecureHostWithTransport() throws Exception {
		final SipURI uri = getNonNumericURI();
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		test(getHopForSecureHostWithTransport(), uri);
	}
	
	protected abstract Hop getHopForNumericHost();
	protected abstract Hop getHopForNumericHostWithTransportAndPort();
	protected abstract Hop getHopForNumericHostWithPort();
	protected abstract Hop getHopForNumericHostWithTransport();
	protected abstract Hop getHopForSecureNumericHost();
	protected abstract Hop getHopForSecureNumericHostWithTransportAndPort();
	protected abstract Hop getHopForSecureNumericHostWithPort();
	protected abstract Hop getHopForSecureNumericHostWithTransport();
	protected abstract Hop getHopForHost();
	protected abstract Hop getHopForHostWithTransportAndPort();
	protected abstract Hop getHopForHostWithPort();
	protected abstract Hop getHopForHostWithTransport();
	protected abstract Hop getHopForSecureHost();
	protected abstract Hop getHopForSecureHostWithTransportAndPort();
	protected abstract Hop getHopForSecureHostWithPort();
	protected abstract Hop getHopForSecureHostWithTransport();
	protected abstract List<String> getTransports();
}
