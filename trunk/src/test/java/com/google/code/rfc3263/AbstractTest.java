package com.google.code.rfc3263;

import java.util.List;

import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.code.rfc3263.dns.Resolver;

public abstract class AbstractTest {
	protected final static String TEST_HOST = "example.org";
	protected final static String TEST_ADDRESS = "192.168.0.1";
	protected final static String TEST_RESOLVED_ADDRESS = "192.168.0.2";
	protected final static String TEST_RESOLVED_SERVICE_ADDRESS = "192.168.0.3";
	protected final static String TEST_TRANSPORT = "TCP";
	protected final static String TEST_SECURE_TRANSPORT = "TLS";
	protected final static int TEST_PORT = 15060;
	
	private final Resolver resolver;
	private Locator locator;
	private AddressFactory addressFactory;
	
	public AbstractTest(Resolver resolver) {
		this.resolver = resolver;
	}
	
	@Before
	public void setUp() throws Exception {
		SipFactory factory = SipFactory.getInstance();
		addressFactory = factory.createAddressFactory();
		locator = new Locator(resolver, getTransports());
	}
	
	@Test
	public void testNumericHost() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		
		Assert.assertEquals(getHopForNumericHost(), locator.locate(uri).poll());
	}
	
	@Test
	public void testNumericHostWithPortAndTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		uri.setPort(TEST_PORT);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForNumericHostWithTransportAndPort(), locator.locate(uri).poll());
	}
	
	@Test
	public void testNumericHostWithPort() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		uri.setPort(TEST_PORT);
		
		Assert.assertEquals(getHopForNumericHostWithPort(), locator.locate(uri).poll());
	}

	@Test
	public void testNumericHostWithTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForNumericHostWithTransport(), locator.locate(uri).poll());
	}
	
	@Test
	public void testSecureNumericHost() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		uri.setSecure(true);
		
		Assert.assertEquals(getHopForSecureNumericHost(), locator.locate(uri).poll());
	}
	
	@Test
	public void testSecureNumericHostWithPortAndTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForSecureNumericHostWithTransportAndPort(), locator.locate(uri).poll());
	}
	
	@Test
	public void testSecureNumericHostWithPort() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		
		Assert.assertEquals(getHopForSecureNumericHostWithPort(), locator.locate(uri).poll());
	}

	@Test
	public void testSecureNumericHostWithTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_ADDRESS);
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForSecureNumericHostWithTransport(), locator.locate(uri).poll());
	}
	
	@Test
	public void testHost() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		
		Assert.assertEquals(getHopForHost(), locator.locate(uri).poll());
	}
	
	@Test
	public void testHostWithPortAndTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		uri.setPort(TEST_PORT);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForHostWithTransportAndPort(), locator.locate(uri).poll());
	}
	
	@Test
	public void testHostWithPort() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		uri.setPort(TEST_PORT);
		
		Assert.assertEquals(getHopForHostWithPort(), locator.locate(uri).poll());
	}

	@Test
	public void testHostWithTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForHostWithTransport(), locator.locate(uri).poll());
	}
	
	@Test
	public void testSecureHost() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		uri.setSecure(true);
		
		Assert.assertEquals(getHopForSecureHost(), locator.locate(uri).poll());
	}
	
	@Test
	public void testSecureHostWithPortAndTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForSecureHostWithTransportAndPort(), locator.locate(uri).poll());
	}
	
	@Test
	public void testSecureHostWithPort() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		uri.setPort(TEST_PORT);
		uri.setSecure(true);
		
		Assert.assertEquals(getHopForSecureHostWithPort(), locator.locate(uri).poll());
	}

	@Test
	public void testSecureHostWithTransport() throws Exception {
		final SipURI uri = addressFactory.createSipURI(null, TEST_HOST);
		uri.setSecure(true);
		uri.setTransportParam(TEST_TRANSPORT);
		
		Assert.assertEquals(getHopForSecureHostWithTransport(), locator.locate(uri).poll());
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
