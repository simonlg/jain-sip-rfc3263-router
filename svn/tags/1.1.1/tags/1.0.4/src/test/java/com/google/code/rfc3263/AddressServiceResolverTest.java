package com.google.code.rfc3263;

import javax.sip.ListeningPoint;
import javax.sip.address.Hop;

import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.AddressServiceResolver;

/**
 * Tests for location in the following DNS environment:
 * 
 * NAPTR	N
 * SRV		Y
 * A/AAAA	Y
 */
public class AddressServiceResolverTest extends AddressResolverTest {
	public AddressServiceResolverTest() {
		super(new AddressServiceResolver());
	}
	
	public AddressServiceResolverTest(Resolver resolver) {
		super(resolver);
	}
	
	@Override
	protected Hop getHopForHost() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, ListeningPoint.PORT_5060, ListeningPoint.TCP);
	}

	@Override
	protected Hop getHopForHostWithTransportAndPort() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, TEST_PORT, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForHostWithTransport() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, ListeningPoint.PORT_5060, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForHostWithPort() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, TEST_PORT, ListeningPoint.UDP);
	}

	@Override
	protected Hop getHopForSecureHost() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, ListeningPoint.PORT_5061, ListeningPoint.TLS);
	}

	@Override
	protected Hop getHopForSecureHostWithTransportAndPort() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, TEST_PORT, TEST_SECURE_TRANSPORT);
	}

	@Override
	protected Hop getHopForSecureHostWithPort() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, TEST_PORT, TEST_SECURE_TRANSPORT);
	}

	@Override
	protected Hop getHopForSecureHostWithTransport() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, ListeningPoint.PORT_5061, TEST_SECURE_TRANSPORT);
	}
}
