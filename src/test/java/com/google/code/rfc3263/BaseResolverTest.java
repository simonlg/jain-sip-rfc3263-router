package com.google.code.rfc3263;

import java.util.ArrayList;
import java.util.List;

import javax.sip.address.Hop;

import com.google.code.rfc3263.dns.BaseResolver;
import com.google.code.rfc3263.dns.Resolver;

/**
 * Tests for location in the following DNS environment:
 * 
 * NAPTR	N
 * SRV		N
 * A/AAAA	N
 */
public class BaseResolverTest extends AbstractResolverTest {
	public Resolver getResolver() {
		return new BaseResolver();
	}
	
	@Override
	protected List<String> getTransports() {
		final List<String> transports = new ArrayList<String>();
		transports.add("TLS");
		transports.add("TCP");
		transports.add("UDP");

		return transports;
	}
	
	@Override
	protected Hop getHopForNumericHost() {
		return new HopImpl(TEST_ADDRESS, 5060, "UDP");
	}

	@Override
	protected Hop getHopForNumericHostWithTransportAndPort() {
		return new HopImpl(TEST_ADDRESS, TEST_PORT, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForNumericHostWithTransport() {
		return new HopImpl(TEST_ADDRESS, 5060, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForNumericHostWithPort() {
		return new HopImpl(TEST_ADDRESS, TEST_PORT, "UDP");
	}

	@Override
	protected Hop getHopForSecureNumericHost() {
		return new HopImpl(TEST_ADDRESS, 5061, "TLS");
	}

	@Override
	protected Hop getHopForSecureNumericHostWithTransportAndPort() {
		return new HopImpl(TEST_ADDRESS, TEST_PORT, TEST_SECURE_TRANSPORT);
	}

	@Override
	protected Hop getHopForSecureNumericHostWithPort() {
		return new HopImpl(TEST_ADDRESS, TEST_PORT, TEST_SECURE_TRANSPORT);
	}

	@Override
	protected Hop getHopForSecureNumericHostWithTransport() {
		return new HopImpl(TEST_ADDRESS, 5061, TEST_SECURE_TRANSPORT);
	}
	
	@Override
	protected Hop getHopForHost() {
		return null;
	}

	@Override
	protected Hop getHopForHostWithTransportAndPort() {
		return null;
	}

	@Override
	protected Hop getHopForHostWithTransport() {
		return null;
	}

	@Override
	protected Hop getHopForHostWithPort() {
		return null;
	}

	@Override
	protected Hop getHopForSecureHost() {
		return null;
	}

	@Override
	protected Hop getHopForSecureHostWithTransportAndPort() {
		return null;
	}

	@Override
	protected Hop getHopForSecureHostWithPort() {
		return null;
	}

	@Override
	protected Hop getHopForSecureHostWithTransport() {
		return null;
	}
}
