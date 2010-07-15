package com.google.code.rfc3263;

import java.util.ArrayList;
import java.util.List;

import javax.sip.ListeningPoint;
import javax.sip.address.Hop;

import com.google.code.rfc3263.dns.AddressResolver;
import com.google.code.rfc3263.dns.Resolver;

/**
 * Tests for location in the following DNS environment:
 * 
 * NAPTR	N
 * SRV		N
 * A/AAAA	Y
 */
public class AddressResolverTest extends BaseResolverTest {
	public AddressResolverTest() {
		this(new AddressResolver());
	}
	
	public AddressResolverTest(Resolver resolver) {
		super(resolver);
	}
	
	@Override
	protected List<String> getTransports() {
		final List<String> transports = new ArrayList<String>();
		transports.add(ListeningPoint.TLS);
		transports.add(ListeningPoint.TCP);
		transports.add(ListeningPoint.UDP);

		return transports;
	}
	
	@Override
	protected Hop getHopForHost() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, ListeningPoint.PORT_5060, ListeningPoint.UDP);
	}

	@Override
	protected Hop getHopForHostWithTransportAndPort() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, TEST_PORT, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForHostWithTransport() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, ListeningPoint.PORT_5060, TEST_TRANSPORT);
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
