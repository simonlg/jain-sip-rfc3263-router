package com.google.code.rfc3263;

import java.util.ArrayList;
import java.util.List;

import javax.sip.address.Hop;

import com.google.code.rfc3263.dns.Resolver;

public class BaseTest extends AbstractTest {
	public BaseTest() {
		this(new BaseTestResolver());
	}
	
	public BaseTest(Resolver resolver) {
		super(resolver);
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
		return new HopImpl(TEST_RESOLVED_ADDRESS, 5060, "UDP");
	}

	@Override
	protected Hop getHopForHostWithTransportAndPort() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, TEST_PORT, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForHostWithTransport() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, 5060, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForHostWithPort() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, TEST_PORT, "UDP");
	}

	@Override
	protected Hop getHopForSecureHost() {
		return new HopImpl(TEST_RESOLVED_ADDRESS, 5061, "TLS");
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
		return new HopImpl(TEST_RESOLVED_ADDRESS, 5061, TEST_SECURE_TRANSPORT);
	}
}
