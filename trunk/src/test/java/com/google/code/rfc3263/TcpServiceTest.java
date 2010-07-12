package com.google.code.rfc3263;

import javax.sip.address.Hop;

public class TcpServiceTest extends BaseTest {
	public TcpServiceTest() {
		super(new TcpServiceResolver());
	}
	
	@Override
	protected Hop getHopForHost() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, 5060, "UDP");
	}

	@Override
	protected Hop getHopForHostWithTransportAndPort() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, TEST_PORT, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForHostWithTransport() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, 5060, TEST_TRANSPORT);
	}

	@Override
	protected Hop getHopForHostWithPort() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, TEST_PORT, "UDP");
	}

	@Override
	protected Hop getHopForSecureHost() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, 5061, "TLS");
	}

	@Override
	protected Hop getHopForSecureHostWithTransportAndPort() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, TEST_PORT, TEST_SECURE_TRANSPORT);
	}

	@Override
	protected Hop getHopForSecureHostWithPort() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, TEST_PORT, TEST_SECURE_TRANSPORT);
	}

	@Override
	protected Hop getHopForSecureHostWithTransport() {
		return new HopImpl(TEST_RESOLVED_SERVICE_ADDRESS, 5061, TEST_SECURE_TRANSPORT);
	}
}
