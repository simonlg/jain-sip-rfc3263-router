package com.google.code.rfc3263;

import javax.sip.address.Hop;

class HopImpl implements Hop {
	private final String host;
	private final int port;
	private final String transport;
	
	public HopImpl(String host, int port, String transport) {
		this.host = host;
		this.port = port;
		this.transport= transport;
	}
	
	@Override
	public String getHost() {
		return host;
	}

	@Override
	public int getPort() {
		return port;
	}

	@Override
	public String getTransport() {
		return transport;
	}
	
	@Override
	public String toString() {
		return host + ":" + port + "/" + transport;
	}
}