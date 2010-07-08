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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((host == null) ? 0 : host.hashCode());
		result = prime * result + port;
		result = prime * result
				+ ((transport == null) ? 0 : transport.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof HopImpl)) {
			return false;
		}
		HopImpl other = (HopImpl) obj;
		if (host == null) {
			if (other.host != null) {
				return false;
			}
		} else if (!host.equals(other.host)) {
			return false;
		}
		if (port != other.port) {
			return false;
		}
		if (transport == null) {
			if (other.transport != null) {
				return false;
			}
		} else if (!transport.equals(other.transport)) {
			return false;
		}
		return true;
	}
}