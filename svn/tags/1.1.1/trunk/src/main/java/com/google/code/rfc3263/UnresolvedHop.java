package com.google.code.rfc3263;

import net.jcip.annotations.Immutable;

import org.xbill.DNS.Name;

/**
 * This is an unresolved hop which carries a dnsjava Name for its host.
 */
@Immutable
class UnresolvedHop {
	private final Name host;
	private final int port;
	private final String transport;
	
	public UnresolvedHop(Name host, int port, String transport) {
		this.host = host;
		this.port = port;
		this.transport= transport;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public Name getHost() {
		return host;
	}

	/**
	 * {@inheritDoc}
	 */
	public int getPort() {
		return port;
	}

	/**
	 * {@inheritDoc}
	 */
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
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		UnresolvedHop other = (UnresolvedHop) obj;
		if (host == null) {
			if (other.host != null)
				return false;
		} else if (!host.equals(other.host))
			return false;
		if (port != other.port)
			return false;
		if (transport == null) {
			if (other.transport != null)
				return false;
		} else if (!transport.equals(other.transport))
			return false;
		return true;
	}
}