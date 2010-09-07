package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;

import javax.sip.address.Hop;

import com.google.code.rfc3263.util.LocatorUtils;

import net.jcip.annotations.Immutable;

/**
 * This is an implementation of the Hop interface.
 */
@Immutable
class HopImpl implements Hop {
	private final String host;
	private final int port;
	private final String transport;
	
	public HopImpl(String host, int port, String transport) {
		this.host = host;
		this.port = port;
		this.transport= transport;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String getHost() {
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

	/**
	 * Parses the provided string into a Hop.
	 * <p>
	 * It's not quite clear how IPv6 hops should be parsed.
	 * 
	 * @param proxy the string to parse.
	 * @return the parsed Hop.
	 */
	static Hop getInstance(String hop) throws ParseException {
		if (hop == null) {
			throw new ParseException("Failed to parse null hop", 0);
		}
		if (hop.indexOf('/') == -1) {
			throw new ParseException("Failed to parse transport", -1);
		}
		int transportStartsAt = hop.lastIndexOf('/');
		String transport = hop.substring(transportStartsAt + 1);
		if (LocatorUtils.isKnownTransport(transport) == false) {
			throw new ParseException("Invalid transport", transportStartsAt);
		}
		
		// Can't search for the index of a colon to guarantee a port exists, as
		// we might have an IPv6 address.  We'll find an error when we try to
		// parse the port number as an int.
		int portStartsAt = hop.lastIndexOf(':');
		String port = hop.substring(portStartsAt + 1, transportStartsAt);
		int portNum;
		try {
			 portNum = Integer.parseInt(port);			
		} catch (NumberFormatException e) {
			ParseException pe = new ParseException("Failed to parse port number", portStartsAt);
			pe.initCause(e);
			
			throw pe;
		}
		// Now, what constitutes a valid port number?
		if (portNum < 0 || portNum > 65535) {
			throw new ParseException("Port number is not valid for TCP or UDP", portStartsAt);
		}
		
		String address = hop.substring(0, portStartsAt);
		try {
			InetAddress inetAddress = InetAddress.getByName(address);
			String[] parts = inetAddress.toString().split("\\/");
			if (parts[0].isEmpty() == false) {
				throw new ParseException("Address was not an IP address", 0);
			}
		} catch (UnknownHostException e) {
			throw new ParseException("Address was not an IP address", 0);
		}
		
		return new HopImpl(address, portNum, transport);
	}
}