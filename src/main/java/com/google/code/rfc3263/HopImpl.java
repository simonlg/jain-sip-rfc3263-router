package com.google.code.rfc3263;

import java.text.ParseException;

import javax.sip.address.Hop;

import net.jcip.annotations.Immutable;

import com.google.code.rfc3263.util.LocatorUtils;

/**
 * This is an implementation of the Hop interface.
 */
@Immutable
public class HopImpl implements Hop {
	private final String host;
	private final int port;
	private final String transport;
	
	public HopImpl(String host, int port, String transport) {
		this.host = host;
		this.port = port;
		if (transport != null) {
			this.transport= transport.toUpperCase();
		} else {
			this.transport= transport;
		}
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
		if (host.indexOf(":") == -1) {
			return host + ":" + port + "/" + transport;
		} else {
			return "[" + host + "]:" + port + "/" + transport;
		}
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
	 * 
	 * @param proxy the string to parse.
	 * @return the parsed Hop.
	 */
	public static Hop getInstance(String hop) throws ParseException {
		// Hops should use the [::1]:5060/TLS style.
		if (hop == null) {
			throw new ParseException("Failed to parse null hop", 0);
		}
		int closingSquareBracket = hop.indexOf("]");
		int portColon = hop.indexOf(":", closingSquareBracket);
		if (portColon == -1) {
			// We MUST have a colon before the port number.
			throw new ParseException("Missing port delimiter", -1);
		}
		int transportSlash = hop.indexOf("/", portColon);
		if (transportSlash == -1) {
			// We MUST have a forward slash before the transport.
			throw new ParseException("Missing transport delimiter", -1);
		}
		
		// Check the port number
		final String port = hop.substring(portColon + 1, transportSlash);
		final int portNum;
		try {
			 portNum = Integer.parseInt(port);			
		} catch (NumberFormatException e) {
			ParseException pe = new ParseException("Failed to parse port number", portColon);
			pe.initCause(e);
			
			throw pe;
		}
		// Check the port number range
		if (portNum < 0 || portNum > 65535) {
			throw new ParseException("Port number is not valid for TCP or UDP", portColon);
		}
		
		// Check the transport
		final String transport = hop.substring(transportSlash + 1);
		if (LocatorUtils.isKnownTransport(transport) == false) {
			throw new ParseException("Invalid transport", transportSlash);
		}
		
		final String address = hop.substring(0, portColon);
		if (LocatorUtils.isNumeric(address) == false && address.length() == 0) {
			throw new ParseException("Invalid host", 0);
		}
		
		if (LocatorUtils.isIPv6Reference(address)) {
			return new HopImpl(address.substring(1, address.length() - 1), portNum, transport);
		} else {
			return new HopImpl(address, portNum, transport);
		}
	}
}