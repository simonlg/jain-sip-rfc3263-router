package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

import javax.sip.address.Hop;

/**
 * This interface is used for exposing a hop-parsing mechanism. 
 */
public class HopParser {
	private static Set<String> transports = new HashSet<String>();
	static {
		transports.add("UDP");
		transports.add("TCP");
		transports.add("TLS");
		transports.add("SCTP");
		transports.add("TLS-SCTP");
	}
	
	/**
	 * Parses the provided string into a Hop.
	 * 
	 * @param proxy the string to parse.
	 * @return the parsed Hop.
	 */
	static Hop parseHop(String hop) throws ParseException {
		if (hop == null) {
			throw new ParseException("Failed to parse null hop", 0);
		}
		if (hop.indexOf('/') == -1) {
			throw new ParseException("Failed to parse transport", -1);
		}
		int transportStartsAt = hop.lastIndexOf('/');
		String transport = hop.substring(transportStartsAt + 1);
		if (transports.contains(transport) == false) {
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
