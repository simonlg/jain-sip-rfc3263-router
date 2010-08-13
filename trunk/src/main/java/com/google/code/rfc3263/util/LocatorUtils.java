package com.google.code.rfc3263.util;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.sip.address.SipURI;

import org.apache.log4j.Logger;

public final class LocatorUtils {
	private final static Logger LOGGER = Logger.getLogger(LocatorUtils.class);
	private final static Set<String> knownTransports = new HashSet<String>();
	static {
		knownTransports.add("UDP");
		knownTransports.add("TCP");
		knownTransports.add("TLS");
		knownTransports.add("SCTP");
		knownTransports.add("SCTP-TLS");
	}
	
	private LocatorUtils() {}

	public static boolean isNumeric(String target) {
		LOGGER.debug("isNumeric? " + target);
		boolean numeric = LocatorUtils.isIPv4Address(target) || LocatorUtils.isIPv6Reference(target);
		LOGGER.debug("isNumeric? " + target + ": " + numeric);
		
		return numeric;
	}

	private static boolean isIPv4Address(String host) {
		// RFC 2234, Section 6.1
		//
		// DIGIT          =  %x30-39
		//
		// RFC 3261, Section 25.1
		//
		// IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
		String ipv4address = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}";
		
		LOGGER.debug("isIPv4Address? " + host);
		
		final Pattern p = Pattern.compile(ipv4address);
		final Matcher m = p.matcher(host);
		boolean matches = m.matches();
		
		LOGGER.debug("isIPv4Address? " + host + ": " + matches);
		
		return matches;
	}

	public static boolean isIPv6Reference(String host) {
		// RFC 2234, Section 6.1
		//
		// DIGIT          =  %x30-39
		// HEXDIG         =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
		String hexdig = "[0-9A-F]";
	
		// RFC 3261, Section 25.1
		//
		// IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
		String ipv4address = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}";
		// hex4           =  1*4HEXDIG
		String hex4 = hexdig + "{1,4}";
		// hexseq         =  hex4 *( ":" hex4)
		String hexseq = hex4 + "(:" + hex4 + ")*";
		// hexpart        =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
		String hexpart = "(" + hexseq + "|" + hexseq + "::(" + hexseq + ")?|::(" + hexseq + ")?)";
		// IPv6address    =  hexpart [ ":" IPv4address ]
		String ipv6address = hexpart + "(:" + ipv4address + ")?";
		// IPv6reference  =  "[" IPv6address "]"
		String ipv6reference = "\\[" + ipv6address + "\\]";
		
		LOGGER.debug("isIPv6Reference? " + host);
		
		final Pattern p = Pattern.compile(ipv6reference, Pattern.CASE_INSENSITIVE);
		final Matcher m = p.matcher(host);
		boolean matches = m.matches();
		
		LOGGER.debug("isIPv6Reference? " + host + ": " + matches);
		
		return matches;
	}
	
	private static void checkTransport(String transport) {
		if (knownTransports.contains(transport.toUpperCase()) == false) {
			throw new IllegalArgumentException("Unknown transport: " + transport);
		}
	}

	public static int getDefaultPortForTransport(String transport) {
		LOGGER.debug("Determining default port for " + transport);
		checkTransport(transport);
		
		int port;
		if (transport.endsWith("TLS")) {
			port = 5061;
		} else {
			port = 5060;
		}
		LOGGER.debug("Default port is " + port);
		return port;
	}

	public static String upgradeTransport(String transport) {
		checkTransport(transport);
		
		if (transport.equalsIgnoreCase("tcp")) {
			LOGGER.debug("sips: scheme, so upgrading from TCP to TLS");
			return "TLS";
		} else if (transport.equalsIgnoreCase("sctp")) {
			LOGGER.debug("sips: scheme, so upgrading from SCTP to SCTP-TLS");
			return "SCTP-TLS";
		} else {
			throw new IllegalArgumentException("Cannot upgrade " + transport);
		}
	}

	public static String getDefaultTransportForScheme(String scheme) {
		LOGGER.debug("Determining default transport for " + scheme + ": scheme");
		String transport;
		if ("SIPS".equalsIgnoreCase(scheme)) {
			LOGGER.debug("Default transport is TCP");
			transport = upgradeTransport("TCP");
		} else if ("SIP".equalsIgnoreCase(scheme)) {
			LOGGER.debug("Default transport is UDP");
			transport = "UDP";
		} else {
			throw new IllegalArgumentException("Unknown scheme: " + scheme);
		}
		return transport;
	}

	public static String getTarget(SipURI uri) {
		LOGGER.debug("Resolving TARGET for " + uri);
		// RFC 3263 Section 4 Para 5
	
		// We define TARGET as the value of the maddr parameter of
		// the URI, if present, otherwise, the host value of the
		// hostport component of the URI.
		final String maddr = uri.getMAddrParam();
		final String target;
		if (maddr != null) {
			LOGGER.debug(uri + " has no maddr parameter");
			target = maddr;
		} else {
			target = uri.getHost();
		}
		LOGGER.debug("TARGET is " + target);
		return target;
	}

	public static String getServiceIdentifier(String transport, String domain) {
		LOGGER.debug("Determining service identifier for " + domain + "/" + transport);
		checkTransport(transport);
		
		StringBuilder sb = new StringBuilder();
		
		if (transport.endsWith("TLS")) {
			sb.append("_sips.");
		} else {
			sb.append("_sip.");
		}
		
		sb.append("_");
		if (transport.equalsIgnoreCase("TLS")) {
			sb.append("tcp");
		} else if (transport.equalsIgnoreCase("SCTP-TLS")) {
			sb.append("sctp");
		} else {
			sb.append(transport.toLowerCase());
		}
		sb.append(".");
		sb.append(domain);
		
		final String serviceId = sb.toString();
		LOGGER.debug("Service identifier is " + serviceId);
		
		return serviceId;
	}
}
