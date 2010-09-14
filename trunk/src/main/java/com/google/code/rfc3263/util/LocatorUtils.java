package com.google.code.rfc3263.util;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.sip.address.SipURI;

import net.jcip.annotations.ThreadSafe;

import org.apache.log4j.Logger;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.TextParseException;

/**
 * This class contains a collection of useful utility methods.
 */
@ThreadSafe
public final class LocatorUtils {
	private final static Logger LOGGER = Logger.getLogger(LocatorUtils.class);
	private final static Set<String> knownTransports = new HashSet<String>();
	static {
		knownTransports.add("UDP");
		knownTransports.add("TCP");
		knownTransports.add("TLS");
		knownTransports.add("SCTP");
		knownTransports.add("TLS-SCTP");
	}

	private static Name SIP;
	private static Name SIPS;
	private static Name SCTP;
	private static Name TCP;
	private static Name UDP;
	
	static {
		try {
			SIP = new Name("_sip");
			SIPS = new Name("_sips");
			SCTP = new Name("_sctp");
			TCP = new Name("_tcp");
			UDP = new Name("_udp");
		} catch (TextParseException e) {
			
		}
	}
	
	private LocatorUtils() {}

	/**
	 * Returns <code>true</code> if the provided host is an IPv4 address or
	 * IPv6 reference, or <code>false</code> if the provided host is a hostname.
	 * 
	 * @param host the host to check.
	 * @return <code>true</code> if an IPv4 or IPv6 string, <code>false</code> otherwise.
	 */
	public static boolean isNumeric(String host) {
		LOGGER.debug("isNumeric(" + host + ")");
		boolean numeric = LocatorUtils.isIPv4Address(host) || LocatorUtils.isIPv6Reference(host);
		LOGGER.debug("isNumeric(" + host + "): " + numeric);
		
		return numeric;
	}

	/**
	 * Returns <code>true</code> if the given host is an IPv4 address.
	 * <p>
	 * This method uses the definition of <code>IPv4address</code> from RFC 3261, which
	 * is four groups of 1-3 digits, delimited by a period (.) character.
	 * 
	 * @param host the host to check.
	 * @return <code>true</code> if the provided host is an IPv4 address, <code>false</code> otherwise.
	 */
	public static boolean isIPv4Address(String host) {
		LOGGER.debug("isIPv4Address(" + host + ")");
		
		// RFC 2234, Section 6.1
		//
		// DIGIT          =  %x30-39
		//
		// RFC 3261, Section 25.1
		//
		// IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
		String ipv4address = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}";
		
		final Pattern p = Pattern.compile(ipv4address);
		final Matcher m = p.matcher(host);
		boolean matches = m.matches();
		
		LOGGER.debug("isIPv4Address(" + host + "): " + matches);
		
		return matches;
	}

	/**
	 * Returns <code>true</code> if the provided host is an IPv6 reference, or
	 * <code>false</code> otherwise.
	 * <p>
	 * This method uses the definition of <code>IPv6reference</code> from RFC
	 * 3261, which is effectively an IPv6 address surrounded by square brackets.
	 * 
	 * @param host the host to check.
	 * @return <code>true</code> if the host is an IPv6 reference, <code>false</code> otherwise.
	 */
	public static boolean isIPv6Reference(String host) {
		LOGGER.debug("isIPv6Reference(" + host + ")");
		
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
		
		final Pattern p = Pattern.compile(ipv6reference, Pattern.CASE_INSENSITIVE);
		final Matcher m = p.matcher(host);
		boolean matches = m.matches();
		
		LOGGER.debug("isIPv6Reference(" + host + "): " + matches);
		
		return matches;
	}
	
	/**
	 * Returns <code>true</code> if the provided transport is defined by a
	 * standards-track SIP document.
	 * <p>
	 * Namely:
	 * <ul>
	 * <li>UDP</li>
	 * <li>TCP</li>
	 * <li>TLS</li>
	 * <li>SCTP</li>
	 * <li>TLS-SCTP</li>
	 * </ul>
	 * 
	 * @param transport the transport to check.
	 * @return <code>true</code> if the transport is known, <code>false</code> otherwise.
	 */
	public static boolean isKnownTransport(String transport) {
		LOGGER.debug("isKnownTransport(" + transport + ")");
		boolean known = knownTransports.contains(transport.toUpperCase());
		LOGGER.debug("isKnownTransport(" + transport + "): " + known);
		
		return known;
	}

	/**
	 * Returns the default port number for the provided transport.
	 * <p>
	 * At the time of writing, all secure transports used port 5061, and all
	 * insecure transports 5060.  Using this method ensures that, should that
	 * change, this method will be updated to reflect that.
	 * 
	 * @param transport the transport to check.
	 * @return the default port number for the provided transport.
	 */
	public static int getDefaultPortForTransport(String transport) {
		LOGGER.debug("getDefaultPortForTransport(" + transport + ")");
		if (isKnownTransport(transport) == false) {
			throw new IllegalArgumentException("Unknown transport: " + transport);
		}
		
		int port;
		if (transport.startsWith("TLS")) {
			port = 5061;
		} else {
			port = 5060;
		}
		LOGGER.debug("getDefaultPortForTransport(" + transport + "): " + port);
		
		return port;
	}

	/**
	 * Returns the secure transport for the given transport.
	 * <p>
	 * For example, given TCP, this method will return TLS.  Given UDP, this
	 * method will throw an IllegalArgumentException. 
	 * 
	 * @param transport the transport to upgrade.
	 * @return the upgraded transport.
	 */
	public static String upgradeTransport(String transport) {
		LOGGER.debug("upgradeTransport(" + transport + ")");
		if (isKnownTransport(transport) == false) {
			throw new IllegalArgumentException("Unknown transport: " + transport);
		}
		
		String upgradedTransport;
		if (transport.equalsIgnoreCase("tcp")) {
			upgradedTransport = "TLS";
		} else if (transport.equalsIgnoreCase("sctp")) {
			upgradedTransport = "TLS-SCTP";
		} else {
			throw new IllegalArgumentException("Cannot upgrade " + transport);
		}		
		LOGGER.debug("upgradeTransport(" + transport + "): " + upgradedTransport);
		
		return upgradedTransport;
	}

	/**
	 * Returns the default transport for the provided SIP URI scheme.
	 * <p>
	 * Default transports are defined by standards-track SIP documents.  In the 
	 * case of "sip:", the default transport is UDP.  For "sips:", the default
	 * transport is TLS.  This method can be used to future-proof your application.
	 *  
	 * @param scheme the URI scheme.
	 * @return the default transport for the provided scheme.
	 */
	public static String getDefaultTransportForScheme(String scheme) {
		LOGGER.debug("getDefaultTransportForScheme(" + scheme + ")");
		String transport;
		if ("SIPS".equalsIgnoreCase(scheme)) {
			transport = upgradeTransport("TCP");
		} else if ("SIP".equalsIgnoreCase(scheme)) {
			transport = "UDP";
		} else {
			throw new IllegalArgumentException("Unknown scheme: " + scheme);
		}
		
		LOGGER.debug("getDefaultTransportForScheme(" + scheme + "): " + transport);
		return transport;
	}

	/**
	 * Returns the TARGET value for the provided SIP URI.
	 * <p>
	 * RFC 3263 defines the TARGET as being the maddr parameter, if present,
	 * or the hostpart of the URI if the maddr parameter is absent.
	 * 
	 * @param uri the SIP uri to check.
	 * @return the target.
	 */
	public static String getTarget(SipURI uri) {
		LOGGER.debug("getTarget(" + uri + ")");
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
		LOGGER.debug("getTarget(" + uri + "): " + target);
		return target;
	}

	/**
	 * Returns the SRV service identifier for the given transport and domain.
	 * <p>
	 * For example, given a transport of TLS and a domain of example.org., this method
	 * will return <code>_sips._tcp.example.org.</code>, as TLS is secure (hence <code>_sips</code>)
	 * and is sent over TCP (hence <code>_tcp</code>).
	 * 
	 * @param transport the transport.
	 * @param suffix the domain name.
	 * @return the SRV service identifier.
	 */
	public static Name getServiceIdentifier(String transport, Name suffix) {
		LOGGER.debug("getServiceIdentifier(" + transport + ", " + suffix + ")");
		if (isKnownTransport(transport) == false) {
			throw new IllegalArgumentException("Unknown transport: " + transport);
		}
		
		final Name transportName;
		
		if (transport.equalsIgnoreCase("TLS") || transport.equalsIgnoreCase("TCP")) {
			transportName = TCP;
		} else if (transport.equalsIgnoreCase("TLS-SCTP") || transport.equalsIgnoreCase("SCTP")) {
			transportName = SCTP;
		} else {
			transportName = UDP;
		}
		
		final Name scheme = transport.startsWith("TLS") ? SIPS : SIP;
		
		try {
			Name prefix = Name.concatenate(scheme, transportName);
			Name serviceId = Name.concatenate(prefix, suffix);
			
			LOGGER.debug("getServiceIdentifier(" + transport + ", " + suffix + "): " + serviceId);
			return serviceId;	
		} catch (NameTooLongException e) {
			// TODO: This is a generic DNS exception.
			throw new RuntimeException(e);
		}
	}
}
