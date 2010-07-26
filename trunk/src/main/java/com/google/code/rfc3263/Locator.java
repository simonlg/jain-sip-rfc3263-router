package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.apache.log4j.Logger;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.DefaultResolver;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;
import com.google.code.rfc3263.dns.ServiceRecordSelector;

public class Locator {
	private final Logger LOGGER = Logger.getLogger(Locator.class);
	/**
	 * Class to use for DNS lookups.
	 */
	private final Resolver resolver;
	/**
	 * Preferred transports.
	 */
	private final List<String> prefTransports;
	// SIP Table of Mappings From Service Field Values to Transport Protocols
	//
	// Services Field        Protocol  Reference
	// --------------------  --------  ---------
	// SIP+D2T               TCP       [RFC3263]
	// SIPS+D2T              TCP       [RFC3263]
	// SIP+D2U               UDP       [RFC3263]
	// SIP+D2S               SCTP      [RFC3263]
	// SIPS+D2S              SCTP      [RFC4168]
	private Map<String, String> serviceTransportMap = new HashMap<String, String>();
	{
		serviceTransportMap.put("SIP+D2T", "TCP");
		serviceTransportMap.put("SIPS+D2T", "TLS");
		serviceTransportMap.put("SIP+D2U", "UDP");
		serviceTransportMap.put("SIP+D2S", "SCTP");
		serviceTransportMap.put("SIPS+D2S", "SCTP-TLS");
	}
	private Map<String, String> serviceIdTransportMap = new HashMap<String, String>();
	{
		serviceIdTransportMap.put("TCP", "_sip._tcp.");
		serviceIdTransportMap.put("TLS", "_sips._tcp.");
		serviceIdTransportMap.put("UDP", "_sip._udp.");
		serviceIdTransportMap.put("SCTP", "_sip._sctp.");
		serviceIdTransportMap.put("SCTP-TLS", "_sips._sctp.");
	}
	
	/**
	 * Constructs a new instance of the <code>Locator</code> class using
	 * the {@link DefaultResolver} and the given list of transports.
	 *   
	 * @param transports the transports to use.
	 */
	public Locator(List<String> transports) {
		this(new DefaultResolver(), transports);
	}
	
	/**
	 * Constructs a new instance of the <code>Locator</code> class using
	 * the given {@link Resolver} and list of transports.
	 *  
	 * @param resolver the resolver to use.
	 * @param transports the transports to use.
	 */
	public Locator(Resolver resolver, List<String> transports) {
		this.resolver = resolver;
		this.prefTransports = transports;
	}
	
	protected Queue<Hop> locateNumeric(SipURI uri) {
		final String domain = getTarget(uri);
		
		final String hopAddress;
		final int hopPort;
		final String hopTransport;
		
		LOGGER.debug("Selecting transport for " + uri);
		
		if (uri.getTransportParam() != null) {
			LOGGER.debug("Transport parameter found");
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (uri.isSecure()) {
				hopTransport = upgradeTransport(uri.getTransportParam());
			} else {
				hopTransport = uri.getTransportParam().toUpperCase();
			}
		} else {
			LOGGER.debug("No transport parameter found, so using scheme default transport");
			// 4.1 Para 3
			//
			// Otherwise, if no transport protocol is specified, but the TARGET is a
			// numeric IP address, the client SHOULD use UDP for a SIP URI, and TCP
			// for a SIPS URI.
			hopTransport = getDefaultTransportForScheme(uri);
		}
		
		LOGGER.debug("Transport selected for " + uri + ": " + hopTransport);
		LOGGER.debug("Determining IP address and port for " + uri);
		
		// 4.2 Para 2
		//
		// If TARGET is a numeric IP address, the client uses that address.  If
		// the URI also contains a port, it uses that port.  If no port is
		// specified, it uses the default port for the particular transport
		// protocol.
		hopAddress = domain;
		if (uri.getPort() != -1) {
			hopPort = uri.getPort();
		} else {
			hopPort = getDefaultPortForTransport(hopTransport);
		}
		
		LOGGER.debug("Determined IP address and port for " + uri + ": " + hopAddress + ":" + hopPort);
		
		final Queue<Hop> hops = new LinkedList<Hop>();
		hops.add(new HopImpl(hopAddress, hopPort, hopTransport));
		
		return hops;
	}
	
	private String getDefaultTransportForScheme(SipURI uri) {
		LOGGER.debug("Determining default transport for " + uri.getScheme() + ": scheme");
		String transport;
		if (uri.isSecure()) {
			LOGGER.debug("Default transport is TCP");
			transport = upgradeTransport("TCP");
		} else {
			LOGGER.debug("Default transport is UDP");
			transport = "UDP";
		}
		return transport;
	}
	
	private int getDefaultPortForTransport(String transport) {
		LOGGER.debug("Determining default port for " + transport);
		int port;
		if (transport.endsWith("TLS")) {
			port = 5061;
		} else {
			port = 5060;
		}
		LOGGER.debug("Default port is " + port);
		return port;
	}

	private String upgradeTransport(String transport) {
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

	protected Queue<Hop> locateNonNumeric(SipURI uri) throws UnknownHostException {
		final Queue<Hop> hops = new LinkedList<Hop>();
		
		String domain = getTarget(uri);
		String hopTransport = null;
		
		LOGGER.debug("Selecting transport for " + uri);
		
		if (uri.getTransportParam() != null) {
			LOGGER.debug("Transport parameter was specified");
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (uri.isSecure()) {
				hopTransport = upgradeTransport(uri.getTransportParam());
			} else {
				hopTransport = uri.getTransportParam().toUpperCase();
			}
		} else if (uri.getPort() != -1) {
			LOGGER.debug("No transport parameter found, so using scheme default transport");
			// 4.1 Para 3
			//
			// ... if no transport protocol is specified, and the TARGET is not 
			// numeric, but an explicit port is provided, the client SHOULD use 
			// UDP for a SIP URI, and TCP for a SIPS URI.
			hopTransport = getDefaultTransportForScheme(uri);
		} else {
			LOGGER.debug("No transport parameter or port was specified.");
			// 4.1 Para 4
			//
			// Otherwise, if no transport protocol or port is specified, and the
			// target is not a numeric IP address, the client SHOULD perform a NAPTR
			// query for the domain in the URI.
			LOGGER.debug("Looking up NAPTR records for " + domain);
			final List<PointerRecord> pointers = resolver.lookupPointerRecords(domain);
			discardInvalidPointers(pointers, uri.isSecure());
			
			if (pointers.size() > 0) {
				LOGGER.debug("Found " + pointers.size() + " NAPTR record(s)");
				
				// 4.1 Para 6
				//
				// The NAPTR processing as described in RFC 2915 will result in 
				// the discovery of the most preferred transport protocol of the 
				// server that is supported by the client, as well as an SRV 
				// record for the server.
				PointerRecord pointer = selectPointerRecord(pointers);
				String serviceId = pointer.getReplacement();
				LOGGER.debug("Looking up SRV records for " + serviceId);
				final List<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
				if (isValid(services)) {
					LOGGER.debug("Found " + services.size() + " SRV record(s)");
					List<ServiceRecord> sortedServices = sortServiceRecords(services);
					
					hopTransport = serviceTransportMap.get(pointer.getService());
					for (ServiceRecord service : sortedServices) {
						hops.add(new HopImpl(service.getTarget(), service.getPort(), hopTransport));
					}
				}
			} else {
				LOGGER.debug("No NAPTR records found for " + domain);
				// 4.1 Para 12
				//
				// If no NAPTR records are found, the client constructs SRV queries for
				// those transport protocols it supports, and does a query for each.
				// Queries are done using the service identifier "_sip" for SIP URIs and
				// "_sips" for SIPS URIs.  A particular transport is supported if the
				// query is successful.
				final List<String> filteredTransports = filterTransports(uri.isSecure());
				for (String prefTransport : filteredTransports) {
					String serviceId = getServiceIdentifier(prefTransport, domain);
					LOGGER.debug("Looking up SRV records for " + serviceId);
					final List<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
					if (isValid(services)) {
						LOGGER.debug("Found " + services.size() + " SRV record(s) for " + serviceId);
						List<ServiceRecord> sortedServices = sortServiceRecords(services);
						hopTransport = prefTransport;
						for (ServiceRecord service : sortedServices) {
							hops.add(new HopImpl(service.getTarget(), service.getPort(), hopTransport));
						}
					} else {
						LOGGER.debug("No valid SRV records for " + serviceId);
					}
				}
			}
			
			if (hops.size() == 0) {
				LOGGER.debug("No SRV records found  " + domain);
				// 4.1 Para 13
				//
				// If no SRV records are found, the client SHOULD use TCP for a SIPS
				// URI, and UDP for a SIP URI.
				if (uri.isSecure()) {
					hopTransport = upgradeTransport("TCP");
				} else {
					hopTransport = "UDP";
				}
			}
		}
		
		LOGGER.debug("Transport selected for " + uri + ": " + hopTransport);
		LOGGER.debug("Determining IP address and port for " + uri);
		
		if (uri.getPort() != -1) {
			LOGGER.debug("Port is present in the URI");
			// 4.2 Para 3
			//
			// If the TARGET was not a numeric IP address, but a port is present in
			// the URI, the client performs an A or AAAA record lookup of the domain
			// name.  The result will be a list of IP addresses, each of which can
			// be contacted at the specific port from the URI and transport protocol
			// determined previously.
			hops.add(new HopImpl(domain, uri.getPort(), hopTransport));
		} else {
			LOGGER.debug("No port is present in the URI");
			// 4.2 Para 4
			//
			// If the TARGET was not a numeric IP address, and no port was present
			// in the URI, the client performs an SRV query on the record returned
			// from the NAPTR processing of Section 4.1, if such processing was
			// performed.
			if (hops.size() > 0) {
				LOGGER.debug("SRV records found during transport selection");
				// Nothing to do here: hops were created earlier.
			} else if (uri.getTransportParam() != null) {
				LOGGER.debug("Transport parameter was specified");
				// 4.2 Para 4
				//
				// If [NAPTR processing] was not [performed], because a transport was 
				// specified explicitly, the client performs an SRV query for that 
				// specific transport, using the service identifier "_sips" for SIPS URIs.  
				// For a SIP URI, if the client wishes to use TLS, it also uses the service
				// identifier "_sips" for that specific transport, otherwise, it uses
				// "_sip".
				String serviceId = getServiceIdentifier(hopTransport, domain);
				LOGGER.debug("Looking up SRV records for " + serviceId);
				final List<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
				if (isValid(services)) {
					LOGGER.debug("Found " + services.size() + " SRV records");
					List<ServiceRecord> sortedServices = sortServiceRecords(services);
					for (ServiceRecord service : sortedServices) {
						hops.add(new HopImpl(service.getTarget(), service.getPort(), hopTransport));
					}
				} else {
					LOGGER.debug("No valid SRV records for " + serviceId);
					// 4.2 Para 5
					//
					// If no SRV records were found, the client performs an A or AAAA record
					// lookup of the domain name.  The result will be a list of IP
					// addresses, each of which can be contacted using the transport
					// protocol determined previously, at the default port for that
					// transport.
					hops.add(new HopImpl(domain, getDefaultPortForTransport(hopTransport), hopTransport));
				}
			} else {
				// 4.2 Para 5
				//
				// If no SRV records were found, the client performs an A or AAAA record
				// lookup of the domain name.  The result will be a list of IP
				// addresses, each of which can be contacted using the transport
				// protocol determined previously, at the default port for that
				// transport.
				hops.add(new HopImpl(domain, getDefaultPortForTransport(hopTransport), hopTransport));
			}
		}
		
		return hops;
	}

	private PointerRecord selectPointerRecord(List<PointerRecord> pointers) {
		LOGGER.debug("Selecting pointer record from record set");
		return pointers.get(0);
	}
	
	private Queue<Hop> resolveHops(Queue<Hop> hops) {
		Queue<Hop> resolvedHops = new LinkedList<Hop>();
		
		for (Hop hop : hops) {
			final Set<AddressRecord> addresses = resolver.lookupAddressRecords(hop.getHost());
			for (AddressRecord address : addresses) {
				final String ipAddress = address.getAddress().getHostAddress();
				final Hop resolvedHop = new HopImpl(ipAddress, hop.getPort(), hop.getTransport());
				if (resolvedHops.contains(resolvedHop) == false) {
					resolvedHops.add(resolvedHop);
				}
			}
		}
		
		return resolvedHops;
	}
	
	private List<ServiceRecord> sortServiceRecords(List<ServiceRecord> services) {
		LOGGER.debug("Selecting service record from record set");
		
		final ServiceRecordSelector selector = new ServiceRecordSelector(services);
		return selector.select();
	}
	
	private void discardInvalidPointers(List<PointerRecord> pointers, boolean isSecure) {
		final Set<String> validServiceFields = new HashSet<String>();
		// 4.1 Para 5
		//
		// The services relevant for the task of transport protocol selection 
		// are those with NAPTR service fields with values "SIP+D2X" and "SIPS+D2X", 
		// where X is a letter that corresponds to a transport protocol supported 
		// by the domain.  This specification defines D2U for UDP, D2T for TCP, 
		// and D2S for SCTP.  We also establish an IANA registry for NAPTR service 
		// name to transport protocol mappings.
		validServiceFields.addAll(serviceTransportMap.keySet());
		
		// 4.1 Para 6
		//
		// First, a client resolving a SIPS URI MUST discard any services that
		// do not contain "SIPS" as the protocol in the service field.
		if (isSecure) {
			validServiceFields.remove("SIP+D2T");
			validServiceFields.remove("SIP+D2U");
			validServiceFields.remove("SIP+D2S");
		}
		
		// 4.1 Para 6
		//
		// A client resolving a SIP URI SHOULD retain records with "SIPS"
		// as the protocol, if the client supports TLS.
		if (prefTransports.contains("TLS") == false) {
			validServiceFields.remove("SIPS+D2T");
		}
		if (prefTransports.contains("SCTP-TLS") == false) {
			validServiceFields.remove("SIPS+D2S");
		}
		
		// 4.1 Para 6
		//
		// Second, a client MUST discard any service fields that identify
		// a resolution service whose value is not "D2X", for values of X that
		// indicate transport protocols supported by the client.
		if (prefTransports.contains("TCP") == false) {
			validServiceFields.remove("SIP+D2T");
		}
		if (prefTransports.contains("UDP") == false) {
			validServiceFields.remove("SIP+D2U");
		}
		if (prefTransports.contains("SCTP") == false) {
			validServiceFields.remove("SIP+D2S");
		}
		
		LOGGER.debug("Supported NAPTR services: " + validServiceFields);

		// Discard
		final Iterator<PointerRecord> iter = pointers.iterator();
		while (iter.hasNext()) {
			final PointerRecord pointer = iter.next();
			if (validServiceFields.contains(pointer.getService()) == false) {
				LOGGER.debug("Removing unsupported NAPTR record: " + pointer);
				iter.remove();
			} else if (isValid(pointer) == false) {
				LOGGER.debug("Removing invalid NAPTR record: " + pointer);
				iter.remove();
			}
		}
	}

	/**
	 * Generates a queue of {@see Hop} instances which should be used to route
	 * the message with the given URI.
	 * 
	 * @param uri the URI for which to determine a hop queue.
	 * @return the hop queue.
	 * @throws UnknownHostException if the URI host is invalid.
	 */
	public Queue<Hop> locate(SipURI uri) throws UnknownHostException {
		LOGGER.debug("Locating SIP server for " + uri);
		final String target = getTarget(uri);

		final Queue<Hop> hops;
		if (isNumeric(target)) {
			hops = locateNumeric(uri);
		} else {
			hops = resolveHops(locateNonNumeric(uri));
		}
		if (hops.size() == 0) {
			LOGGER.debug("No next hop could be determined for " + uri);
		} else {
			LOGGER.debug("Hop list for " + uri + " is " + hops);
		}
		
		return hops;
	}
	
	protected List<String> filterTransports(boolean isSecure) {
		if (isSecure) {
			final List<String> filteredTransports = new ArrayList<String>(prefTransports);
			Iterator<String> iter = filteredTransports.iterator();
			while (iter.hasNext()) {
				// TLS or SCTP-TLS
				if (iter.next().endsWith("TLS") == false) {
					iter.remove();
				}
			}
			return filteredTransports;
		} else {
			return prefTransports;
		}
	}
	
	protected String getTarget(SipURI uri) {
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
	
	/**
	 * See RFC 2782
	 * 
	 * @param services
	 * @return true is the list of services is valid; false otherwise.
	 */
	protected boolean isValid(List<ServiceRecord> services) {
		if (services.size() == 0) {
			return false;
		} else if (services.size() == 1) {
			ServiceRecord service = services.iterator().next();
			if (service.getTarget().equals(".")) {
				return false;
			} else {
				return true;
			}
		} else {
			return true;
		}
	}
	
	protected boolean isValid(PointerRecord pointer) {
		return pointer.getRegexp().isEmpty() && pointer.getFlags().equalsIgnoreCase("s"); 
	}
	
	protected boolean isNumeric(String target) {
		LOGGER.debug("Determining if " + target + " is numeric");
		try {
			// The contract of InetAddress.getByName states the following:
			//
			// "If a literal IP address is supplied, only the validity of
			// the address format is checked."
			final InetAddress addr = InetAddress.getByName(target);

			// The contract of InetAddress.toString states the following:
			//
			// "The string returned is of the form: hostname / literal IP
			// address. If the host name is unresolved, no reverse name
			// service loopup is performed. The hostname part will be
			// represented by an empty string."
			final String[] parts = addr.toString().split("/");

			// Therefore, since no lookup takes place on an IPv4 or IPv6
			// address,
			// the host part will ALWAYS be empty for numeric addresses.
			if (parts[0].isEmpty()) {
				// Empty, so an IP address was used.
				LOGGER.debug(target + " is numeric");
				return true;
			}
			// Non-empty, so a resolvable host name was provided.
			LOGGER.debug(target + " is NOT numeric");
			return false;
		} catch (UnknownHostException e) {
			// InetAddress.getByName throws this exception "if no IP address
			// for the host could be found".
			//
			// InetAddress will only attempt resolution for host names, so
			// the argument to this method MUST have been a host name for
			// this exception to have been thrown.
			LOGGER.debug(target + " is NOT numeric");
			return false;
		}
	}
	
	private String getServiceIdentifier(String transport, String host) {
		LOGGER.debug("Determining service identifier for " + host + "/" + transport);
		StringBuilder sb = new StringBuilder();
		
		if (transport.endsWith("TLS")) {
			sb.append("_sips.");
		} else {
			sb.append("_sip.");
		}
		
		sb.append("_");
		sb.append(transport.toLowerCase());
		sb.append(".");
		sb.append(host);
		sb.append(".");
		
		final String serviceId = sb.toString();
		LOGGER.debug("Service identifier is " + serviceId);
		return serviceId;
	}
}
