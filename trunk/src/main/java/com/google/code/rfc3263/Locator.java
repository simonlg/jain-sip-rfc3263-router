package com.google.code.rfc3263;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import net.jcip.annotations.ThreadSafe;

import org.apache.log4j.Logger;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TextParseException;

import com.google.code.rfc3263.dns.DefaultResolver;
import com.google.code.rfc3263.dns.PointerRecordSelector;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecordDeterministicComparator;
import com.google.code.rfc3263.dns.ServiceRecordSelector;
import com.google.code.rfc3263.util.LocatorUtils;

/**
 * This class provides the mechanism defined by RFC 3263 for ascertaining the hops to try
 * for a particular request.
 * 
 * This class is thread-safe.
 */
@ThreadSafe
public class Locator {
	private final static Logger LOGGER = Logger.getLogger(Locator.class);
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
	/**
	 * Comparator for sorting prioritised SRV records.
	 */
	private Comparator<SRVRecord> weightingComparator = new ServiceRecordDeterministicComparator();
	private final Lock comparatorLock = new ReentrantLock();
	{
		serviceTransportMap.put("SIP+D2T", "TCP");
		serviceTransportMap.put("SIPS+D2T", "TLS");
		serviceTransportMap.put("SIP+D2U", "UDP");
		serviceTransportMap.put("SIP+D2S", "SCTP");
		serviceTransportMap.put("SIPS+D2S", "TLS-SCTP");
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
	
	private Hop locateNumeric(SipURI uri) {
		final String domain = LocatorUtils.getTarget(uri);
		
		final String transportParam = getTransportParam(uri);
		final boolean isSecure = isSecure(uri);
		final int port = uri.getPort();
		
		final String hopAddress;
		final int hopPort;
		final String hopTransport;
		
		LOGGER.debug("Selecting transport for " + uri);
		
		if (transportParam != null) {
			LOGGER.debug("Transport parameter found");
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (isSecure) {
				try {
					hopTransport = LocatorUtils.upgradeTransport(transportParam);
				} catch (IllegalArgumentException e) {
					// User is trying to use secure UDP
					return null;
				}
			} else {
				hopTransport = transportParam.toUpperCase();
			}
		} else {
			LOGGER.debug("No transport parameter found, so using scheme default transport");
			// 4.1 Para 3
			//
			// Otherwise, if no transport protocol is specified, but the TARGET is a
			// numeric IP address, the client SHOULD use UDP for a SIP URI, and TCP
			// for a SIPS URI.
			hopTransport = LocatorUtils.getDefaultTransportForScheme(uri.getScheme());
		}
		
		LOGGER.debug("Transport selected for " + uri + ": " + hopTransport);
		LOGGER.debug("Determining IP address and port for " + uri);
		
		// 4.2 Para 2
		//
		// If TARGET is a numeric IP address, the client uses that address.  If
		// the URI also contains a port, it uses that port.  If no port is
		// specified, it uses the default port for the particular transport
		// protocol.
		if (LocatorUtils.isIPv6Reference(domain)) {
			hopAddress = domain.substring(1, domain.length() - 1);
		} else {
			hopAddress = domain;
		}
		if (port != -1) {
			hopPort = port;
		} else {
			hopPort = LocatorUtils.getDefaultPortForTransport(hopTransport);
		}
		
		LOGGER.debug("Determined IP address and port for " + uri + ": " + hopAddress + ":" + hopPort);
		
		return new HopImpl(hopAddress, hopPort, hopTransport);
	}
	
	private Queue<UnresolvedHop> locateNonNumeric(SipURI uri) {
		final Queue<UnresolvedHop> hops = new LinkedList<UnresolvedHop>();
		
		final String transportParam = getTransportParam(uri);
		final boolean isSecure = isSecure(uri);
		final int port = uri.getPort();
		
		Name domain;
		try {
			domain = Name.concatenate(new Name(LocatorUtils.getTarget(uri)), Name.root);
		} catch (TextParseException e) {
			// TODO DNS Exception
			throw new RuntimeException(e);
		} catch (NameTooLongException e) {
			// TODO DNS Exception
			throw new RuntimeException(e);
		}
		String hopTransport = null;
		
		LOGGER.debug("Selecting transport for " + uri);
		
		if (transportParam != null) {
			LOGGER.debug("Transport parameter was specified");
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (isSecure) {
				try {
					hopTransport = LocatorUtils.upgradeTransport(transportParam);
				} catch (IllegalArgumentException e) {
					// User is trying to use secure UDP
					return hops;
				}
			} else {
				hopTransport = transportParam.toUpperCase();
			}
		} else if (port != -1) {
			LOGGER.debug("No transport parameter found, so using scheme default transport");
			// 4.1 Para 3
			//
			// ... if no transport protocol is specified, and the TARGET is not 
			// numeric, but an explicit port is provided, the client SHOULD use 
			// UDP for a SIP URI, and TCP for a SIPS URI.
			hopTransport = LocatorUtils.getDefaultTransportForScheme(uri.getScheme());
		} else {
			LOGGER.debug("No transport parameter or port was specified.");
			// 4.1 Para 4
			//
			// Otherwise, if no transport protocol or port is specified, and the
			// target is not a numeric IP address, the client SHOULD perform a NAPTR
			// query for the domain in the URI.
			LOGGER.debug("Looking up NAPTR records for " + domain);
			final List<NAPTRRecord> pointers = resolver.lookupNAPTRRecords(domain);
			discardInvalidPointers(pointers, isSecure);
			
			if (pointers.size() > 0) {
				LOGGER.debug("Found " + pointers.size() + " NAPTR record(s)");
				
				// 4.1 Para 6
				//
				// The NAPTR processing as described in RFC 2915 will result in 
				// the discovery of the most preferred transport protocol of the 
				// server that is supported by the client, as well as an SRV 
				// record for the server.
				List<NAPTRRecord> sortedPointers = sortPointerRecords(pointers);
				for (NAPTRRecord pointer : sortedPointers) {
					LOGGER.debug("Processing NAPTR record: " + pointer);
					Name serviceId = pointer.getReplacement();
					LOGGER.debug("Looking up SRV records for " + serviceId);
					final List<SRVRecord> services = resolver.lookupSRVRecords(serviceId);
					if (isValid(services)) {
						LOGGER.debug("Found " + services.size() + " SRV record(s)");
						List<SRVRecord> sortedServices = sortServiceRecords(services);
						
						hopTransport = serviceTransportMap.get(pointer.getService());
						for (SRVRecord service : sortedServices) {
							LOGGER.debug("Processing SRV record: " + service);
							hops.add(new UnresolvedHop(service.getTarget(), service.getPort(), hopTransport));
						}
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
				final List<String> filteredTransports = filterTransports(isSecure);
				for (String prefTransport : filteredTransports) {
					Name serviceId = LocatorUtils.getServiceIdentifier(prefTransport, domain);
					LOGGER.debug("Looking up SRV records for " + serviceId);
					final List<SRVRecord> services = resolver.lookupSRVRecords(serviceId);
					if (isValid(services)) {
						LOGGER.debug("Found " + services.size() + " SRV record(s) for " + serviceId);
						List<SRVRecord> sortedServices = sortServiceRecords(services);
						hopTransport = prefTransport;
						for (SRVRecord service : sortedServices) {
							LOGGER.debug("Processing SRV record: " + service);
							hops.add(new UnresolvedHop(service.getTarget(), service.getPort(), hopTransport));
						}
					} else {
						LOGGER.debug("No valid SRV records for " + serviceId);
					}
				}
			}
			
			if (hops.size() == 0) {
				LOGGER.debug("No SRV records found for " + domain);
				// 4.1 Para 13
				//
				// If no SRV records are found, the client SHOULD use TCP for a SIPS
				// URI, and UDP for a SIP URI.
				hopTransport = LocatorUtils.getDefaultTransportForScheme(uri.getScheme());
			}
		}
		
		LOGGER.debug("Transport selected for " + uri + ": " + hopTransport);
		LOGGER.debug("Determining IP address and port for " + uri);
		
		if (port != -1) {
			LOGGER.debug("Port is present in the URI");
			// 4.2 Para 3
			//
			// If the TARGET was not a numeric IP address, but a port is present in
			// the URI, the client performs an A or AAAA record lookup of the domain
			// name.  The result will be a list of IP addresses, each of which can
			// be contacted at the specific port from the URI and transport protocol
			// determined previously.
			hops.add(new UnresolvedHop(domain, port, hopTransport));
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
			} else if (transportParam != null) {
				LOGGER.debug("Transport was sepecified explicitly, so no NAPTR processing was performed.");
				LOGGER.debug("Performing an SRV query for " + hopTransport);
				// 4.2 Para 4
				//
				// If [NAPTR processing] was not [performed], because a transport was 
				// specified explicitly, the client performs an SRV query for that 
				// specific transport, using the service identifier "_sips" for SIPS URIs.  
				// For a SIP URI, if the client wishes to use TLS, it also uses the service
				// identifier "_sips" for that specific transport, otherwise, it uses
				// "_sip".
				Name serviceId = LocatorUtils.getServiceIdentifier(hopTransport, domain);
				LOGGER.debug("Looking up SRV records for " + serviceId);
				final List<SRVRecord> services = resolver.lookupSRVRecords(serviceId);
				if (isValid(services)) {
					LOGGER.debug("Found " + services.size() + " SRV records for " + serviceId + ", so use provided targets and ports");
					LOGGER.debug(services);
					List<SRVRecord> sortedServices = sortServiceRecords(services);
					for (SRVRecord service : sortedServices) {
						LOGGER.debug("Processing SRV record: " + service);
						hops.add(new UnresolvedHop(service.getTarget(), service.getPort(), hopTransport));
					}
				} else {
					LOGGER.debug("No valid SRV records found for " + serviceId + ", so use default port for " + hopTransport);
					// 4.2 Para 5
					//
					// If no SRV records were found, the client performs an A or AAAA record
					// lookup of the domain name.  The result will be a list of IP
					// addresses, each of which can be contacted using the transport
					// protocol determined previously, at the default port for that
					// transport.
					hops.add(new UnresolvedHop(domain, LocatorUtils.getDefaultPortForTransport(hopTransport), hopTransport));
				}
			} else {
				LOGGER.debug("No port was discovered during transport selection, so use default port for selected transport");
				// 4.2 Para 5
				//
				// If no SRV records were found, the client performs an A or AAAA record
				// lookup of the domain name.  The result will be a list of IP
				// addresses, each of which can be contacted using the transport
				// protocol determined previously, at the default port for that
				// transport.
				hops.add(new UnresolvedHop(domain, LocatorUtils.getDefaultPortForTransport(hopTransport), hopTransport));
			}
		}
		
		return hops;
	}

	private static List<NAPTRRecord> sortPointerRecords(List<NAPTRRecord> pointers) {
		LOGGER.debug("Selecting pointer record from record set");
		PointerRecordSelector selector = new PointerRecordSelector(pointers);
		
		return selector.select();
	}
	
	private Queue<Hop> resolveHops(Queue<UnresolvedHop> hops) {
		Queue<Hop> resolvedHops = new LinkedList<Hop>();
		
		for (UnresolvedHop hop : hops) {
			LOGGER.debug("Resolving hop: " + hop);
			final Set<ARecord> aRecords = resolver.lookupARecords(hop.getHost());

			for (ARecord aRecord : aRecords) {
				LOGGER.debug("Processing A record: " + aRecord);
				final String ipAddress = aRecord.getAddress().getHostAddress();
				final Hop resolvedHop = new HopImpl(ipAddress, hop.getPort(), hop.getTransport());
				if (resolvedHops.contains(resolvedHop) == false) {
					resolvedHops.add(resolvedHop);
				}
			}
			
			final Set<AAAARecord> aaaaRecords = resolver.lookupAAAARecords(hop.getHost());

			for (AAAARecord aaaaRecord : aaaaRecords) {
				LOGGER.debug("Processing AAAA record: " + aaaaRecord);
				final String ipAddress = aaaaRecord.getAddress().getHostAddress();
				final Hop resolvedHop = new HopImpl(ipAddress, hop.getPort(), hop.getTransport());
				if (resolvedHops.contains(resolvedHop) == false) {
					resolvedHops.add(resolvedHop);
				}
			}
		}
		
		return resolvedHops;
	}
	
	/**
	 * Provide a comparator to override the default comparator, which sorts by weight,
	 * then by target.
	 * 
	 * @param weightingComparator the comparator to use to sort SRV records.
	 */
	public void setWeightingComparator(Comparator<SRVRecord> weightingComparator) {
		comparatorLock.lock();
		try {
			this.weightingComparator = weightingComparator; 
		} finally {
			comparatorLock.unlock();
		}
	}
	
	private List<SRVRecord> sortServiceRecords(List<SRVRecord> services) {
		LOGGER.debug("Selecting service record from record set");
		
		comparatorLock.lock();
		try {
			final ServiceRecordSelector selector = new ServiceRecordSelector(services, weightingComparator);
			return selector.select();
		} finally {
			comparatorLock.unlock();
		}
	}
	
	private void discardInvalidPointers(List<NAPTRRecord> pointers, boolean isSecure) {
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
		if (prefTransports.contains("TLS-SCTP") == false) {
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
		final Iterator<NAPTRRecord> iter = pointers.iterator();
		while (iter.hasNext()) {
			final NAPTRRecord pointer = iter.next();
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
	 * Generates a queue of {@link Hop} instances which should be used to route
	 * the message with the given URI.
	 * 
	 * @param uri the URI for which to determine a hop queue.
	 * @return the hop queue.
	 * @throws UnknownHostException if the URI host is invalid.
	 */
	public Queue<Hop> locate(SipURI uri) {
		LOGGER.debug("locate(" + uri + ")");
		final String target = LocatorUtils.getTarget(uri);

		final Queue<Hop> hops = new LinkedList<Hop>();
		if (LocatorUtils.isNumeric(target)) {
			Hop hop = locateNumeric(uri);
			if (hop != null) {
				hops.add(hop);
			}
		} else {
			hops.addAll(resolveHops(locateNonNumeric(uri)));
		}
		LOGGER.debug("locate(" + uri + "): " + hops);
		
		return hops;
	}
	
	private List<String> filterTransports(boolean isSecure) {
		if (isSecure) {
			final List<String> filteredTransports = new ArrayList<String>(prefTransports);
			Iterator<String> iter = filteredTransports.iterator();
			while (iter.hasNext()) {
				// TLS or SCTP-TLS
				if (iter.next().startsWith("TLS") == false) {
					iter.remove();
				}
			}
			return filteredTransports;
		} else {
			return prefTransports;
		}
	}
	
	/**
	 * See RFC 2782
	 * 
	 * @param services
	 * @return true is the list of services is valid; false otherwise.
	 */
	private static boolean isValid(List<SRVRecord> services) {
		if (services.size() == 0) {
			return false;
		} else if (services.size() == 1) {
			// RFC 2782, Section "The format of the SRV RR"
			//
			// A target of "." means that the service is decidedly not
	        // available at this domain.
			final SRVRecord service = services.iterator().next();
			if (service.getTarget().equals(Name.root)) {
				return false;
			} else {
				return true;
			}
		} else {
			return true;
		}
	}
	
	private String getTransportParam(SipURI uri) {
		if ("tls".equals(uri.getTransportParam())) {
			return "tcp";
		}
		return uri.getTransportParam();
	}
	
	private boolean isSecure(SipURI uri) {
		if ("tls".equals(uri.getTransportParam())) {
			return true;
		}
		return uri.isSecure();
	}
	
	private static boolean isValid(NAPTRRecord pointer) {
		// RFC 3263, Section 4.1
		//
		// The resource record will contain an empty regular expression and a 
		// replacement value, which is the SRV record for that particular transport 
		// protocol.
		//
		// RFC 2915, Section 4
		//
		// The "S" flag means that the next lookup should be for SRV records.
		
		return pointer.getRegexp().isEmpty() && pointer.getFlags().equalsIgnoreCase("s"); 
	}
}
