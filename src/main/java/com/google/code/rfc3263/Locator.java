package com.google.code.rfc3263;

import static com.google.code.rfc3263.util.LocatorUtils.getDefaultPortForTransport;
import static com.google.code.rfc3263.util.LocatorUtils.getDefaultTransportForScheme;
import static com.google.code.rfc3263.util.LocatorUtils.getServiceIdentifier;
import static com.google.code.rfc3263.util.LocatorUtils.getTarget;
import static com.google.code.rfc3263.util.LocatorUtils.getTransportForService;
import static com.google.code.rfc3263.util.LocatorUtils.isIPv6Reference;
import static com.google.code.rfc3263.util.LocatorUtils.isNumeric;
import static com.google.code.rfc3263.util.LocatorUtils.upgradeTransport;
import static javax.sip.ListeningPoint.SCTP;
import static javax.sip.ListeningPoint.TCP;
import static javax.sip.ListeningPoint.TLS;
import static javax.sip.ListeningPoint.UDP;

import java.io.IOException;
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

import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import net.jcip.annotations.ThreadSafe;

import org.apache.log4j.Logger;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.SRVRecord;

import com.google.code.rfc3263.dns.DefaultResolver;
import com.google.code.rfc3263.dns.PointerRecordSelector;
import com.google.code.rfc3263.dns.ServiceRecordDeterministicComparator;
import com.google.code.rfc3263.dns.ServiceRecordSelector;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.sorter.ServiceRecordDeterministicWeightSorter;
import com.google.code.rfc3263.dns.sorter.ServiceRecordWeightSorter;

/**
 * This class provides the mechanism defined by RFC 3263 for ascertaining the hops to try
 * for a particular request.
 *
 * This class is thread-safe.
 */
@ThreadSafe
public class Locator {
	private final static Logger LOGGER = Logger.getLogger(Locator.class);
	public static final String JAVA_NET_PREFER_IPV_4_STACK = "java.net.preferIPv4Stack";
	public static final String JAVA_NET_PREFER_IPV_6_ADDRESSES = "java.net.preferIPv6Addresses";

	/**
	 * Class to use for DNS lookups.
	 */
	private final Resolver resolver;
	/**
	 * Preferred transports.
	 */
	private final List<String> prefTransports;
	/**
	 * Sorter for sorting prioritised SRV records.
	 */
	private final ServiceRecordWeightSorter weightingSorter;
	// SIP Table of Mappings From Service Field Values to Transport Protocols
	//
	// Services Field        Protocol  Reference
	// --------------------  --------  ---------
	// SIP+D2T               TCP       [RFC3263]
	// SIPS+D2T              TCP       [RFC3263]
	// SIP+D2U               UDP       [RFC3263]
	// SIP+D2S               SCTP      [RFC3263]
	// SIPS+D2S              SCTP      [RFC4168]
	private final Map<String, String> serviceTransportMap = new HashMap<String, String>();
	{
		serviceTransportMap.put("SIP+D2T", TCP);
		serviceTransportMap.put("SIPS+D2T", TLS);
		serviceTransportMap.put("SIP+D2U", UDP);
		serviceTransportMap.put("SIP+D2S", SCTP);
		serviceTransportMap.put("SIPS+D2S", "TLS-SCTP");
	}

	/**
	 * Flag based on java.net.preferIPv4Stack
	 */
	private final boolean ipv4only;

	/**
	 * Flag based on java.net.preferIPv6Addresses
	 */
	private final boolean ipv6first;

	/**
	 * Constructs a new instance of the <code>Locator</code> class using
	 * the {@link DefaultResolver} and the given list of transports.
	 *
	 * @param transports the transports to use.
	 */
	public Locator(List<String> transports) {
		this(transports, new DefaultResolver());
	}

	/**
	 * Constructs a new instance of the <code>Locator</code> class using
	 * the given {@link Resolver} and list of transports.
	 *
	 * @param transports the transports to use.
	 * @param resolver the resolver to use.
	 */
	public Locator(List<String> transports, Resolver resolver) {
		this(transports, resolver, new ServiceRecordDeterministicComparator());
	}

	/**
	 * Constructs a new instance of the <code>Locator</code> class using
	 * the {@link DefaultResolver}, the given list of transports and the given
	 * SRV weighting algorithm.
	 *
	 * @param transports the transports to use.
	 * @param weightingComparator the comparator to use to sort SRV records
	 */
	public Locator(List<String> transports, Comparator<SRVRecord> weightingComparator) {
		this(transports, new DefaultResolver(), weightingComparator);
	}

	/**
	 * Constructs a new instance of the <code>Locator</code> class using
	 * the given {@link Resolver}, the list of transports and the given
	 * SRV weighting algorithm.
	 *
	 * @param transports the transports to use.
	 * @param resolver the resolver to use.
	 * @param weightingComparator the comparator to use to sort SRV records
	 */
	public Locator(List<String> transports, Resolver resolver, Comparator<SRVRecord> weightingComparator) {
		this(transports, resolver, new ServiceRecordDeterministicWeightSorter(weightingComparator));
	}

	/**
	 * Constructs a new instance of the <code>Locator</code> class using
	 * the given {@link Resolver}, the list of transports and the given
	 * SRV weighting algorithm.
	 *
	 * @param transports the transports to use.
	 * @param resolver the resolver to use.
	 * @param weightingSorter the sorter used to sort SRV records
	 */
	public Locator(List<String> transports, Resolver resolver, ServiceRecordWeightSorter weightingSorter) {
		this.resolver = resolver;
		this.prefTransports = transports;
		this.weightingSorter = weightingSorter;
		this.ipv4only = Boolean.getBoolean(JAVA_NET_PREFER_IPV_4_STACK);
		this.ipv6first = Boolean.getBoolean(JAVA_NET_PREFER_IPV_6_ADDRESSES);
	}

	/**
	 * This method returns a the next hop for a numeric URI.
	 *
	 * @param uri the URI to locate a hop for.
	 * @return the next hop.
	 */
	private Hop locateNumeric(SipURI uri) {
		final String domain = getTarget(uri);

		final String transportParam = getTransportParam(uri);
		final boolean isSecure = isSecure(uri);
		final int port = uri.getPort();

		final String hopAddress;
		final int hopPort;
		final String hopTransport;

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Selecting transport for " + uri);
		}

		if (transportParam != null) {
			LOGGER.debug("Transport parameter found");
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (isSecure) {
				try {
					hopTransport = upgradeTransport(transportParam);
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
			hopTransport = getDefaultTransportForScheme(uri.getScheme());
		}

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Transport selected for " + uri + ": " + hopTransport);
			LOGGER.debug("Determining IP address and port for " + uri);
		}

		// 4.2 Para 2
		//
		// If TARGET is a numeric IP address, the client uses that address.  If
		// the URI also contains a port, it uses that port.  If no port is
		// specified, it uses the default port for the particular transport
		// protocol.
		if (isIPv6Reference(domain)) {
			hopAddress = domain.substring(1, domain.length() - 1);
		} else {
			hopAddress = domain;
		}
		if (port != -1) {
			hopPort = port;
		} else {
			hopPort = getDefaultPortForTransport(hopTransport);
		}

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Determined IP address and port for " + uri + ": " + hopAddress + ":" + hopPort);
		}

		return new HopImpl(hopAddress, hopPort, hopTransport);
	}

	private Queue<UnresolvedHop> locateNonNumeric(SipURI uri) throws IOException {
		final Queue<UnresolvedHop> hops = new LinkedList<UnresolvedHop>();

		final String transportParam = getTransportParam(uri);
		final boolean isSecure = isSecure(uri);
		final int port = uri.getPort();
		final Name domain = Name.concatenate(new Name(getTarget(uri)), Name.root);

		String hopTransport = null;

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Selecting transport for " + uri);
		}

		if (transportParam != null) {
			LOGGER.debug("Transport parameter was specified");
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (isSecure) {
				try {
					hopTransport = upgradeTransport(transportParam);
				} catch (IllegalArgumentException e) {
					LOGGER.error("No known transport for secure UDP.", e);
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
			hopTransport = getDefaultTransportForScheme(uri.getScheme());
		} else {
			LOGGER.debug("No transport parameter or port was specified.");
			// 4.1 Para 4
			//
			// Otherwise, if no transport protocol or port is specified, and the
			// target is not a numeric IP address, the client SHOULD perform a NAPTR
			// query for the domain in the URI.
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Looking up NAPTR records for " + domain);
			}
			final List<NAPTRRecord> pointers = resolver.lookupNAPTRRecords(domain);
			discardInvalidPointers(pointers, isSecure);

			if (pointers.size() > 0) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Found " + pointers.size() + " NAPTR record(s)");
				}

				// 4.1 Para 6
				//
				// The NAPTR processing as described in RFC 2915 will result in
				// the discovery of the most preferred transport protocol of the
				// server that is supported by the client, as well as an SRV
				// record for the server.
				List<NAPTRRecord> sortedPointers = sortPointerRecords(pointers);
				for (NAPTRRecord pointer : sortedPointers) {
					final Name serviceId = pointer.getReplacement();
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Processing NAPTR record: " + pointer);
						LOGGER.debug("Looking up SRV records for " + serviceId);
					}
					final List<SRVRecord> services = resolver.lookupSRVRecords(serviceId);
					if (isValid(services)) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Found " + services.size() + " SRV record(s)");
						}
						final List<SRVRecord> sortedServices = sortServiceRecords(services);

						hopTransport = getTransportForService(pointer.getService());
						for (SRVRecord service : sortedServices) {
							if (LOGGER.isDebugEnabled()) {
								LOGGER.debug("Processing SRV record: " + service);
							}
							hops.add(new UnresolvedHop(service.getTarget(), service.getPort(), hopTransport));
						}
					}
				}
			} else {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("No NAPTR records found for " + domain);
				}
				// 4.1 Para 12
				//
				// If no NAPTR records are found, the client constructs SRV queries for
				// those transport protocols it supports, and does a query for each.
				// Queries are done using the service identifier "_sip" for SIP URIs and
				// "_sips" for SIPS URIs.  A particular transport is supported if the
				// query is successful.
				final List<String> filteredTransports = filterTransports(isSecure);
				for (String prefTransport : filteredTransports) {
					final Name serviceId = getServiceIdentifier(prefTransport, domain);
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Looking up SRV records for " + serviceId);
					}
					final List<SRVRecord> services = resolver.lookupSRVRecords(serviceId);
					if (isValid(services)) {
						LOGGER.debug("Found " + services.size() + " SRV record(s) for " + serviceId);
						final List<SRVRecord> sortedServices = sortServiceRecords(services);
						hopTransport = prefTransport;
						for (SRVRecord service : sortedServices) {
							if (LOGGER.isDebugEnabled()) {
								LOGGER.debug("Processing SRV record: " + service);
							}
							hops.add(new UnresolvedHop(service.getTarget(), service.getPort(), hopTransport));
						}
					} else if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("No valid SRV records for " + serviceId);
					}
				}
			}

			if (hops.size() == 0) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("No SRV records found for " + domain);
				}
				// 4.1 Para 13
				//
				// If no SRV records are found, the client SHOULD use TCP for a SIPS
				// URI, and UDP for a SIP URI.
				hopTransport = getDefaultTransportForScheme(uri.getScheme());
			}
		}

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Transport selected for " + uri + ": " + hopTransport);
			LOGGER.debug("Determining IP address and port for " + uri);
		}

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
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Transport was sepecified explicitly, so no NAPTR processing was performed.");
					LOGGER.debug("Performing an SRV query for " + hopTransport);
				}
				// 4.2 Para 4
				//
				// If [NAPTR processing] was not [performed], because a transport was
				// specified explicitly, the client performs an SRV query for that
				// specific transport, using the service identifier "_sips" for SIPS URIs.
				// For a SIP URI, if the client wishes to use TLS, it also uses the service
				// identifier "_sips" for that specific transport, otherwise, it uses
				// "_sip".
				final Name serviceId = getServiceIdentifier(hopTransport, domain);
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Looking up SRV records for " + serviceId);
				}
				final List<SRVRecord> services = resolver.lookupSRVRecords(serviceId);
				if (isValid(services)) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Found " + services.size() + " SRV records for " + serviceId + ", so use provided targets and ports");
						LOGGER.debug(services);
					}
					List<SRVRecord> sortedServices = sortServiceRecords(services);
					for (SRVRecord service : sortedServices) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Processing SRV record: " + service);
						}
						hops.add(new UnresolvedHop(service.getTarget(), service.getPort(), hopTransport));
					}
				} else {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("No valid SRV records found for " + serviceId + ", so use default port for " + hopTransport);
					}
					// 4.2 Para 5
					//
					// If no SRV records were found, the client performs an A or AAAA record
					// lookup of the domain name.  The result will be a list of IP
					// addresses, each of which can be contacted using the transport
					// protocol determined previously, at the default port for that
					// transport.
					hops.add(new UnresolvedHop(domain, getDefaultPortForTransport(hopTransport), hopTransport));
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
				hops.add(new UnresolvedHop(domain, getDefaultPortForTransport(hopTransport), hopTransport));
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
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Resolving hop: " + hop);
			}

			Queue<Hop> resolvedIpv4Hops = new LinkedList<Hop>();
			final Set<ARecord> aRecords = resolver.lookupARecords(hop.getHost());

			for (ARecord aRecord : aRecords) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Processing A record: " + aRecord);
				}
				final String ipAddress = aRecord.getAddress().getHostAddress();
				final Hop resolvedHop = new HopImpl(ipAddress, hop.getPort(), hop.getTransport());
				if (resolvedHops.contains(resolvedHop) == false && resolvedIpv4Hops.contains(resolvedHop) == false) {
					resolvedIpv4Hops.add(resolvedHop);
				}
			}

			Queue<Hop> resolvedIpv6Hops = new LinkedList<Hop>();
			if(!ipv4only) {
				final Set<AAAARecord> aaaaRecords = resolver.lookupAAAARecords(hop.getHost());

				for (AAAARecord aaaaRecord : aaaaRecords) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Processing AAAA record: " + aaaaRecord);
					}
					final String ipAddress = aaaaRecord.getAddress().getHostAddress();
					final Hop resolvedHop = new HopImpl(ipAddress, hop.getPort(), hop.getTransport());
					if (resolvedHops.contains(resolvedHop) == false && resolvedIpv6Hops.contains(resolvedHop) == false) {
						resolvedIpv6Hops.add(resolvedHop);
					}
				}
			} else {
				LOGGER.debug("Not resolving AAAA records because " + JAVA_NET_PREFER_IPV_4_STACK + "=true");
			}

			if(ipv6first) {
				LOGGER.debug("Preferring AAAA records because " + JAVA_NET_PREFER_IPV_6_ADDRESSES + "=true");
				resolvedHops.addAll(resolvedIpv6Hops);
				resolvedHops.addAll(resolvedIpv4Hops);
			} else {
				resolvedHops.addAll(resolvedIpv4Hops);
				resolvedHops.addAll(resolvedIpv6Hops);
			}

		}

		return resolvedHops;
	}

	private List<SRVRecord> sortServiceRecords(List<SRVRecord> services) {
		LOGGER.debug("Selecting service record from record set");

		final ServiceRecordSelector selector = new ServiceRecordSelector(services, weightingSorter);
		return selector.select();
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
		if (prefTransports.contains(TLS) == false) {
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
		if (prefTransports.contains(TCP) == false) {
			validServiceFields.remove("SIP+D2T");
		}
		if (prefTransports.contains(UDP) == false) {
			validServiceFields.remove("SIP+D2U");
		}
		if (prefTransports.contains(SCTP) == false) {
			validServiceFields.remove("SIP+D2S");
		}

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Supported NAPTR services: " + validServiceFields);
		}

		// Discard
		final Iterator<NAPTRRecord> iter = pointers.iterator();
		while (iter.hasNext()) {
			final NAPTRRecord pointer = iter.next();
			if (validServiceFields.contains(pointer.getService()) == false) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Removing unsupported NAPTR record: " + pointer);
				}
				iter.remove();
			} else if (isValid(pointer) == false) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Removing invalid NAPTR record: " + pointer);
				}
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
	 * @throws IOException if any DNS error occurs.
	 */
	public Queue<Hop> locate(SipURI uri) throws IOException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("locate(" + uri + ")");
		}
		final String target = getTarget(uri);

		final Queue<Hop> hops = new LinkedList<Hop>();
		if (isNumeric(target)) {
			Hop hop = locateNumeric(uri);
			if (hop != null) {
				hops.add(hop);
			}
		} else {
			hops.addAll(resolveHops(locateNonNumeric(uri)));
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("locate(" + uri + "): " + hops);
		}

		return hops;
	}

	private List<String> filterTransports(boolean isSecure) {
		if (isSecure) {
			final List<String> filteredTransports = new ArrayList<String>(prefTransports);
			Iterator<String> iter = filteredTransports.iterator();
			while (iter.hasNext()) {
				// TLS or SCTP-TLS
				if (iter.next().startsWith(TLS) == false) {
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
