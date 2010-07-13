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
import java.util.SortedSet;

import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

public class Locator {
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
	
	public Locator(Resolver resolver, List<String> transports) {
		this.resolver = resolver;
		this.prefTransports = transports;
	}
	
	protected Queue<Hop> locateNumeric(String domain, int port, String transport, boolean isSecure) {
		final Queue<Hop> hops = new LinkedList<Hop>();
		
		final String hopAddress;
		final String hopTransport;
		final int hopPort;
		
		if (transport != null) {
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (isSecure) {
				hopTransport = upgradeTransport(transport);
			} else {
				hopTransport = transport.toUpperCase();
			}
		} else {
			// 4.1 Para 3
			//
			// Otherwise, if no transport protocol is specified, but the TARGET is a
			// numeric IP address, the client SHOULD use UDP for a SIP URI, and TCP
			// for a SIPS URI.
			if (isSecure) {
				hopTransport = upgradeTransport("TCP");
			} else {
				hopTransport = "UDP";
			}
		}

		// 4.2 Para 2
		//
		// If TARGET is a numeric IP address, the client uses that address.  If
		// the URI also contains a port, it uses that port.  If no port is
		// specified, it uses the default port for the particular transport
		// protocol.
		hopAddress = domain;
		if (port != -1) {
			hopPort = port;
		} else {
			hopPort = getDefaultPortForTransport(hopTransport);
		}
		
		hops.add(new HopImpl(hopAddress, hopPort, hopTransport));
		return hops;
	}
	
	private int getDefaultPortForTransport(String transport) {
		if (transport.endsWith("TLS")) {
			return 5061;
		} else {
			return 5060;
		}
	}

	private String upgradeTransport(String transport) {
		if (transport.equalsIgnoreCase("tcp")) {
			return "TLS";
		} else if (transport.equalsIgnoreCase("sctp")) {
			return "SCTP-TLS";
		} else {
			throw new IllegalArgumentException("Cannot upgrade " + transport);
		}
	}

	protected Queue<Hop> locate(String domain, int port, String transport, boolean isSecure) throws UnknownHostException {
		final Queue<Hop> hops = new LinkedList<Hop>();
		final Queue<Hop> partialHops = new LinkedList<Hop>();
		boolean servicesFound = false;
		
		if (transport != null) {
			// 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			if (isSecure) {
				partialHops.add(new HopImpl(null, -1, upgradeTransport(transport)));
			} else {
				partialHops.add(new HopImpl(null, -1, transport.toUpperCase()));
			}
		} else if (port != -1) {
			// 4.1 Para 3
			//
			// ... if no transport protocol is specified, and the TARGET is not 
			// numeric, but an explicit port is provided, the client SHOULD use 
			// UDP for a SIP URI, and TCP for a SIPS URI.
			if (isSecure) {
				partialHops.add(new HopImpl(null, -1, upgradeTransport("TCP")));
			} else {
				partialHops.add(new HopImpl(null, -1, "UDP"));
			}
		} else {
			// 4.1 Para 4
			//
			// Otherwise, if no transport protocol or port is specified, and the
			// target is not a numeric IP address, the client SHOULD perform a NAPTR
			// query for the domain in the URI.
			final SortedSet<PointerRecord> pointers = resolver.lookupPointerRecords(domain);
			
			if (pointers.size() > 0) {
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
	
				// Discard
				final Iterator<PointerRecord> iter = pointers.iterator();
				while (iter.hasNext()) {
					final PointerRecord pointer = iter.next();
					if (validServiceFields.contains(pointer.getService()) == false) {
						iter.remove();
					} else if (isValid(pointer) == false) {
						iter.remove();
					}
				}
				
				// 4.1 Para 6
				//
				// The NAPTR processing as described in RFC 2915 will result in 
				// the discovery of the most preferred transport protocol of the 
				// server that is supported by the client, as well as an SRV 
				// record for the server.
				for (PointerRecord pointer : pointers) {
					final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(pointer.getReplacement());
					if (isValid(services)) {
						servicesFound = true;
						
						for (ServiceRecord service : services) {
							partialHops.add(new HopImpl(service.getTarget(), service.getPort(), serviceTransportMap.get(pointer.getService())));
						}
					}
				}
			} else {
				// 4.1 Para 12
				//
				// If no NAPTR records are found, the client constructs SRV queries for
				// those transport protocols it supports, and does a query for each.
				// Queries are done using the service identifier "_sip" for SIP URIs and
				// "_sips" for SIPS URIs.  A particular transport is supported if the
				// query is successful.
				final List<String> filteredTransports = filterTransports(isSecure);
				for (String prefTransport : filteredTransports) {
					String serviceId = getServiceIdentifier(prefTransport, domain);
					final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
					if (isValid(services)) {
						servicesFound = true;
						
						for (ServiceRecord service : services) {
							partialHops.add(new HopImpl(service.getTarget(), service.getPort(), prefTransport));
						}
					}
				}
			}
			
			if (servicesFound == false) {
				// 4.1 Para 13
				//
				// If no SRV records are found, the client SHOULD use TCP for a SIPS
				// URI, and UDP for a SIP URI.
				if (isSecure) {
					partialHops.add(new HopImpl(null, -1, "TLS"));
				} else {
					partialHops.add(new HopImpl(null, -1, "UDP"));
				}
			}
		}
		
		if (port != -1) {
			// 4.2 Para 3
			//
			// If the TARGET was not a numeric IP address, but a port is present in
			// the URI, the client performs an A or AAAA record lookup of the domain
			// name.  The result will be a list of IP addresses, each of which can
			// be contacted at the specific port from the URI and transport protocol
			// determined previously.
			Set<AddressRecord> addresses = resolver.lookupAddressRecords(domain);
			for (AddressRecord address : addresses) {
				for (Hop partialHop : partialHops) {
					hops.add(new HopImpl(address.getAddress().getHostAddress(), port, partialHop.getTransport()));
				}
			}
		} else {
			// 4.2 Para 4
			//
			// If the TARGET was not a numeric IP address, and no port was present
			// in the URI, the client performs an SRV query on the record returned
			// from the NAPTR processing of Section 4.1, if such processing was
			// performed.
			if (servicesFound) {
				for (Hop partialHop : partialHops) {
					Set<AddressRecord> addresses = resolver.lookupAddressRecords(partialHop.getHost());
					for (AddressRecord address : addresses) {
						hops.add(new HopImpl(address.getAddress().getHostAddress(), partialHop.getPort(), partialHop.getTransport()));
					}
				}
			} else if (transport != null) {
				// 4.2 Para 4
				//
				// If [NAPTR processing] was not [performed], because a transport was 
				// specified explicitly, the client performs an SRV query for that 
				// specific transport, using the service identifier "_sips" for SIPS URIs.  
				// For a SIP URI, if the client wishes to use TLS, it also uses the service
				// identifier "_sips" for that specific transport, otherwise, it uses
				// "_sip".
				Hop partialHop = partialHops.poll();
				String serviceId = getServiceIdentifier(partialHop.getTransport(), domain);
				final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
				if (isValid(services)) {
					for (ServiceRecord service : services) {
						Set<AddressRecord> addresses = resolver.lookupAddressRecords(service.getTarget());
						for (AddressRecord address : addresses) {
							hops.add(new HopImpl(address.getAddress().getHostAddress(), service.getPort(), partialHop.getTransport()));
						}
					}
				} else {
					// 4.2 Para 5
					//
					// If no SRV records were found, the client performs an A or AAAA record
					// lookup of the domain name.  The result will be a list of IP
					// addresses, each of which can be contacted using the transport
					// protocol determined previously, at the default port for that
					// transport.
					int hopPort = getDefaultPortForTransport(partialHop.getTransport());
					Set<AddressRecord> addresses = resolver.lookupAddressRecords(domain);
					for (AddressRecord address : addresses) {
						hops.add(new HopImpl(address.getAddress().getHostAddress(), hopPort, partialHop.getTransport()));
					}
				}
			} else {
				// 4.2 Para 5
				//
				// If no SRV records were found, the client performs an A or AAAA record
				// lookup of the domain name.  The result will be a list of IP
				// addresses, each of which can be contacted using the transport
				// protocol determined previously, at the default port for that
				// transport.
				Set<AddressRecord> addresses = resolver.lookupAddressRecords(domain);
				for (AddressRecord address : addresses) {
					for (Hop partialHop : partialHops) {
						int hopPort = getDefaultPortForTransport(partialHop.getTransport());
						hops.add(new HopImpl(address.getAddress().getHostAddress(), hopPort, partialHop.getTransport()));
					}
				}
			}
		}
		
		return hops;
	}

	public Queue<Hop> locate(SipURI uri) throws UnknownHostException {
		final String transportParam = uri.getTransportParam();
		final String target = getTarget(uri);
		final boolean isTargetNumeric = isNumeric(target);
		final boolean isSecure = uri.isSecure();
		final int providedPort = uri.getPort();

		if (isTargetNumeric) {
			return locateNumeric(target, providedPort, transportParam, isSecure);
		} else {
			return locate(target, providedPort, transportParam, isSecure);
		}
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
		// RFC 3263 Section 4 Para 5

		// We define TARGET as the value of the maddr parameter of
		// the URI, if present, otherwise, the host value of the
		// hostport component of the URI.
		final String maddr = uri.getMAddrParam();
		if (maddr != null) {
			return maddr;
		} else {
			return uri.getHost();
		}
	}
	
	/**
	 * See RFC 2782
	 * 
	 * @param services
	 * @return
	 */
	protected boolean isValid(SortedSet<ServiceRecord> services) {
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
				return true;
			}
			// Non-empty, so a resolvable host name was provided.
			return false;
		} catch (UnknownHostException e) {
			// InetAddress.getByName throws this exception "if no IP address
			// for the host could be found".
			//
			// InetAddress will only attempt resolution for host names, so
			// the argument to this method MUST have been a host name for
			// this exception to have been thrown.
			return false;
		}
	}
	
	protected String getServiceIdentifier(String transport, String host) {
		if (transport.equalsIgnoreCase("TLS") || transport.equalsIgnoreCase("SCTP-TLS")) {
			return getServiceIdentifier(transport, host, true);
		} else {
			return getServiceIdentifier(transport, host, false);
		}
	}
	
	protected String getServiceIdentifier(String transport, String host, boolean isSecure) {
		StringBuilder sb = new StringBuilder();
		
		if (isSecure) {
			sb.append("_sips.");
		} else {
			sb.append("_sip.");
		}
		
		sb.append("_");
		sb.append(transport.toLowerCase());
		sb.append(".");
		sb.append(host);
		sb.append(".");
		
		return sb.toString();
	}
	
	protected Queue<Hop> getHops(String domain, int port, String transport) throws UnknownHostException {
		Queue<Hop> hops = new LinkedList<Hop>();
		
		final Set<AddressRecord> hosts = resolver.lookupAddressRecords(domain);
		for (AddressRecord host : hosts) {
			hops.add(new HopImpl(host.getAddress().getHostAddress(), port, transport.toUpperCase()));
		}
		
		return hops;
	}
	
	protected Queue<Hop> getHops(String host, String transport, boolean isSecure) throws UnknownHostException {
		return getHops(host, getDefaultPort(isSecure), transport);
	}
	
	protected Queue<Hop> getHops(String host, int port, boolean isSecure) throws UnknownHostException {
		return getHops(host, port, getDefaultTransport(isSecure));
	}
	
	protected Queue<Hop> getHops(String host, boolean isSecure) throws UnknownHostException {
		return getHops(host, getDefaultPort(isSecure), getDefaultTransport(isSecure));
	}
	
	protected int getDefaultPort(boolean isSecure) {
		return isSecure ? 5061 : 5060;
	}
	
	protected String getDefaultTransport(boolean isSecure) {
		return isSecure ? "TLS" : "UDP";
	}
}
