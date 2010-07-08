package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

public class Locator {
	private final Resolver resolver;
	private final List<String> transports;
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
		this.transports = transports;
	}
	
	public List<Hop> locate(SipURI uri) throws UnknownHostException {
		return selectTransport(uri);
	}
	
	protected List<Hop> selectTransport(SipURI uri) throws UnknownHostException {
		List<Hop> hops = new ArrayList<Hop>();
		
		if (uri.getTransportParam() != null) {
			String transport = uri.getTransportParam().toUpperCase();
			
			final String serviceId;
			// If ... a transport was specified explicitly, the client performs an 
			// SRV query for that specific transport, using the service identifier 
			// "_sips" for SIPS URIs.  For a SIP URI, if the client wishes to use 
			// TLS, it also uses the service identifier "_sips" for that specific 
			// transport, otherwise, it uses "_sip".
			if (uri.isSecure()) {
				serviceId = getServiceIdentifier(transport, uri.getHost(), true);
			} else {
				// Work out if a client wishes to use TLS.
				if (transport.equals("UDP")) {
					// No option for UDP, which is always false.
					serviceId = getServiceIdentifier(transport, uri.getHost(), false);
				} else if (transport.equals("TCP")) {
					if (transports.contains("TCP") && transports.contains("TLS")) {
						if (transports.indexOf("TLS") < transports.indexOf("TCP")) {
							serviceId = getServiceIdentifier(transport, uri.getHost(), true);
						} else {
							serviceId = getServiceIdentifier(transport, uri.getHost(), false);
						}
					} else {
						if (transports.contains("TLS")) {
							serviceId = getServiceIdentifier(transport, uri.getHost(), true);
						} else if (transports.contains("TCP")) {
							serviceId = getServiceIdentifier(transport, uri.getHost(), false);
						} else {
							throw new IllegalStateException("No usable transports (TCP or TLS) for transport flag: " + transport);
						}
					}
				} else if (transport.equals("SCTP")) {
					if (transports.contains("SCTP") && transports.contains("SCTP-TLS")) {
						if (transports.indexOf("SCTP-TLS") < transports.indexOf("SCTP")) {
							serviceId = getServiceIdentifier(transport, uri.getHost(), true);
						} else {
							serviceId = getServiceIdentifier(transport, uri.getHost(), false);
						}
					} else {
						if (transports.contains("SCTP-TLS")) {
							serviceId = getServiceIdentifier(transport, uri.getHost(), true);
						} else if (transports.contains("SCTP")) {
							serviceId = getServiceIdentifier(transport, uri.getHost(), false);
						} else {
							throw new IllegalStateException("No usable transports (SCTP or SCTP-TLS) for transport flag: " + transport);
						}
					}
				} else {
					throw new IllegalStateException("Unrecognised transport flag: " + transport);
				}
			}
			SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
			final int port;
			final InetAddress[] hosts;
			if (services.size() > 0) {
				ServiceRecord service = services.iterator().next();
				hosts = InetAddress.getAllByName(service.getTarget());
				port = service.getPort();
			} else {
				// If no SRV records were found, the client performs an A or AAAA record
				// lookup of the domain name.  The result will be a list of IP
				// addresses, each of which can be contacted using the transport
				// protocol determined previously, at the default port for that
				// transport.  Processing then proceeds as described above for an
				// explicit port once the A or AAAA records have been looked up.
				hosts = InetAddress.getAllByName(uri.getHost());
				// TODO: Invalid Port
				port = -1;
			}
			
			// RFC 3263 Section 4.1 Para 2
			//
			// If the URI specifies a transport protocol in the transport parameter,
			// that transport protocol SHOULD be used.
			for (InetAddress host : hosts) {
				hops.add(new HopImpl(host.getHostAddress(), port, uri.getTransportParam()));
			}
			return hops;
		}
		if (isNumeric(getTarget(uri))) {
			// RFC 3263 Section 4.1 Para 2
			//
			// If TARGET is a numeric IP address, the client uses that address.  If
			// the URI also contains a port, it uses that port.  If no port is
			// specified, it uses the default port for the particular transport
			// protocol.
			final InetAddress[] hosts = InetAddress.getAllByName(getTarget(uri));
			final int port;
			if (uri.getPort() != -1) {
				// RFC 3263 Section 4.1 Para 2 (Cont)
				//
				// If the URI also contains a port, it uses that port.
				port = uri.getPort();
			} else {
				// RFC 3263 Section 4.1 Para 2 (Cont)
				//
				// If no port is specified, it uses the default port for the 
				// particular transport protocol.
				if (uri.isSecure()) {
					port = 5061;
				} else {
					port = 5060;
				}
			}
			// RFC 3263 Section 4.1 Para 3
			//
			// Otherwise, if no transport protocol is specified, but the TARGET is a
			// numeric IP address, the client SHOULD use UDP for a SIP URI, and TCP
			// for a SIPS URI.
			if (uri.isSecure() == false) {
				for (InetAddress host : hosts) {
					hops.add(new HopImpl(host.getHostAddress(), port, "UDP"));
				}
			} else {
				for (InetAddress host : hosts) {
					hops.add(new HopImpl(host.getHostAddress(), port, "TCP"));
				}
			}
			return hops;
		} else if (uri.getPort() != -1) {
			// RFC 3263 Section 4.2 Para 3
			//
			// If the TARGET was not a numeric IP address, but a port is present in
			// the URI, the client performs an A or AAAA record lookup of the domain
			// name.
			final InetAddress[] hosts = InetAddress.getAllByName(getTarget(uri));
			final int port = uri.getPort();
			// RFC 3263 Section 4.1 Para 3 (Cont)
			//
			// Similarly, if no transport protocol is specified, and the TARGET is 
			// not numeric, but an explicit port is provided, the client SHOULD use 
			// UDP for a SIP URI, and TCP for a SIPS URI.
			if (uri.isSecure() == false) {
				for (InetAddress host : hosts) {
					hops.add(new HopImpl(host.getHostAddress(), port, "UDP"));
				}
			} else {
				for (InetAddress host : hosts) {
					hops.add(new HopImpl(host.getHostAddress(), port, "TCP"));
				}
			}
			return hops;
		}
		// RFC 3263 Section 4.1 Para 4
		//
		// Otherwise, if no transport protocol or port is specified, and the
		// target is not a numeric IP address, the client SHOULD perform a NAPTR
		// query for the domain in the URI.
		final SortedSet<PointerRecord> pointers = resolver.lookupPointerRecords(uri.getHost());
		
		if (pointers.size() > 0) {
			// RFC 3263 Section 4.1 Para 4 (Cont)
			//
			// The services relevant for the task of transport protocol selection are 
			// those with NAPTR service fields with values "SIP+D2X" and "SIPS+D2X", 
			// where X is a letter that corresponds to a transport protocol supported 
			// by the domain.  This specification defines D2U for UDP, D2T for TCP, and 
			// D2S for SCTP.  We also establish an IANA registry for NAPTR service name 
			// to transport protocol mappings.
			final Set<String> validServiceFields = new HashSet<String>();
			validServiceFields.addAll(serviceTransportMap.keySet());
			
			// RFC 3263 Section 4.1 Para 5
			//
			// These NAPTR records provide a mapping from a domain to the SRV record
			// for contacting a server with the specific transport protocol in the
			// NAPTR services field.  The resource record will contain an empty
			// regular expression and a replacement value, which is the SRV record
			// for that particular transport protocol.  If the server supports
			// multiple transport protocols, there will be multiple NAPTR records,
			// each with a different service value.  As per RFC 2915 [3], the client
			// discards any records whose services fields are not applicable.  For
			// the purposes of this specification, several rules are defined.
			
			// RFC 3263 Section 4.1 Para 6
			//
			// First, a client resolving a SIPS URI MUST discard any services that
			// do not contain "SIPS" as the protocol in the service field.  The
			// converse is not true, however.
			if (uri.isSecure()) {
				validServiceFields.remove("SIP+D2T");
				validServiceFields.remove("SIP+D2U");
				validServiceFields.remove("SIP+D2S");
			}
			
			// RFC 3263 Section 4.1 Para 6 (Cont)
			//
			// A client resolving a SIP URI SHOULD retain records with "SIPS" as the 
			// protocol, if the client supports TLS.
			//
			// NOTE: "TLS" here is taken to mean TLS over TCP or SCTP.
			if (transports.contains("TLS") == false) {
				validServiceFields.remove("SIPS+D2T");
			}
			if (transports.contains("SCTP-TLS") == false) {
				validServiceFields.remove("SIPS+D2S");
			}
	
			// RFC 3263 Section 4.1 Para 6 (Cont)
			//
			// Second, a client MUST discard any service fields that identify
			// a resolution service whose value is not "D2X", for values of X that
			// indicate transport protocols supported by the client.  The NAPTR
			// processing as described in RFC 2915 will result in the discovery of
			// the most preferred transport protocol of the server that is supported
			// by the client, as well as an SRV record for the server.  It will also
			// allow the client to discover if TLS is available and its preference
			// for its usage.
			if (transports.contains("TCP") == false) {
				validServiceFields.remove("SIP+D2T");
			}
			if (transports.contains("UDP") == false) {
				validServiceFields.remove("SIP+D2U");
			}
			if (transports.contains("SCTP") == false) {
				validServiceFields.remove("SIP+D2S");
			}
			
			final Iterator<PointerRecord> iter = pointers.iterator();
			while (iter.hasNext()) {
				final PointerRecord pointer = iter.next();
				if (validServiceFields.contains(pointer.getService()) == false) {
					iter.remove();
				}
			}
			
			if (pointers.size() > 0) {
				for (PointerRecord pointer : pointers) {
					final String domain = pointer.getReplacement();
					final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(domain);
					if (services.size() > 0) {
						for (ServiceRecord service : services) {
							final InetAddress[] hosts = InetAddress.getAllByName(service.getTarget());
							final int port = service.getPort();
							String transport = serviceTransportMap.get(pointer.getService());
							for (InetAddress host : hosts) {
								hops.add(new HopImpl(host.getHostAddress(), port, transport));
							}
						}
					}
				}
				return hops;
			}
		} else {
			// RFC 3263 Section 4.1 Para 12
			//
			// If no NAPTR records are found, the client constructs SRV queries for
			// those transport protocols it supports, and does a query for each.
			// Queries are done using the service identifier "_sip" for SIP URIs and
			// "_sips" for SIPS URIs.  A particular transport is supported if the
			// query is successful.  The client MAY use any transport protocol it
			// desires which is supported by the server.
			for (String transport : transports) {
				final String domain = serviceIdTransportMap.get(transport) + uri.getHost() + ".";
				final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(domain);
				if (services.size() > 0) {
					for (ServiceRecord service : services) {
						final InetAddress[] hosts = InetAddress.getAllByName(service.getTarget());
						final int port = service.getPort();
						for (InetAddress host : hosts) {
							hops.add(new HopImpl(host.getHostAddress(), port, transport));
						}
					}
				}
			}
			if (hops.size() > 0) {
				return hops;
			}
		}
		// RFC 3263 Section 4.2 Para 5
		//
		// If no SRV records were found, the client performs an A or AAAA record
		// lookup of the domain name.  The result will be a list of IP
		// addresses, each of which can be contacted using the transport
		// protocol determined previously, at the default port for that
		// transport.  Processing then proceeds as described above for an
		// explicit port once the A or AAAA records have been looked up.
		final InetAddress[] hosts = InetAddress.getAllByName(uri.getHost());
		final int port;
		final String transport;
		
		// RFC 3263 Section 4.1 Para 13
		//
		// If no SRV records are found, the client SHOULD use TCP for a SIPS
		// URI, and UDP for a SIP URI.  However, another transport protocol,
		// such as TCP, MAY be used if the guidelines of SIP mandate it for this
		// particular request.  That is the case, for example, for requests that
		// exceed the path MTU.
		if (uri.isSecure()) {
			port = 5061;
			transport = "TCP";
			
		} else {
			port = 5060;
			transport = "UDP";
		}
		for (InetAddress host : hosts) {
			hops.add(new HopImpl(host.getHostAddress(), port, transport));
		}
		return hops;
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
}
