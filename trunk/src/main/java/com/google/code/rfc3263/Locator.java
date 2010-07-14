package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.apache.log4j.Logger;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;
import com.google.code.rfc3263.dns.ServiceRecordPriorityComparator;
import com.google.code.rfc3263.dns.ServiceRecordWeightComparator;

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
	
	public Locator(Resolver resolver, List<String> transports) {
		this.resolver = resolver;
		this.prefTransports = transports;
	}
	
	protected Hop locateNumeric(SipURI uri) {
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
		return new HopImpl(hopAddress, hopPort, hopTransport);
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

	protected Hop locateNonNumeric(SipURI uri) throws UnknownHostException {
		String domain = getTarget(uri);
		
		String hopHost = null;
		String hopAddress = null;
		int hopPort = -1;
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
					ServiceRecord service = selectServiceRecord(services);
					
					hopTransport = serviceTransportMap.get(pointer.getService());
					hopPort = service.getPort();
					hopHost = service.getTarget();
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
						ServiceRecord service = selectServiceRecord(services);

						hopHost = service.getTarget();
						hopPort = service.getPort();
						hopTransport = prefTransport;
						
						break;
					} else {
						LOGGER.debug("No valid SRV records for " + serviceId);
					}
				}
			}
			
			if (hopPort == -1 || hopHost == null) {
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
			hopPort = uri.getPort();
			hopAddress = lookupAddress(domain);
		} else {
			LOGGER.debug("No port is present in the URI");
			// 4.2 Para 4
			//
			// If the TARGET was not a numeric IP address, and no port was present
			// in the URI, the client performs an SRV query on the record returned
			// from the NAPTR processing of Section 4.1, if such processing was
			// performed.
			if (hopPort != -1 && hopHost != null) {
				LOGGER.debug("SRV records found during transport selection");
				hopAddress = lookupAddress(hopHost);
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
					ServiceRecord service = selectServiceRecord(services);
					
					hopPort = service.getPort();
					hopHost = service.getTarget();
					hopAddress = lookupAddress(service.getTarget());
				} else {
					LOGGER.debug("No valid SRV records for " + serviceId);
					// 4.2 Para 5
					//
					// If no SRV records were found, the client performs an A or AAAA record
					// lookup of the domain name.  The result will be a list of IP
					// addresses, each of which can be contacted using the transport
					// protocol determined previously, at the default port for that
					// transport.
					hopPort = getDefaultPortForTransport(hopTransport);
					hopHost = domain;
					hopAddress = lookupAddress(domain);
				}
			} else {
				// 4.2 Para 5
				//
				// If no SRV records were found, the client performs an A or AAAA record
				// lookup of the domain name.  The result will be a list of IP
				// addresses, each of which can be contacted using the transport
				// protocol determined previously, at the default port for that
				// transport.
				hopPort = getDefaultPortForTransport(hopTransport);
				hopHost = domain;
				hopAddress = lookupAddress(domain); 
			}
		}
		
		if (hopAddress != null && hopPort != -1) {
			LOGGER.debug("Determined IP address and port for " + uri + ": " + hopAddress + ":" + hopPort);
		} else {
			LOGGER.debug("Failed to determine IP address and port for " + uri);
		}
		
		if (hopAddress != null && hopPort != -1 && hopTransport != null) {
			return new HopImpl(hopAddress, hopPort, hopTransport);
		} else {
			return null;
		}
	}

	private PointerRecord selectPointerRecord(List<PointerRecord> pointers) {
		LOGGER.debug("Selecting pointer record from record set");
		return pointers.get(0);
	}

	private String lookupAddress(String domain) {
		LOGGER.debug("Attempting to resolve " + domain + " to an IP address");
		final Set<AddressRecord> addresses = resolver.lookupAddressRecords(domain);
		if (addresses.size() > 0) {
			LOGGER.debug("Found " + addresses.size() + " IP address(es) for " + domain);
			AddressRecord address = selectAddressRecord(addresses);
			return address.getAddress().getHostAddress();
		} else {
			LOGGER.debug("No IP addresses found for " + domain);
			return null;
		}
	}
	
	private AddressRecord selectAddressRecord(Set<AddressRecord> addresses) {
		LOGGER.debug("Using first IP address record from set");
		return addresses.iterator().next();
	}
	
	private ServiceRecord selectServiceRecord(List<ServiceRecord> services) {
		LOGGER.debug("Selecting service record from record set");
		
		// RFC 2782 Usage Rules
		
		// Sort the list by priority (lowest number first)
		Collections.sort(services, new ServiceRecordPriorityComparator());
		// Create a new empty list
		List<ServiceRecord> priorityList = new ArrayList<ServiceRecord>();
		
		int p = -1;
		int totalWeight = 0;
		for (ServiceRecord service : services) {
			if (service.getPriority() != p) {
				// Update priority.
				Collections.sort(priorityList, new ServiceRecordWeightComparator());
				
				p = service.getPriority();
				priorityList = new ArrayList<ServiceRecord>();
			}
			priorityList.add(service);
		}
		
		return services.iterator().next();
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

	public Hop locate(SipURI uri) throws UnknownHostException {
		LOGGER.debug("Locating SIP server for " + uri);
		final String target = getTarget(uri);

		final Hop hop;
		if (isNumeric(target)) {
			hop = locateNumeric(uri);
		} else {
			hop = locateNonNumeric(uri);
		}
		if (hop == null) {
			LOGGER.debug("No next hop could be determined for " + uri);
		} else {
			LOGGER.debug("Next hop for " + uri + " is " + hop);
		}
		
		return hop;
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
	 * @return
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
