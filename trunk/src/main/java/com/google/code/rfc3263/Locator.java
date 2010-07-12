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
		final String hopTransport;
		final int hopPort;
		
		if (transport != null) {
			if (isSecure) {
				if (transport.equalsIgnoreCase("TCP")) {
					hopTransport = "TLS";
				} else if (transport.equalsIgnoreCase("SCTP")) {
					hopTransport = "SCTP-TLS";
				} else {
					throw new IllegalArgumentException("UDP for SIPS URIs is not supported.");
				}
			} else {
				hopTransport = transport.toUpperCase();
			}
		} else if (isSecure) {
			hopTransport = "TLS";
		} else {
			hopTransport = "UDP";
		}
		
		if (port != -1) {
			hopPort = port;
		} else if (isSecure) {
			hopPort = 5061;
		} else {
			hopPort = 5060;
		}
		
		hops.add(new HopImpl(domain, hopPort, hopTransport));
		return hops;
	}
	
	protected Queue<Hop> locate(String domain, int port, String transport, boolean isSecure) throws UnknownHostException {
		final Queue<Hop> hops = new LinkedList<Hop>();
		final Queue<Hop> partialHops = new LinkedList<Hop>();
		boolean servicesFound = false;
		
		if (transport != null) {
			if (isSecure) {
				if (transport.equalsIgnoreCase("TCP")) {
					partialHops.add(new HopImpl(null, -1, "TLS"));
				} else if (transport.equalsIgnoreCase("SCTP")) {
					partialHops.add(new HopImpl(null, -1, "SCTP-TLS"));
				} else {
					throw new IllegalArgumentException("UDP for SIPS URIs is not supported.");
				}
			} else {
				partialHops.add(new HopImpl(null, -1, transport.toUpperCase()));
			}
		} else if (port != -1) {
			if (isSecure) {
				partialHops.add(new HopImpl(null, -1, "TLS"));
			} else {
				partialHops.add(new HopImpl(null, -1, "UDP"));
			}
		} else {
			final SortedSet<PointerRecord> pointers = resolver.lookupPointerRecords(domain);
			
			if (pointers.size() > 0) {
				final Set<String> validServiceFields = new HashSet<String>();
				validServiceFields.addAll(serviceTransportMap.keySet());
				
				if (isSecure) {
					validServiceFields.remove("SIP+D2T");
					validServiceFields.remove("SIP+D2U");
					validServiceFields.remove("SIP+D2S");
				}
				
				if (prefTransports.contains("TLS") == false) {
					validServiceFields.remove("SIPS+D2T");
				}
				if (prefTransports.contains("SCTP-TLS") == false) {
					validServiceFields.remove("SIPS+D2S");
				}
				if (prefTransports.contains("TCP") == false) {
					validServiceFields.remove("SIP+D2T");
				}
				if (prefTransports.contains("UDP") == false) {
					validServiceFields.remove("SIP+D2U");
				}
				if (prefTransports.contains("SCTP") == false) {
					validServiceFields.remove("SIP+D2S");
				}
	
				final Iterator<PointerRecord> iter = pointers.iterator();
				while (iter.hasNext()) {
					final PointerRecord pointer = iter.next();
					if (validServiceFields.contains(pointer.getService()) == false) {
						iter.remove();
					}
				}
				
				for (PointerRecord pointer : pointers) {
					final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(pointer.getReplacement());
					if (services.size() > 0) {
						servicesFound = true;
						
						for (ServiceRecord service : services) {
							partialHops.add(new HopImpl(service.getTarget(), service.getPort(), serviceTransportMap.get(pointer.getService())));
						}
					}
				}
			} else {
				List<String> filteredTransports = filterTransports(isSecure);
				for (String prefTransport : filteredTransports) {
					String serviceId = getServiceIdentifier(prefTransport, domain);
					final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
					if (services.size() > 0) {
						servicesFound = true;
						
						for (ServiceRecord service : services) {
							partialHops.add(new HopImpl(service.getTarget(), service.getPort(), prefTransport));
						}
					}
				}
			}
			
			if (servicesFound == false) {
				if (isSecure) {
					partialHops.add(new HopImpl(null, -1, "TLS"));
				} else {
					partialHops.add(new HopImpl(null, -1, "UDP"));
				}
			}
		}
		
		if (port != -1) {
			Set<AddressRecord> addresses = resolver.lookupAddressRecords(domain);
			for (AddressRecord address : addresses) {
				for (Hop partialHop : partialHops) {
					hops.add(new HopImpl(address.getAddress().getHostAddress(), port, partialHop.getTransport()));
				}
			}
		} else {
			if (servicesFound) {
				for (Hop partialHop : partialHops) {
					Set<AddressRecord> addresses = resolver.lookupAddressRecords(partialHop.getHost());
					for (AddressRecord address : addresses) {
						hops.add(new HopImpl(address.getAddress().getHostAddress(), partialHop.getPort(), partialHop.getTransport()));
					}
				}
			} else if (transport != null) {
				// Guaranteed to be only one partial hop.
				
				Hop partialHop = partialHops.poll();
				String serviceId = getServiceIdentifier(partialHop.getTransport(), domain);
				final SortedSet<ServiceRecord> services = resolver.lookupServiceRecords(serviceId);
				if (services.size() > 0) {
					for (ServiceRecord service : services) {
						Set<AddressRecord> addresses = resolver.lookupAddressRecords(service.getTarget());
						for (AddressRecord address : addresses) {
							hops.add(new HopImpl(address.getAddress().getHostAddress(), service.getPort(), partialHop.getTransport()));
						}
					}
				} else {
					int hopPort = isSecure ? 5061 : 5060;
					Set<AddressRecord> addresses = resolver.lookupAddressRecords(domain);
					for (AddressRecord address : addresses) {
						hops.add(new HopImpl(address.getAddress().getHostAddress(), hopPort, partialHop.getTransport()));
					}
				}
			} else {
				int hopPort = isSecure ? 5061 : 5060;
				Set<AddressRecord> addresses = resolver.lookupAddressRecords(domain);
				for (AddressRecord address : addresses) {
					for (Hop partialHop : partialHops) {
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
