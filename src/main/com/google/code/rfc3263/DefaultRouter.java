package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.TreeSet;

import javax.sip.ListeningPoint;
import javax.sip.SipException;
import javax.sip.SipStack;
import javax.sip.address.Hop;
import javax.sip.address.Router;
import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.message.Request;

import com.google.code.rfc3263.dns.DefaultResolver;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

/**
 * TODO: Check MTU
 */
public class DefaultRouter implements Router {
	private final SipStack sipStack;
	private final String outboundProxy;

	public DefaultRouter(SipStack sipStack, String outboundProxy) {
		this.sipStack = sipStack;
		this.outboundProxy = outboundProxy;
	}

	@Override
	public Hop getNextHop(Request request) throws SipException {
		final URI uri = request.getRequestURI();

		if (uri instanceof SipURI == false) {
			return null;
		}
		final SipURI sipUri = (SipURI) uri;
		
		List<String> transports = new ArrayList<String>();
		Resolver resolver = new DefaultResolver();
		
		Locator locator = new Locator(resolver, transports);
		try {
			locator.locate(sipUri);
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
		
		Hop transport = selectTransport(sipUri);
		determineHost(sipUri);
		System.out.println(transport);

		return new HopImpl("192.168.11.31", 5060, ListeningPoint.TCP);
	}

	@Override
	public ListIterator<?> getNextHops(Request request) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Hop getOutboundProxy() {
		return null;
	}

	protected String determineHost(SipURI uri) {
		// RFC 3263 Section 4.1
		//
		// If TARGET is a numeric IP address, the client uses that address.
		final String target = getTarget(uri);
		if (isNumeric(target)) {
			if (uri.getPort() != -1) {
				System.out.println("PORT: " + uri.getPort());
			}
			return target;
		} else {
			
		}
		return null;
	}

	protected Hop selectTransport(SipURI uri) {
		final String transportParam = uri.getTransportParam();
		final String target = getTarget(uri);
		final boolean isNumericTarget = isNumeric(target);
		final int uriPort = uri.getPort();
		final boolean isSipsUri = uri.isSecure();
		
		String transport = null;
		String host = null;
		int port = -1;
		
		// RFC 3263 Section 4.1
		//
		// If the URI specifies a transport protocol in the
		// transport parameter, that transport protocol SHOULD
		// be used.
		if (transportParam != null) {
			transport = transportParam;
		} else {
			// RFC 3263 Section 4.1
			//
			// ... if no transport protocol is specified, but the
			// TARGET is a numeric IP address, the client SHOULD
			// use UDP for a SIP URI, and TCP for a SIPS URI.
			if (isNumericTarget) {
				if (isSipsUri) {
					transport = "tcp";
				} else {
					transport = "udp";
				}
				// RFC 3263 Section 4.2
				//
				// If TARGET is a numeric IP address, the client uses that address...
				host = target;
				// ... If the URI also contains a port, it uses that port.  If no port is
				// specified, it uses the default port for the particular transport
				// protocol.
				if (uriPort != -1) {
					port = uriPort;
				} else {
					// No port specified, so use the default port for each transport.
					if (transport.equals("tcp") && isSipsUri) {
						port = ListeningPoint.PORT_5061;
					} else {
						port = ListeningPoint.PORT_5060;
					}
				}
			} else {
				// RFC 3263 Section 4.1
				//
				// ... if no transport protocol is specified, and the
				// TARGET is not numeric, but an explicit port is provided,
				// the client SHOULD use UDP for a SIP URI, and TCP for a
				// SIPS URI.
				if (uriPort != -1) {
					if (isSipsUri) {
						transport = "tcp";
					} else {
						transport = "udp";
					}
				}
			}
		}
		
		if (transport != null) {
			return new HopImpl(transport, port, transport);
		}

		// RFC 3263 Section 4.1
		//
		// ... if no transport protocol or port is specified, and the target
		// is not a numeric IP address, the client SHOULD perform a NAPTR
		// query for the domain in the URI.
		if (transportParam == null && uriPort == -1 && isNumericTarget == false) {
			Set<PointerRecord> pointers = lookupPointerRecords(target);
			List<String> serviceNames = new ArrayList<String>();
			
			if (pointers.size() == 0) {
				// RFC 3263 Section 4.1
				//
				// If no NAPTR records are found, the client constructs SRV queries
				// for those transport protocols it supports, and does a query for each.
				final Set<String> supportedTransports = getSupportedTransportProtocols();
				// TODO: Allow the end user to determine our transport preference.

				// RFC 3263 Section 4.1
				//
				// Queries are done using the service identifier "_sip" for SIP URIs
				// and "_sips" for SIPS URIs.
				if (supportedTransports.contains("tls")) {
					serviceNames.add("_sips._tcp." + target);
				}
				if (supportedTransports.contains("tcp")) {
					serviceNames.add("_sip._tcp." + target);
				}
				if (supportedTransports.contains("udp")) {
					serviceNames.add("_sip._udp." + target);
				}
				if (supportedTransports.contains("sctp")) {
					serviceNames.add("_sip._sctp." + target);
				}
				// Nothing to do for SIPS over SCTP or UDP.
			} else {
				// Found NAPTR records.
				
				// RFC 3263 Section 4.1
				//
				// First, a client resolving a SIPS URI MUST discard any services
				// that do not contain "SIPS" as the protocol in the service field
				if (isSipsUri) {
					discardInsecureTransports(pointers);
				}

				// RFC 3263 Section 4.1
				//
				// Second, a client MUST discard any service fields that identify
				// a resolution service whose value is not "D2X", for values of X
				// that indicate transport protocols supported by the client.
				discardUnsupportedTransports(pointers);

				// NAPTR allows the DNS administrator to indicate their transport
				// preference, so we choose the first one.
				for (PointerRecord pointer : pointers) {
					serviceNames.add(pointer.getReplacement());
				}
			}
			
			// RFC 3263 Section 4.1
			//
			// A particular transport is supported if the query is successful. The
			// client MAY use any transport protocol it desires which is supported by the
			// server.
			//
			// In our case, we'll use the first one we get to, since they are in
			// priority order already.
			if (serviceNames.size() > 0) {
				for (String serviceName : serviceNames) {
					final Set<ServiceRecord> records = lookupServiceRecords(serviceName);
					if (records.size() > 0) {
						// TODO: This is a bit of a hack.
						final String[] parts = serviceName.split("\\.");
						return new HopImpl(null, -1, parts[1].substring(1));
					}
				}
			}
			
			// RFC 3263 Section 4.1
			//
			// If no SRV records are found, the client SHOULD use TCP for a SIPS
			// URI, and UDP for a SIP URI.
			if (isSipsUri) {
				return new HopImpl(null, -1, "tcp");
			} else {
				return new HopImpl(null, -1, "udp");
			}
		}

		return null;
	}

	protected String getTarget(SipURI uri) {
		// RFC 3263 Section 4

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

	protected Set<ServiceRecord> lookupServiceRecords(String service) {
		// TODO: Delegate this so we can inject the DNS lookup.
		final Set<ServiceRecord> services = new TreeSet<ServiceRecord>();

		services.add(new ServiceRecord(0, 1, 5060, "server1.example.org"));
		services.add(new ServiceRecord(0, 1, 5060, "server2.example.org"));

		return services;
	}

	protected Set<PointerRecord> lookupPointerRecords(String target) {
		// TODO: Delegate this so we can inject the DNS lookup.
		final Set<PointerRecord> pointers = new TreeSet<PointerRecord>();

		return pointers;
		// pointers.add(new PointerRecord(10, 50, "s", "SIPS+D2S", "",
		// "_sips._sctp." + target + "."));
		// pointers.add(new PointerRecord(20, 50, "s", "SIPS+D2T", "",
		// "_sips._tcp." + target + "."));
		// pointers.add(new PointerRecord(30, 50, "s", "SIPS+D2U", "",
		// "_sips._udp." + target + "."));
		// pointers.add(new PointerRecord(40, 50, "s", "SIP+D2S", "",
		// "_sip._sctp." + target + "."));
		// pointers.add(new PointerRecord(50, 50, "s", "SIP+D2T", "",
		// "_sip._tcp." + target + "."));
		// pointers.add(new PointerRecord(60, 50, "s", "SIP+D2U", "",
		// "_sip._udp." + target + "."));
		//
		// return pointers;
	}

	protected Set<String> getSupportedTransportProtocols() {
		// TODO: Should these listening points be associated with a
		// SIP Provider?
		final Iterator<?> iter = sipStack.getListeningPoints();
		final Set<String> supportedTransports = new HashSet<String>();
		while (iter.hasNext()) {
			ListeningPoint endpoint = (ListeningPoint) iter.next();
			supportedTransports.add(endpoint.getTransport());
		}

		return supportedTransports;
	}

	protected void discardInsecureTransports(Set<PointerRecord> pointers) {
		final Iterator<PointerRecord> iter = pointers.iterator();
		while (iter.hasNext()) {
			final PointerRecord pointer = iter.next();

			if (pointer.getService().contains("SIPS") == false) {
				iter.remove();
			}
		}
	}

	protected void discardUnsupportedTransports(Set<PointerRecord> pointers) {
		final Set<String> supportedTransports = getSupportedTransportProtocols();
		if (supportedTransports.contains("sctp") == false) {
			final Iterator<PointerRecord> iter = pointers.iterator();
			while (iter.hasNext()) {
				final PointerRecord pointer = iter.next();

				if (pointer.getService().equals("SIP+D2S")) {
					iter.remove();
				}
			}
		}
		if (supportedTransports.contains("tcp") == false) {
			final Iterator<PointerRecord> iter = pointers.iterator();
			while (iter.hasNext()) {
				final PointerRecord pointer = iter.next();

				if (pointer.getService().equals("SIP+D2T")) {
					iter.remove();
				}
			}
		}
		if (supportedTransports.contains("udp") == false) {
			final Iterator<PointerRecord> iter = pointers.iterator();
			while (iter.hasNext()) {
				final PointerRecord pointer = iter.next();

				if (pointer.getService().equals("SIP+D2U")) {
					iter.remove();
				}
			}
		}
		if (supportedTransports.contains("tls") == false) {
			final Iterator<PointerRecord> iter = pointers.iterator();
			while (iter.hasNext()) {
				final PointerRecord pointer = iter.next();

				if (pointer.getService().equals("SIPS+D2T")) {
					iter.remove();
				}
			}
		}
		// No transport support in JAIN-SIP for SIPS over SCTP or UDP,
		// so delete always.
		final Iterator<PointerRecord> iter = pointers.iterator();
		while (iter.hasNext()) {
			final PointerRecord pointer = iter.next();

			if (pointer.getService().equals("SIPS+D2S")) {
				iter.remove();
			}
			if (pointer.getService().equals("SIPS+D2U")) {
				iter.remove();
			}
		}
	}
}
