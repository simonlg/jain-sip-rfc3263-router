package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.SortedSet;

import javax.sip.ListeningPoint;
import javax.sip.address.SipURI;

import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;

public class Locator {
	private final Resolver resolver;
	private String transport;
	
	public Locator(Resolver resolver) {
		this.resolver = resolver;
	}
	
	public void locate(SipURI uri) {
		selectTransport(uri);
	}
	
	protected String selectTransport(SipURI uri) {
		// RFC 3263 Section 4.1 Para 2
		//
		// If the URI specifies a transport protocol in the transport parameter,
		// that transport protocol SHOULD be used.
		if (uri.getTransportParam() != null) {
			return uri.getTransportParam();
		}
		// RFC 3263 Section 4.1 Para 3
		//
		// Otherwise, if no transport protocol is specified, but the TARGET is a
		// numeric IP address, the client SHOULD use UDP for a SIP URI, and TCP
		// for a SIPS URI.  Similarly, if no transport protocol is specified,
		// and the TARGET is not numeric, but an explicit port is provided, the
		// client SHOULD use UDP for a SIP URI, and TCP for a SIPS URI.  This is
		// because UDP is the only mandatory transport in RFC 2543 [6], and thus
		// the only one guaranteed to be interoperable for a SIP URI.  It was
		// also specified as the default transport in RFC 2543 when no transport
		// was present in the SIP URI.  However, another transport, such as TCP,
		// MAY be used if the guidelines of SIP mandate it for this particular
		// request.  That is the case, for example, for requests that exceed the
		// path MTU.
		if (isNumeric(getTarget(uri))) {
			if (uri.isSecure() == false) {
				return ListeningPoint.UDP;
			} else {
				return ListeningPoint.TCP;
			}
		} else if (uri.getPort() != -1) {
			if (uri.isSecure() == false) {
				return ListeningPoint.UDP;
			} else {
				return ListeningPoint.TCP;
			}
		}
		// RFC 3263 Section 4.1 Para 4
		//
		// Otherwise, if no transport protocol or port is specified, and the
		// target is not a numeric IP address, the client SHOULD perform a NAPTR
		// query for the domain in the URI.  The services relevant for the task
		// of transport protocol selection are those with NAPTR service fields
		// with values "SIP+D2X" and "SIPS+D2X", where X is a letter that
		// corresponds to a transport protocol supported by the domain.  This
		// specification defines D2U for UDP, D2T for TCP, and D2S for SCTP.  We
		// also establish an IANA registry for NAPTR service name to transport
		// protocol mappings.
		SortedSet<PointerRecord> pointers = resolver.lookupPointerRecords(uri.getHost(), uri.isSecure()); 
		
		return null;
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
}
