package com.google.code.rfc3263;

import java.util.ListIterator;

import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.header.RouteHeader;
import javax.sip.message.Request;

import org.apache.log4j.Logger;

/**
 * This class is used for applying the procedures defined in RFC 3261 Section 8.2.1 to
 * a SIP request for the selection of the SIP URI to which procedures defined in RFC 3263 
 * should be applied.
 */
public final class DestinationSelector {
	private static final Logger LOGGER = Logger.getLogger(DestinationSelector.class);
	
	public static SipURI select(Request request) {
		LOGGER.debug("select(" + request + ")"); 
		// RFC 3261 Section 8.1.2 Para 1
		//
		// The destination for the request is then computed.  Unless there is
		// local policy specifying otherwise, the destination MUST be determined
		// by applying the DNS procedures described in [4] as follows.  If the
		// first element in the route set indicated a strict router (resulting
		// in forming the request as described in Section 12.2.1.1), the
		// procedures MUST be applied to the Request-URI of the request.
		// Otherwise, the procedures are applied to the first Route header field
		// value in the request (if one exists), or to the request's Request-URI
		// if there is no Route header field present.  These procedures yield an
		// ordered set of address, port, and transports to attempt.  Independent
		// of which URI is used as input to the procedures of [4], if the
		// Request-URI specifies a SIPS resource, the UAC MUST follow the
		// procedures of [4] as if the input URI were a SIPS URI.
		
		final SipURI requestUri = (SipURI) request.getRequestURI();
		final SipURI destination;
		
		final ListIterator<?> routes = request.getHeaders(RouteHeader.NAME);
		if (routes.hasNext()) {
			LOGGER.debug("Request contains 1 or more Route headers");
			// We have a Route set.  Get the top route.
			final RouteHeader route = (RouteHeader) routes.next();
			final URI routeUri = route.getAddress().getURI();
			if (routeUri.isSipURI() == false) {
				LOGGER.error("Top route in set is not a SIP URI.  Unable to route request");
				throw new IllegalArgumentException("Can't route non-SIP URI" + routeUri);
			}
			final SipURI routeSipUri = (SipURI) routeUri;
			if (routeSipUri.hasLrParam() == false) {
				LOGGER.debug("Top Route header indicates a strict router.  Using Request-URI for input");
				// RFC 3261 Section 8.1.2 Para 1 (Cont)
				//
				// If the first element in the route set indicated a strict router, 
				// the procedures MUST be applied to the Request-URI of the request.
				destination = requestUri;
			} else {
				LOGGER.debug("Top Route header indicates a loose router.  Using route for input");
				// RFC 3261 Section 8.1.2 Para 1 (Cont)
				//
				// Otherwise, the procedures are applied to the first Route header field
				// value in the request
				destination = routeSipUri;
			}
		} else {
			LOGGER.debug("No Route header field present.  Using Request-URI for input");
			// RFC 3261 Section 8.1.2 Para 1 (Cont)
			//
			// Otherwise, the procedures are applied to ... the request's Request-URI
			// if there is no Route header field present.
			destination = requestUri;
		}
		
		// RFC 3261 Section 8.1.2 Para 1 (Cont)
		//
		// if the Request-URI specifies a SIPS resource, the UAC MUST follow 
		// the procedures of [4] as if the input URI were a SIPS URI.
		if (requestUri.isSecure()) {
			LOGGER.debug("Request URI is a SIPS URI.  Treating input URI as a SIPS URI too");
			destination.setSecure(true);
		}
		
		LOGGER.debug("select(" + request + "): " + destination);
		return destination;
	}
}
