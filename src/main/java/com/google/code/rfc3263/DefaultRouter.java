package com.google.code.rfc3263;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Queue;

import javax.sip.ListeningPoint;
import javax.sip.SipException;
import javax.sip.SipProvider;
import javax.sip.SipStack;
import javax.sip.address.Hop;
import javax.sip.address.Router;
import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.header.RouteHeader;
import javax.sip.message.Request;

import org.apache.log4j.Logger;

import com.google.code.rfc3263.dns.DefaultResolver;

/**
 * JAIN-SIP router implementation that uses the procedures laid out in RFC 3261
 * and RFC 3263 to locate the hop to which a given request should be routed.
 * <p>
 * This class is stateless, meaning that in a stable DNS environment, multiple invocations
 * of {@link #getNextHop(javax.sip.Request)} will always return the same hop.  Clients wishing
 * to react to unstable environments, where a SIP server might be unavailable, should use
 * the {@link Locator} instead, and use the resulting {@link javax.sip.address.Hop} to create a 
 * {@link javax.sip.header.RouteHeader} instead.
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc3261.txt">RFC 3261</a>
 * @see <a href="http://www.ietf.org/rfc/rfc3263.txt">RFC 3263</a>
 */
public class DefaultRouter implements Router {
	private static final Logger LOGGER = Logger.getLogger(DefaultRouter.class);
	private final Hop outboundProxy;
	private final Locator locator;

	/**
	 * Creates a new instance of this class.
	 * 
	 * @param sipStack the SipStack to use.
	 * @param outboundProxy the outbound proxy specified by the user.
	 */
	public DefaultRouter(SipStack sipStack, String outboundProxy) {
		this(sipStack, outboundProxy, new Locator(new DefaultResolver(), getSupportedTransports(sipStack)));
	}
	
	protected DefaultRouter(SipStack sipStack, String outboundProxy, Locator locator) {
		LOGGER.debug("Router instantiated for " + sipStack);
		
		this.locator = locator;
		if (outboundProxy == null) {
			this.outboundProxy = null;
		} else {
			try {
				this.outboundProxy = HopParser.parseHop(outboundProxy);
			} catch (ParseException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public Hop getNextHop(Request request) throws SipException {
		LOGGER.debug("Attempting to route the following request \n\n" + request);
		final SipURI destination;
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

		final URI requestUri = request.getRequestURI();
		if (requestUri.isSipURI() == false) {
			LOGGER.warn("Request-URI is not a SIP URI.  Unable to route request");
			throw new SipException("Can't route non-SIP URI" + requestUri);
		}
		final SipURI requestSipUri = (SipURI) requestUri;
		
		final ListIterator<?> routes = request.getHeaders(RouteHeader.NAME);
		if (routes.hasNext()) {
			LOGGER.debug("Route set found");
			// We have a Route set.  Get the top route.
			// TODO: Should this be popped?
			final RouteHeader route = (RouteHeader) routes.next();
			final URI routeUri = route.getAddress().getURI();
			if (routeUri.isSipURI() == false) {
				LOGGER.warn("Top route in set is not a SIP URI.  Unable to route request");
				throw new SipException("Can't route non-SIP URI" + routeUri);
			}
			final SipURI routeSipUri = (SipURI) routeUri;
			if (routeSipUri.hasLrParam() == false) {
				LOGGER.debug("First element in route set indicates a strict router.  Using Request-URI for input");
				// RFC 3261 Section 8.1.2 Para 1 (Cont)
				//
				// If the first element in the route set indicated a strict router, 
				// the procedures MUST be applied to the Request-URI of the request.
				destination = requestSipUri;
			} else {
				LOGGER.debug("First element in route set indicates a loose router.  Using route for input");
				// RFC 3261 Section 8.1.2 Para 1 (Cont)
				//
				// Otherwise, the procedures are applied to the first Route header field
				// value in the request
				destination = routeSipUri;
			}
		} else if (outboundProxy != null) {
			LOGGER.debug("Outbound proxy has been defined, returning proxy hop.");
			return outboundProxy;
		} else {
			LOGGER.debug("No route set found.  Using Request-URI for input");
			// RFC 3261 Section 8.1.2 Para 1 (Cont)
			//
			// Otherwise, the procedures are applied to ... the request's Request-URI
			// if there is no Route header field present.
			destination = requestSipUri;
		}
		
		// RFC 3261 Section 8.1.2 Para 1 (Cont)
		//
		// if the Request-URI specifies a SIPS resource, the UAC MUST follow 
		// the procedures of [4] as if the input URI were a SIPS URI.
		if (requestSipUri.isSecure()) {
			LOGGER.debug("Request URI is a SIPS URI.  Treating input URI as a SIPS URI too");
			destination.setSecure(true);
		}
//		Locator locator = new Locator(resolver, getSupportedTransports());
		try {
			Queue<Hop> hops = locator.locate(destination);
			if (hops.size() > 0) {
				return hops.poll();
			} else {
				return null;
			}
		} catch (IllegalArgumentException e) {
			throw new SipException("Rethrowing", e);
		}
	}

	/**
	 * This method is deprecated, so this method returns the bare
	 * minimum, which is an empty iterator. 
	 * 
	 * @param request the request to retrieve the next hops for.
	 * @return an empty ListIterator.
	 */
	@Deprecated
	public ListIterator<?> getNextHops(Request request) {
		return new LinkedList<Hop>().listIterator();
	}

	/**
	 * {@inheritDoc}
	 */
	public Hop getOutboundProxy() {
		return outboundProxy;
	}

	protected static List<String> getSupportedTransports(SipStack sipStack) {
		LOGGER.debug("Determining transports supported by stack");
		final List<String> supportedTransports = new ArrayList<String>();

		final Iterator<?> providers = sipStack.getSipProviders();
		while (providers.hasNext()) {
			SipProvider provider = (SipProvider) providers.next();
			for (ListeningPoint endpoint : provider.getListeningPoints()) {
				supportedTransports.add(endpoint.getTransport().toUpperCase());
			}
		}
		
		LOGGER.debug("Supported transports: " + supportedTransports);
		return supportedTransports;
	}
}
