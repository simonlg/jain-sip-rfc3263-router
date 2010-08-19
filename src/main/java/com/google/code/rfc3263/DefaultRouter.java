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
import javax.sip.message.Request;

import org.apache.log4j.Logger;

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
	private final SipStack sipStack;

	/**
	 * Creates a new instance of this class.
	 * 
	 * @param sipStack the SipStack to use.
	 * @param outboundProxy the outbound proxy specified by the user.
	 */
	public DefaultRouter(SipStack sipStack, String outboundProxy) {
		LOGGER.debug("Router instantiated for " + sipStack);

		this.sipStack = sipStack;
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
		LOGGER.debug("getNextHop(" + request + ")");
		
		
		if (outboundProxy != null) {
			LOGGER.debug("Outbound proxy has been defined, returning proxy hop.");
			LOGGER.debug("getNextHop(" + request + "): " + outboundProxy);
			return outboundProxy;
		}
		
		final SipURI destination = DestinationSelector.select(request);
		try {
			Locator locator = new Locator(getSupportedTransports());
			Queue<Hop> hops = locator.locate(destination);
			Hop top = null;
			if (hops.size() > 0) {
				top = hops.poll();
			}
			LOGGER.debug("getNextHop(" + request + "): " + top);
			return top;
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

	protected List<String> getSupportedTransports() {
		LOGGER.debug("Determining transports supported by stack");
		final List<String> supportedTransports = new ArrayList<String>();

		final Iterator<?> providers = sipStack.getSipProviders();
		while (providers.hasNext()) {
			final SipProvider provider = (SipProvider) providers.next();
			for (ListeningPoint endpoint : provider.getListeningPoints()) {
				final String transport = endpoint.getTransport().toUpperCase();
				LOGGER.debug("Found ListeningPoint " + endpoint.getIPAddress() + ":" + endpoint.getPort() + "/" + endpoint.getTransport());
				supportedTransports.add(transport);
			}
		}
		
		LOGGER.debug("Supported transports: " + supportedTransports);
		return supportedTransports;
	}
}
