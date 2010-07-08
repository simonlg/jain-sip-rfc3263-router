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
		
		Resolver resolver = new DefaultResolver();		
		Locator locator = new Locator(resolver, getSupportedTransports());
		try {
			List<Hop> hops = locator.locate(sipUri);
			return new HopImpl("192.168.11.31", 5060, ListeningPoint.TCP);
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ListIterator<?> getNextHops(Request request) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Hop getOutboundProxy() {
		return null;
	}

	protected List<String> getSupportedTransports() {
		final List<String> supportedTransports = new ArrayList<String>();
		// TODO: Should these listening points be associated with a
		// SIP Provider?
		final Iterator<?> iter = sipStack.getListeningPoints();
		while (iter.hasNext()) {
			ListeningPoint endpoint = (ListeningPoint) iter.next();
			supportedTransports.add(endpoint.getTransport());
		}

		return supportedTransports;
	}
}
