package com.google.code.rfc3263;

import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.Properties;

import javax.sip.SipFactory;
import javax.sip.SipStack;
import javax.sip.address.Address;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
import javax.sip.address.Router;
import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.HeaderFactory;
import javax.sip.header.MaxForwardsHeader;
import javax.sip.header.RouteHeader;
import javax.sip.header.ToHeader;
import javax.sip.header.ViaHeader;
import javax.sip.message.MessageFactory;
import javax.sip.message.Request;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class DefaultRouterTest {
	private AddressFactory addressFactory;
	private HeaderFactory headerFactory;
	private MessageFactory messageFactory;
	private SipStack stack;

	@Before
	public void setUp() throws Exception {
		SipFactory factory = SipFactory.getInstance();
		addressFactory = factory.createAddressFactory();
		headerFactory = factory.createHeaderFactory();
		messageFactory = factory.createMessageFactory();
		
		final Properties properties = new Properties();
		properties.put("javax.sip.STACK_NAME", "Test");
		stack = factory.createSipStack(properties);
	}

	@Test
	public void testRequestUriShouldBeUsedWithoutProxy() throws Exception {
		Request request = getRequest();
		
		assertEquals(request.getRequestURI(), DefaultRouter.selectDestination(request));
	}
	
	@Test
	public void testLooseRouteHeaderShouldBeUsedWhenPresent() throws Exception {
		final Request request = getRequest();
		final RouteHeader route = getRoute(true);
		request.addHeader(route);
		
		assertEquals(route.getAddress().getURI(), DefaultRouter.selectDestination(request));
	}
	
	@Test
	public void testFixedRouteHeaderShouldNeverBeUsed() throws Exception {
		final Request request = getRequest();
		final RouteHeader route = getRoute(false);
		request.addHeader(route);
		
		assertEquals(request.getRequestURI(), DefaultRouter.selectDestination(request));
	}
	
	@Test
	public void testGivenTelRequestUriWhenSelectingDestinationThenErrorThrown() throws Exception {
		//given
		Request request = getRequest();
		request.setRequestURI(getTelUri());
		try {
			//when
			DefaultRouter.selectDestination(request);
			fail();
		} catch(IllegalArgumentException e) {
			//then
		}
	}
	
	@Test
	public void testGivenStrictRoutingRouteHeaderAndTelRequestUriWhenSelectingDestinationThenErrorThrown() throws Exception {
		//given
		Request request = getRequest();
		request.setRequestURI(getTelUri());
		final RouteHeader route = getRoute(false);
		request.addHeader(route);
		try {
			//when
			DefaultRouter.selectDestination(request);
			fail();
		} catch(IllegalArgumentException e) {
			//then
		}
	}
	
	@Test
	public void testGivenTelRouteHeaderWhenSelectingDestinationThenErrorThrown() throws Exception {
		//given
		Request request = getRequest();
		request.setRequestURI(getTelUri());
		URI routeUri = getTelUri();
		RouteHeader route = headerFactory.createRouteHeader(addressFactory.createAddress(routeUri));
		request.addHeader(route);
		try {
			//when
			DefaultRouter.selectDestination(request);
			fail();
		} catch(IllegalArgumentException e) {
			//then
		}
	}
	
	@Test
	public void testGivenLooseRoutingRouteHeaderAndTelRequestUriWhenSelectingDestinationThenDestinationIsRouteUri() throws Exception {
		//given
		Request request = getRequest();
		request.setRequestURI(getTelUri());
		final RouteHeader route = getRoute(true);
		request.addHeader(route);
		
		//when
		SipURI destination = DefaultRouter.selectDestination(request);
		//then
		assertEquals(route.getAddress().getURI(), destination);
	}
	
	@Test
	public void testProxyShouldBeUsedInAbsenseOfRoute() throws Exception {
		Hop expected = new HopImpl("192.168.0.3", 5060, "UDP");
		Hop actual = getRouter("192.168.0.3:5060/UDP").getNextHop(getRequest());
		
		Assert.assertEquals(expected, actual);
	}

	@Test
	public void testGetNextHopsShouldReturnEmptyIterator() throws Exception {
		@SuppressWarnings("deprecation")
		ListIterator<?> iter = getRouter(null).getNextHops(getRequest());
		
		Assert.assertFalse(iter.hasNext());
		Assert.assertFalse(iter.hasPrevious());
	}

	@Test
	public void testGetOutboundProxy() {
		Hop expected = new HopImpl("192.168.0.3", 5060, "UDP");
		Hop actual = getRouter("192.168.0.3:5060/UDP").getOutboundProxy();
		
		Assert.assertEquals(expected, actual);
	}
	
	@Test
	public void testOutboundProxyShouldBeNullAsDefault() {
		Hop expected = null;
		Hop actual = getRouter(null).getOutboundProxy();
		
		Assert.assertEquals(expected, actual);
	}
	
	@Test
	public void testMcastShouldBeUsedWhenPresent() throws Exception {
		final Request request = getRequest();
		SipURI requestUri = (SipURI) request.getRequestURI();

		Hop expected;
		try {
			InetAddress.getByName("sip.mcast.net");
			requestUri.setMAddrParam("sip.mcast.net");
			expected = new HopImpl("224.0.1.75", 5060 , "UDP");
		} catch (UnknownHostException e) {
			// This path is used when the DNS of the server running the test doesn't know sip.mcast.net
			requestUri.setMAddrParam("localhost");
			expected = new HopImpl("127.0.0.1", 5060 , "UDP");
		}
		Hop actual = getRouter(null).getNextHop(request);
		
		assertEquals(expected, actual);
	}
	
	private Router getRouter(String outboundProxy) {
		return new DefaultRouter(stack, outboundProxy);
	}
	
	private RouteHeader getRoute(boolean loose) throws Exception {
		final SipURI routeUri = addressFactory.createSipURI(null, "192.168.0.2");
		if (loose) {
			routeUri.setLrParam();
		}
		final Address routeAddr = addressFactory.createAddress(routeUri);
		return headerFactory.createRouteHeader(routeAddr);
	}
	
	private URI getTelUri() throws ParseException {
		return addressFactory.createTelURL("4181234567");
	}
	
	private Request getRequest() throws Exception {
		final SipURI requestUri = addressFactory.createSipURI(null, "192.168.0.1");
		final String method = "INVITE";
		final CallIdHeader callId = headerFactory.createCallIdHeader("deadbeef");
		final CSeqHeader cSeq = headerFactory.createCSeqHeader(1L, method);
		final SipURI fromUri = addressFactory.createSipURI("alice", "example.org");
		final Address fromAddress = addressFactory.createAddress(fromUri);
		final FromHeader from = headerFactory.createFromHeader(fromAddress, null);
		final SipURI toUri = addressFactory.createSipURI("bob", "example.org");
		final Address toAddress = addressFactory.createAddress(toUri);
		final ToHeader to = headerFactory.createToHeader(toAddress, null);
		final List<ViaHeader> vias = new ArrayList<ViaHeader>();
		final MaxForwardsHeader maxForwards = headerFactory.createMaxForwardsHeader(70);
		
		return messageFactory.createRequest(requestUri, method, callId, cSeq, from, to, vias, maxForwards);
	}

}
