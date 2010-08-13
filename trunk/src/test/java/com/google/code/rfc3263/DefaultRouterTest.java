package com.google.code.rfc3263;

import static org.easymock.EasyMock.expect;
import static org.easymock.classextension.EasyMock.createMock;
import static org.easymock.classextension.EasyMock.replay;
import static org.easymock.classextension.EasyMock.verify;

import java.util.ArrayList;
import java.util.LinkedList;
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

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class DefaultRouterTest {
	private AddressFactory addressFactory;
	private HeaderFactory headerFactory;
	private MessageFactory messageFactory;
	private SipStack stack;
	private Locator locator;
	
	@Before
	public void setUp() throws Exception {
		locator = createMock(Locator.class);
		
		SipFactory factory = SipFactory.getInstance();
		addressFactory = factory.createAddressFactory();
		headerFactory = factory.createHeaderFactory();
		messageFactory = factory.createMessageFactory();
		
		final Properties properties = new Properties();
		properties.put("javax.sip.STACK_NAME", "Test");
		stack = factory.createSipStack(properties);
	}
	
	@After
	public void tearDown() {
		verify(locator);
	}

	@Test
	public void testRequestUriShouldBeUsedWithoutProxy() throws Exception {
		Request request = getRequest();
		expect(locator.locate((SipURI) request.getRequestURI())).andReturn(new LinkedList<Hop>());
		replay(locator);
		
		getRouter(null).getNextHop(request);
	}
	
	@Test
	public void testLooseRouteHeaderShouldBeUsedWhenPresent() throws Exception {
		final Request request = getRequest();
		final RouteHeader route = getRoute(true);
		request.addHeader(route);
		
		expect(locator.locate((SipURI) route.getAddress().getURI())).andReturn(new LinkedList<Hop>());
		replay(locator);
		
		getRouter(null).getNextHop(request);
	}
	
	@Test
	public void testFixedRouteHeaderShouldNeverBeUsed() throws Exception {
		final Request request = getRequest();
		final RouteHeader route = getRoute(false);
		request.addHeader(route);
		
		expect(locator.locate((SipURI) request.getRequestURI())).andReturn(new LinkedList<Hop>());
		replay(locator);
		
		getRouter(null).getNextHop(request);
	}
	
	@Test
	public void testProxyShouldBeUsedInAbsenseOfRoute() throws Exception {
		replay(locator);
		
		Hop expected = new HopImpl("192.168.0.3", 5060, "UDP");
		Hop actual = getRouter("192.168.0.3:5060/UDP").getNextHop(getRequest());
		
		Assert.assertEquals(expected, actual);
	}

	@Test
	public void testGetNextHopsShouldReturnEmptyIterator() throws Exception {
		replay(locator);
		
		@SuppressWarnings("deprecation")
		ListIterator<?> iter = getRouter(null).getNextHops(getRequest());
		
		Assert.assertFalse(iter.hasNext());
		Assert.assertFalse(iter.hasPrevious());
	}

	@Test
	public void testGetOutboundProxy() {
		replay(locator);
		
		Hop expected = new HopImpl("192.168.0.3", 5060, "UDP");
		Hop actual = getRouter("192.168.0.3:5060/UDP").getOutboundProxy();
		
		Assert.assertEquals(expected, actual);
	}
	
	@Test
	public void testOutboundProxyShouldBeNullAsDefault() {
		replay(locator);
		
		Hop expected = null;
		Hop actual = getRouter(null).getOutboundProxy();
		
		Assert.assertEquals(expected, actual);
	}
	
	private Router getRouter(String outboundProxy) {
		return new DefaultRouter(stack, outboundProxy, locator);
	}
	
	private RouteHeader getRoute(boolean loose) throws Exception {
		final SipURI routeUri = addressFactory.createSipURI(null, "192.168.0.2");
		if (loose) {
			routeUri.setLrParam();
		}
		final Address routeAddr = addressFactory.createAddress(routeUri);
		return headerFactory.createRouteHeader(routeAddr);
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
