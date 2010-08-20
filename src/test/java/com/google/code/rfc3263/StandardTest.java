package com.google.code.rfc3263;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;

import javax.sip.ListeningPoint;
import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.google.code.rfc3263.LabelledParameterized.Parameters;

@RunWith(LabelledParameterized.class)
public class StandardTest {
	@Parameters
	public static List<Object[]> getParameters() throws Exception {
		final SipFactory sipFactory = SipFactory.getInstance();
		final AddressFactory addressFactory = sipFactory.createAddressFactory();
		
		// For each Object[]:
		// 0 -> SIP URI
		// 1 -> Expected Hop
		final List<Object[]> parameters = new ArrayList<Object[]>();

		// Scheme: SIP
		// Host: IPv4
		// Port: Absent
		// Transport: Absent
		SipURI uri = addressFactory.createSipURI(null, "127.0.0.1");
		Hop hop = new HopImpl("127.0.0.1", ListeningPoint.PORT_5060, ListeningPoint.UDP);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv4
		// Port: Present
		// Transport: Absent
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setPort(1234);
		hop = new HopImpl("127.0.0.1", 1234, ListeningPoint.UDP);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv4
		// Port: Present
		// Transport: Present (UDP)
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setPort(1234);
		uri.setTransportParam("UDP");
		hop = new HopImpl("127.0.0.1", 1234, "UDP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv4
		// Port: Present
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setPort(1234);
		uri.setTransportParam("TCP");
		hop = new HopImpl("127.0.0.1", 1234, "TCP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv4
		// Port: Absent
		// Transport: Present (UDP)
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setTransportParam("UDP");
		hop = new HopImpl("127.0.0.1", ListeningPoint.PORT_5060, "UDP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv4
		// Port: Absent
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setTransportParam("TCP");
		hop = new HopImpl("127.0.0.1", ListeningPoint.PORT_5060, "TCP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv6
		// Port: Absent
		// Transport: Absent
		uri = addressFactory.createSipURI(null, "[::1]");
		hop = new HopImpl("::1", ListeningPoint.PORT_5060, ListeningPoint.UDP);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv6
		// Port: Present
		// Transport: Absent
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setPort(1234);
		hop = new HopImpl("::1", 1234, ListeningPoint.UDP);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv6
		// Port: Present
		// Transport: Present (UDP)
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setPort(1234);
		uri.setTransportParam("UDP");
		hop = new HopImpl("::1", 1234, "UDP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv6
		// Port: Present
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setPort(1234);
		uri.setTransportParam("TCP");
		hop = new HopImpl("::1", 1234, "TCP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv6
		// Port: Absent
		// Transport: Present (UDP)
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setTransportParam("UDP");
		hop = new HopImpl("::1", ListeningPoint.PORT_5060, "UDP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIP
		// Host: IPv6
		// Port: Absent
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setTransportParam("TCP");
		hop = new HopImpl("::1", ListeningPoint.PORT_5060, "TCP");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv4
		// Port: Absent
		// Transport: Absent
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setSecure(true);
		hop = new HopImpl("127.0.0.1", ListeningPoint.PORT_5061, ListeningPoint.TLS);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv4
		// Port: Present
		// Transport: Absent
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setPort(1234);
		uri.setSecure(true);
		hop = new HopImpl("127.0.0.1", 1234, ListeningPoint.TLS);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv4
		// Port: Present
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setPort(1234);
		uri.setSecure(true);
		uri.setTransportParam("TCP");
		hop = new HopImpl("127.0.0.1", 1234, "TLS");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv4
		// Port: Absent
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "127.0.0.1");
		uri.setSecure(true);
		uri.setTransportParam("TCP");
		hop = new HopImpl("127.0.0.1", ListeningPoint.PORT_5061, "TLS");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv6
		// Port: Absent
		// Transport: Absent
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setSecure(true);
		hop = new HopImpl("::1", ListeningPoint.PORT_5061, ListeningPoint.TLS);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv6
		// Port: Present
		// Transport: Absent
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setPort(1234);
		uri.setSecure(true);
		hop = new HopImpl("::1", 1234, ListeningPoint.TLS);
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv6
		// Port: Present
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setPort(1234);
		uri.setSecure(true);
		uri.setTransportParam("TCP");
		hop = new HopImpl("::1", 1234, "TLS");
		parameters.add(new Object[] {uri, hop});
		
		// Scheme: SIPS
		// Host: IPv6
		// Port: Absent
		// Transport: Present (TCP)
		uri = addressFactory.createSipURI(null, "[::1]");
		uri.setSecure(true);
		uri.setTransportParam("TCP");
		hop = new HopImpl("::1", ListeningPoint.PORT_5061, "TLS");
		parameters.add(new Object[] {uri, hop});
		
		return parameters;
	}
	
	private final SipURI uri;
	private final Hop hop;
	private Locator locator;
	
	public StandardTest(SipURI uri, Hop hop) {
		this.uri = uri;
		this.hop = hop;
	}
	
	@Before
	public void setUp() {
		final List<String> transports = Arrays.asList("TLS", "UDP", "TCP");
		locator = new Locator(transports);
	}
	
	@Test
	public void testHop() {
		final Queue<Hop> hops = locator.locate(uri);
		
		assertEquals(hop, hops.peek());
	}
}
