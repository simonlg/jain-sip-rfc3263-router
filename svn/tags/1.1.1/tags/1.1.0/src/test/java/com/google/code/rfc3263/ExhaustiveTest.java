package com.google.code.rfc3263;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Queue;

import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.junit.Test;
import org.junit.runner.RunWith;

import com.google.code.rfc3263.LabelledParameterized.Parameters;

/**
 * example.org resolves to 192.168.0.3
 * example.net resolves to 192.168.0.4
 */
@RunWith(LabelledParameterized.class)
public abstract class ExhaustiveTest {
	private static AddressFactory addressFactory;
	private String uriString;
	
	@Parameters
	public static Collection<Object[]> getParameters() throws Exception {
		SipFactory factory = SipFactory.getInstance();
		addressFactory = factory.createAddressFactory();
		
		Collection<Object[]> params = new ArrayList<Object[]>();
		
		for (String host : Arrays.asList("example.org", "192.168.0.1", "[fe80:0:0:0:0:0:c0a8:1]")) {
			for (int port : Arrays.asList(-1, 1234)) {
				for (boolean secure : Arrays.asList(true, false)) {
					for (String transport : Arrays.asList("udp", "tcp", "sctp", "tls", null)) {
						for (String maddr : Arrays.asList("example.net", "192.168.0.2", "[fe80:0:0:0:0:0:c0a8:2]", null)) {
							SipURI uri = addressFactory.createSipURI(null, host);
							if (transport != null) {
								uri.setTransportParam(transport);
							} else {
								uri.removeParameter("transport");
							}
							uri.setSecure(secure);
							uri.setPort(port);
							if (maddr != null) {
								uri.setMAddrParam(maddr);
							} else {
								uri.removeParameter("maddr");
							}
							params.add(new Object[] { uri.toString() });
						}
					}
				}
			}
		}
		
		return params;
	}
	
	public ExhaustiveTest(String uriString) {
		this.uriString = uriString;
	}
	
	public abstract Locator getLocator();
	public abstract String getHop(String uri) throws Exception;
	
	@Test
	public void testHops() throws Exception {
		final String hopString = getHop(uriString);
		final Hop expectedHop;
		if (hopString == null) {
			expectedHop = null;
		} else {
			expectedHop = HopImpl.getInstance(hopString);
		}
		
		final SipURI uri = (SipURI) addressFactory.createURI(uriString);
		final Queue<Hop> actualHops = getLocator().locate(uri);
		final Hop actualHop = actualHops.peek();
		
		assertEquals(expectedHop, actualHop);
	}
}
