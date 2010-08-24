package com.google.code.rfc3263;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Queue;
import java.util.Set;

import javax.sip.SipFactory;
import javax.sip.address.AddressFactory;
import javax.sip.address.Hop;
import javax.sip.address.SipURI;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.google.code.rfc3263.LabelledParameterized.Parameters;
import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

/**
 * example.org resolves to 192.168.0.3
 * example.net resolves to 192.168.0.4
 */
@RunWith(LabelledParameterized.class)
public class AllTests {
	@Parameters
	public static Collection<Object[]> getParameters() throws Exception {
		SipFactory factory = SipFactory.getInstance();
		AddressFactory addressFactory = factory.createAddressFactory();
		
		Collection<Object[]> params = new ArrayList<Object[]>();
		Object[] paramPoint;
		
		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tcp;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5061, "TLS");;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tcp");
		paramPoint[1] = new HopImpl("192.168.0.3", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=sctp;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5061, "TLS-SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5061, "TLS-SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5061, "TLS-SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=sctp");
		paramPoint[1] = new HopImpl("192.168.0.3", 5061, "TLS-SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tls;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;transport=tls");
		paramPoint[1] = new HopImpl("192.168.0.3", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org");
		paramPoint[1] = new HopImpl("192.168.0.3", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=udp;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=udp");
		paramPoint[1] = new HopImpl("192.168.0.3", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tcp;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5060, "TCP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5060, "TCP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5060, "TCP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tcp");
		paramPoint[1] = new HopImpl("192.168.0.3", 5060, "TCP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=sctp;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5060, "SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5060, "SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5060, "SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=sctp");
		paramPoint[1] = new HopImpl("192.168.0.3", 5060, "SCTP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tls;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;transport=tls");
		paramPoint[1] = new HopImpl("192.168.0.3", 5061, "TLS");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;maddr=example.net");
		paramPoint[1] = new HopImpl("192.168.0.4", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;maddr=192.168.0.2");
		paramPoint[1] = new HopImpl("192.168.0.2", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = new HopImpl("fe80:0:0:0:0:0:c0a8:2", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org");
		paramPoint[1] = new HopImpl("192.168.0.3", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:example.org:1234");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:example.org:1234");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1");
		paramPoint[1] = new HopImpl("192.168.0.1", 5060, "UDP");
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:192.168.0.1:1234");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:192.168.0.1:1234");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sips:[fe80:0:0:0:0:0:c0a8:1]:1234");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=example.net");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=192.168.0.2");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]");
		paramPoint[1] = null;
		params.add(paramPoint);

		paramPoint = new Object[2];
		paramPoint[0] = (SipURI) addressFactory.createURI("sip:[fe80:0:0:0:0:0:c0a8:1]:1234");
		paramPoint[1] = null;
		params.add(paramPoint);
		
		return params;
	}
	
	private SipURI uri;
	private Hop expectedHop;
	private Locator locator;
	
	public AllTests(SipURI uri, Hop expectedHop) {
		this.uri = uri;
		this.expectedHop = expectedHop;
	}
	
	@Before
	public void setUp() throws Exception {
		final Resolver resolver = EasyMock.createMock(Resolver.class);
		
		final Set<AddressRecord> orgAddresses = new HashSet<AddressRecord>();
		orgAddresses.add(new AddressRecord("example.org.", InetAddress.getByName("192.168.0.3")));
		final Set<AddressRecord> netAddresses = new HashSet<AddressRecord>();
		netAddresses.add(new AddressRecord("example.net.", InetAddress.getByName("192.168.0.4")));
		
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(orgAddresses).anyTimes();
		expect(resolver.lookupAddressRecords("example.net.")).andReturn(netAddresses).anyTimes();
		
		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._tcp.example.org.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._sctp.example.org.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._tcp.example.org.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._sctp.example.org.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		
		expect(resolver.lookupServiceRecords("_sip._udp.example.net.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._tcp.example.net.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._sctp.example.net.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._tcp.example.net.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._sctp.example.net.")).andReturn(Collections.<ServiceRecord>emptyList()).anyTimes();
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(Collections.<PointerRecord>emptyList()).anyTimes();
		expect(resolver.lookupPointerRecords("example.net.")).andReturn(Collections.<PointerRecord>emptyList()).anyTimes();
		
		replay(resolver);
		locator = new Locator(resolver, Arrays.asList("udp", "tcp", "tls", "sctp", "tls-sctp"));
	}
	
	@Test
	public void testHops() {
		final Queue<Hop> actualHops = locator.locate(uri);
		assertEquals(expectedHop, actualHops.peek());
	}
}
