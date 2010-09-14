package com.google.code.rfc3263;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.easymock.EasyMock;
import org.junit.Before;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.SRVRecord;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.Resolver;

public class ExhaustiveNoEnvironmentTest extends ExhaustiveTest {
	private static Map<String, String> transportMap;
	private Locator locator;
	
	static {
		transportMap = new HashMap<String, String>();
		
		transportMap.put("sips:example.org;transport=udp;maddr=192.168.0.2", null);
		transportMap.put("sips:example.org;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", null);
		transportMap.put("sips:example.org;transport=tcp;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:example.org;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:example.org;transport=sctp;maddr=192.168.0.2", "192.168.0.2:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS-SCTP");
		transportMap.put("sips:example.org;transport=tls;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:example.org;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:example.org;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:example.org;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sip:example.org;transport=udp;maddr=192.168.0.2", "192.168.0.2:5060/UDP");
		transportMap.put("sip:example.org;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/UDP");
		transportMap.put("sip:example.org;transport=tcp;maddr=192.168.0.2", "192.168.0.2:5060/TCP");
		transportMap.put("sip:example.org;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/TCP");
		transportMap.put("sip:example.org;transport=sctp;maddr=192.168.0.2", "192.168.0.2:5060/SCTP");
		transportMap.put("sip:example.org;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/SCTP");
		transportMap.put("sip:example.org;transport=tls;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sip:example.org;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sip:example.org;maddr=192.168.0.2", "192.168.0.2:5060/UDP");
		transportMap.put("sip:example.org;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/UDP");
		transportMap.put("sips:example.org:1234;transport=udp;maddr=192.168.0.2", null);
		transportMap.put("sips:example.org:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", null);
		transportMap.put("sips:example.org:1234;transport=tcp;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:example.org:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:example.org:1234;transport=sctp;maddr=192.168.0.2", "192.168.0.2:1234/TLS-SCTP");
		transportMap.put("sips:example.org:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS-SCTP");
		transportMap.put("sips:example.org:1234;transport=tls;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:example.org:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:example.org:1234;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:example.org:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sip:example.org:1234;transport=udp;maddr=192.168.0.2", "192.168.0.2:1234/UDP");
		transportMap.put("sip:example.org:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/UDP");
		transportMap.put("sip:example.org:1234;transport=tcp;maddr=192.168.0.2", "192.168.0.2:1234/TCP");
		transportMap.put("sip:example.org:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TCP");
		transportMap.put("sip:example.org:1234;transport=sctp;maddr=192.168.0.2", "192.168.0.2:1234/SCTP");
		transportMap.put("sip:example.org:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/SCTP");
		transportMap.put("sip:example.org:1234;transport=tls;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sip:example.org:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sip:example.org:1234;maddr=192.168.0.2", "192.168.0.2:1234/UDP");
		transportMap.put("sip:example.org:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/UDP");
		transportMap.put("sips:192.168.0.1;transport=udp;maddr=192.168.0.2", null);
		transportMap.put("sips:192.168.0.1;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", null);
		transportMap.put("sips:192.168.0.1;transport=tcp;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=tcp", "192.168.0.1:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=sctp;maddr=192.168.0.2", "192.168.0.2:5061/TLS-SCTP");
		transportMap.put("sips:192.168.0.1;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS-SCTP");
		transportMap.put("sips:192.168.0.1;transport=sctp", "192.168.0.1:5061/TLS-SCTP");
		transportMap.put("sips:192.168.0.1;transport=tls;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:192.168.0.1;transport=tls", "192.168.0.1:5061/TLS");
		transportMap.put("sips:192.168.0.1;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:192.168.0.1;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:192.168.0.1", "192.168.0.1:5061/TLS");
		transportMap.put("sip:192.168.0.1;transport=udp;maddr=192.168.0.2", "192.168.0.2:5060/UDP");
		transportMap.put("sip:192.168.0.1;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/UDP");
		transportMap.put("sip:192.168.0.1;transport=udp", "192.168.0.1:5060/UDP");
		transportMap.put("sip:192.168.0.1;transport=tcp;maddr=192.168.0.2", "192.168.0.2:5060/TCP");
		transportMap.put("sip:192.168.0.1;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/TCP");
		transportMap.put("sip:192.168.0.1;transport=tcp", "192.168.0.1:5060/TCP");
		transportMap.put("sip:192.168.0.1;transport=sctp;maddr=192.168.0.2", "192.168.0.2:5060/SCTP");
		transportMap.put("sip:192.168.0.1;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/SCTP");
		transportMap.put("sip:192.168.0.1;transport=sctp", "192.168.0.1:5060/SCTP");
		transportMap.put("sip:192.168.0.1;transport=tls;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sip:192.168.0.1;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sip:192.168.0.1;transport=tls", "192.168.0.1:5061/TLS");
		transportMap.put("sip:192.168.0.1;maddr=192.168.0.2", "192.168.0.2:5060/UDP");
		transportMap.put("sip:192.168.0.1;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/UDP");
		transportMap.put("sip:192.168.0.1", "192.168.0.1:5060/UDP");
		transportMap.put("sips:192.168.0.1:1234;transport=udp;maddr=192.168.0.2", null);
		transportMap.put("sips:192.168.0.1:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", null);
		transportMap.put("sips:192.168.0.1:1234;transport=udp", null);
		transportMap.put("sips:192.168.0.1:1234;transport=tcp;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;transport=tcp", "192.168.0.1:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;transport=sctp;maddr=192.168.0.2", "192.168.0.2:1234/TLS-SCTP");
		transportMap.put("sips:192.168.0.1:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS-SCTP");
		transportMap.put("sips:192.168.0.1:1234;transport=sctp", "192.168.0.1:1234/TLS-SCTP");
		transportMap.put("sips:192.168.0.1:1234;transport=tls;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;transport=tls", "192.168.0.1:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:192.168.0.1:1234", "192.168.0.1:1234/TLS");
		transportMap.put("sip:192.168.0.1:1234;transport=udp;maddr=192.168.0.2", "192.168.0.2:1234/UDP");
		transportMap.put("sip:192.168.0.1:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/UDP");
		transportMap.put("sip:192.168.0.1:1234;transport=udp", "192.168.0.1:1234/UDP");
		transportMap.put("sip:192.168.0.1:1234;transport=tcp;maddr=192.168.0.2", "192.168.0.2:1234/TCP");
		transportMap.put("sip:192.168.0.1:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TCP");
		transportMap.put("sip:192.168.0.1:1234;transport=tcp", "192.168.0.1:1234/TCP");
		transportMap.put("sip:192.168.0.1:1234;transport=sctp;maddr=192.168.0.2", "192.168.0.2:1234/SCTP");
		transportMap.put("sip:192.168.0.1:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/SCTP");
		transportMap.put("sip:192.168.0.1:1234;transport=sctp", "192.168.0.1:1234/SCTP");
		transportMap.put("sip:192.168.0.1:1234;transport=tls;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sip:192.168.0.1:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sip:192.168.0.1:1234;transport=tls", "192.168.0.1:1234/TLS");
		transportMap.put("sip:192.168.0.1:1234;maddr=192.168.0.2", "192.168.0.2:1234/UDP");
		transportMap.put("sip:192.168.0.1:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/UDP");
		transportMap.put("sip:192.168.0.1:1234", "192.168.0.1:1234/UDP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=192.168.0.2", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=udp", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tcp", "[fe80:0:0:0:0:0:c0a8:1]:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=192.168.0.2", "192.168.0.2:5061/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=sctp", "[fe80:0:0:0:0:0:c0a8:1]:5061/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];transport=tls", "[fe80:0:0:0:0:0:c0a8:1]:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1];maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]", "[fe80:0:0:0:0:0:c0a8:1]:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=192.168.0.2", "192.168.0.2:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=udp", "[fe80:0:0:0:0:0:c0a8:1]:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=192.168.0.2", "192.168.0.2:5060/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tcp", "[fe80:0:0:0:0:0:c0a8:1]:5060/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=192.168.0.2", "192.168.0.2:5060/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=sctp", "[fe80:0:0:0:0:0:c0a8:1]:5060/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=192.168.0.2", "192.168.0.2:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];transport=tls", "[fe80:0:0:0:0:0:c0a8:1]:5061/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=192.168.0.2", "192.168.0.2:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1];maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:5060/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]", "[fe80:0:0:0:0:0:c0a8:1]:5060/UDP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=192.168.0.2", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp", null);
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp", "[fe80:0:0:0:0:0:c0a8:1]:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=192.168.0.2", "192.168.0.2:1234/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp", "[fe80:0:0:0:0:0:c0a8:1]:1234/TLS-SCTP");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls", "[fe80:0:0:0:0:0:c0a8:1]:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sips:[fe80:0:0:0:0:0:c0a8:1]:1234", "[fe80:0:0:0:0:0:c0a8:1]:1234/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=192.168.0.2", "192.168.0.2:1234/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=udp", "[fe80:0:0:0:0:0:c0a8:1]:1234/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=192.168.0.2", "192.168.0.2:1234/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tcp", "[fe80:0:0:0:0:0:c0a8:1]:1234/TCP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=192.168.0.2", "192.168.0.2:1234/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=sctp", "[fe80:0:0:0:0:0:c0a8:1]:1234/SCTP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=192.168.0.2", "192.168.0.2:1234/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;transport=tls", "[fe80:0:0:0:0:0:c0a8:1]:1234/TLS");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=192.168.0.2", "192.168.0.2:1234/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234;maddr=[fe80:0:0:0:0:0:c0a8:2]", "[fe80:0:0:0:0:0:c0a8:2]:1234/UDP");
		transportMap.put("sip:[fe80:0:0:0:0:0:c0a8:1]:1234", "[fe80:0:0:0:0:0:c0a8:1]:1234/UDP");
	}
	
	@Before
	public void setUp() throws Exception {
		
		final Resolver resolver = EasyMock.createMock(Resolver.class);
		
		expect(resolver.lookupAddressRecords("example.org.")).andReturn(Collections.<AddressRecord>emptySet()).anyTimes();
		expect(resolver.lookupAddressRecords("example.net.")).andReturn(Collections.<AddressRecord>emptySet()).anyTimes();

		expect(resolver.lookupServiceRecords("_sip._udp.example.org.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._tcp.example.org.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._sctp.example.org.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._tcp.example.org.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._sctp.example.org.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._udp.example.net.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._tcp.example.net.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sip._sctp.example.net.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._tcp.example.net.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		expect(resolver.lookupServiceRecords("_sips._sctp.example.net.")).andReturn(Collections.<SRVRecord>emptyList()).anyTimes();
		
		expect(resolver.lookupPointerRecords("example.org.")).andReturn(Collections.<NAPTRRecord>emptyList()).anyTimes();
		expect(resolver.lookupPointerRecords("example.net.")).andReturn(Collections.<NAPTRRecord>emptyList()).anyTimes();
		
		replay(resolver);
		locator = new Locator(resolver, Arrays.asList("udp", "tcp", "tls", "sctp", "tls-sctp"));
	}
	
	public ExhaustiveNoEnvironmentTest(String uriString) {
		super(uriString);
	}

	public String getHop(String uri) throws Exception {
		if (transportMap.containsKey(uri)) {
			return transportMap.get(uri);
		} else {
			return null;
		}
	}

	@Override
	public Locator getLocator() {
		return locator;
	}
}
