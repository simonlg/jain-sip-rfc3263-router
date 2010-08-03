package com.google.code.rfc3263.dns;

import org.junit.experimental.theories.DataPoint;

import com.google.code.rfc3263.ObjectTest;


public class PointerRecordTest extends ObjectTest {
	@DataPoint
	public static PointerRecord tls = new PointerRecord("example.org.", 3, 1, "s", "SIPS+D2T", "", "_sips._tcp.example.org.");
	@DataPoint
	public static PointerRecord tcp = new PointerRecord("example.org.", 1, 2, "s", "SIP+D2T", "", "_sip._tcp.example.org.");
	@DataPoint
	public static PointerRecord udp = new PointerRecord("example.org.", 1, 3, "s", "SIP+D2U", "", "_sip._udp.example.org.");
}
