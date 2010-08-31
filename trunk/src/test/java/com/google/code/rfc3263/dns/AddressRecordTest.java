package com.google.code.rfc3263.dns;

import java.net.InetAddress;

import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoint;

import com.google.code.rfc3263.ObjectTest;

public class AddressRecordTest extends ObjectTest {
	@DataPoint
	public static AddressRecord a;
	@DataPoint
	public static AddressRecord b;
	@DataPoint
	public static AddressRecord c;
	
	@BeforeClass
	public static void setUpPoints() throws Exception {
		a = new AddressRecord("example.org.", InetAddress.getByName("192.168.0.1"));
		b = new AddressRecord("example.org.", InetAddress.getByName("192.168.0.2"));
		c = new AddressRecord("example.org.", InetAddress.getByName("192.168.0.3"));
	}
}
