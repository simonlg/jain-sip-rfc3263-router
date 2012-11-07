package com.google.code.rfc3263;

import javax.sip.address.Hop;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.theories.DataPoint;


public class HopImplTest extends ObjectTest {
	@DataPoint 
	public static Hop a = new HopImpl("example.org", 5060, "TCP");
	@DataPoint 
	public static Hop b = new HopImpl("example.net", 5060, "TCP");
	@DataPoint 
	public static Hop c = new HopImpl("example.net", 5061, "TCP");
	@DataPoint 
	public static Hop d = new HopImpl("example.net", 5061, "TLS");
	@DataPoint 
	public static Hop nullHop = null;
	
	@Test
	public void testConstructorUpperCasesTransport() {
		HopImpl hop = new HopImpl("example.org", 5060, "tcP");
		Assert.assertEquals("TCP",hop.getTransport());
	}
	@Test
	
	public void testConstructorCanHaveANullTransport() {
		HopImpl hop = new HopImpl("example.org", 5060, null);
		Assert.assertNull(hop.getTransport());
	}
}
