package com.google.code.rfc3263;

import static org.junit.Assert.assertEquals;

import java.text.ParseException;

import javax.sip.address.Hop;

import org.junit.Test;

public class HopParserTest {

	@Test
	public void testParseHop() throws ParseException {
		Hop expectedHop = new HopImpl("127.0.0.1", 5060, "TCP");
		Hop actualHop = HopImpl.getInstance("127.0.0.1:5060/TCP");
		
		assertEquals(expectedHop, actualHop);
	}
	
	@Test(expected = ParseException.class)
	public void testNullHopShouldThrowException() throws ParseException {
		HopImpl.getInstance(null);
	}
	
	@Test(expected = ParseException.class)
	public void testMissingPortShouldThrowException() throws ParseException {
		HopImpl.getInstance("127.0.0.1/TCP");
	}
	
	@Test(expected = ParseException.class)
	public void testInvalidPortShouldThrowExceptionTooSmall() throws ParseException {
		HopImpl.getInstance("127.0.0.1:-1/TCP");
	}
	
	@Test(expected = ParseException.class)
	public void testInvalidPortShouldThrowExceptionTooLarge() throws ParseException {
		HopImpl.getInstance("127.0.0.1:100000/TCP");
	}
	
	@Test(expected = ParseException.class)
	public void testMissingTransportShouldThrowException() throws ParseException {
		HopImpl.getInstance("127.0.0.1:5060");
	}
	
	@Test(expected = ParseException.class)
	public void testUnknownTransportShouldThrowException() throws ParseException {
		HopImpl.getInstance("127.0.0.1:5060/FOO");
	}
	
	@Test(expected = ParseException.class)
	public void testMissingAddressShouldThrowException() throws ParseException {
		HopImpl.getInstance(":5060/TCP");
	}
	
	@Test
	public void testHostnameHost() throws ParseException {
		Hop hop = HopImpl.getInstance("example.org:5060/TCP");
		assertEquals("example.org", hop.getHost());
	}
	
	@Test
	public void testHostnamePort() throws ParseException {
		Hop hop = HopImpl.getInstance("example.org:5060/TCP");
		assertEquals(5060, hop.getPort());
	}
	
	@Test
	public void testHostnameTransport() throws ParseException {
		Hop hop = HopImpl.getInstance("example.org:5060/TCP");
		assertEquals("TCP", hop.getTransport());
	}
	
	@Test
	public void testIPv6ReferenceHost() throws ParseException {
		Hop hop = HopImpl.getInstance("[::1]:5060/TCP");
		assertEquals("::1", hop.getHost());
	}
	
	@Test
	public void testIPv6ReferencePort() throws ParseException {
		Hop hop = HopImpl.getInstance("[::1]:5060/TCP");
		assertEquals(5060, hop.getPort());
	}
	
	@Test
	public void testIPv6ReferenceTransport() throws ParseException {
		Hop hop = HopImpl.getInstance("[::1]:5060/TCP");
		assertEquals("TCP", hop.getTransport());
	}
	
	@Test(expected=ParseException.class)
	public void testIPv6Host() throws ParseException {
		Hop hop = HopImpl.getInstance("::1:5060/TCP");
		assertEquals("::1", hop.getHost());
	}
	
	@Test(expected=ParseException.class)
	public void testIPv6Port() throws ParseException {
		Hop hop = HopImpl.getInstance("::1:5060/TCP");
		assertEquals(5060, hop.getPort());
	}
	
	@Test(expected=ParseException.class)
	public void testIPv6Transport() throws ParseException {
		Hop hop = HopImpl.getInstance("::1:5060/TCP");
		assertEquals("TCP", hop.getTransport());
	}
}
