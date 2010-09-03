package com.google.code.rfc3263;

import java.text.ParseException;

import javax.sip.address.Hop;

import junit.framework.Assert;

import org.junit.Test;

public class HopParserTest {

	@Test
	public void testParseHop() throws ParseException {
		Hop expectedHop = new HopImpl("127.0.0.1", 5060, "TCP");
		Hop actualHop = HopImpl.getInstance("127.0.0.1:5060/TCP");
		
		Assert.assertEquals(expectedHop, actualHop);
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
	
	@Test(expected = ParseException.class)
	public void testHostAddressShouldThrowException() throws ParseException {
		HopImpl.getInstance("example.org:5060/TCP");
	}
}
