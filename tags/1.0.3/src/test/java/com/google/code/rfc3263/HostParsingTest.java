package com.google.code.rfc3263;

import java.util.ArrayList;
import java.util.List;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import com.google.code.rfc3263.dns.DefaultResolver;

public class HostParsingTest {
	private Locator fixture;
	
	@Before
	public void setUp() {
		final List<String> transports = new ArrayList<String>();
		transports.add("UDP");
		transports.add("TLS");
		transports.add("TCP");
		
		fixture = new Locator(new DefaultResolver(), transports);
	}
	
	@Test
	public void testIsNumericIPv4() {
		Assert.assertTrue(fixture.isNumeric("192.168.0.1"));
	}
	
	@Test
	public void testIsNumericIPv6() {
		Assert.assertTrue(fixture.isNumeric("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6NoLeadingZeroes() {
		Assert.assertTrue(fixture.isNumeric("2001:db8:85a3:0:0:8a2e:370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6GroupedZeroes() {
		Assert.assertTrue(fixture.isNumeric("2001:db8:85a3::8a2e:370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6Loopback() {
		Assert.assertTrue(fixture.isNumeric("::1"));
	}
	
	@Test
	public void testIsNumericIPv6Unspecified() {
		Assert.assertTrue(fixture.isNumeric("::"));
	}
	
	@Test
	public void testIsNumericIPv6IPv4Mapping() {
		Assert.assertTrue(fixture.isNumeric("::ffff:192.0.2.128"));
	}
	
	@Test
	public void testIsNumericHost() {
		Assert.assertFalse(fixture.isNumeric("example.org"));
	}
}
