package com.google.code.rfc3263;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.BasicConfigurator;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.rfc3263.dns.DefaultResolver;

public class HostParsingTest {
	private Locator fixture;
	
	@BeforeClass
	public static void configureLogging() {
		BasicConfigurator.configure();
	}
	
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
		assertTrue(fixture.isNumeric("192.168.0.1"));
	}
	
	@Test
	public void testIsNumericIPv6() {
		assertTrue(fixture.isNumeric("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]"));
	}
	
	@Test
	public void testIsNumericIPv6NonReference() {
		// This test distinguishes between an IPv6 address and IPv6 reference.
		assertFalse(fixture.isNumeric("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6NoLeadingZeroes() {
		assertTrue(fixture.isNumeric("[2001:db8:85a3:0:0:8a2e:370:7334]"));
	}
	
	@Test
	public void testIsNumericIPv6GroupedZeroes() {
		assertTrue(fixture.isNumeric("[2001:db8:85a3::8a2e:370:7334]"));
	}
	
	@Test
	public void testIsNumericIPv6Loopback() {
		assertTrue(fixture.isNumeric("[::1]"));
	}
	
	@Test
	public void testIsNumericIPv6Unspecified() {
		assertTrue(fixture.isNumeric("[::]"));
	}
	
	@Test
	public void testIsNumericIPv6IPv4Mapping() {
		assertTrue(fixture.isNumeric("[::ffff:192.0.2.128]"));
	}
	
	@Test
	public void testIsNumericHost() {
		assertFalse(fixture.isNumeric("example.org"));
	}
}
