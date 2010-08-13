package com.google.code.rfc3263;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import org.apache.log4j.BasicConfigurator;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.rfc3263.util.LocatorUtils;

public class HostParsingTest {
	@BeforeClass
	public static void configureLogging() {
		BasicConfigurator.configure();
	}

	@Test
	public void testIsNumericIPv4() {
		assertTrue(LocatorUtils.isNumeric("192.168.0.1"));
	}
	
	@Test
	public void testIsNumericIPv6() {
		assertTrue(LocatorUtils.isNumeric("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]"));
	}
	
	@Test
	public void testIsNumericIPv6NonReference() {
		// This test distinguishes between an IPv6 address and IPv6 reference.
		assertFalse(LocatorUtils.isNumeric("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
	}
	
	@Test
	public void testIsNumericIPv6NoLeadingZeroes() {
		assertTrue(LocatorUtils.isNumeric("[2001:db8:85a3:0:0:8a2e:370:7334]"));
	}
	
	@Test
	public void testIsNumericIPv6GroupedZeroes() {
		assertTrue(LocatorUtils.isNumeric("[2001:db8:85a3::8a2e:370:7334]"));
	}
	
	@Test
	public void testIsNumericIPv6Loopback() {
		assertTrue(LocatorUtils.isNumeric("[::1]"));
	}
	
	@Test
	public void testIsNumericIPv6Unspecified() {
		assertTrue(LocatorUtils.isNumeric("[::]"));
	}
	
	@Test
	public void testIsNumericIPv6IPv4Mapping() {
		assertTrue(LocatorUtils.isNumeric("[::ffff:192.0.2.128]"));
	}
	
	@Test
	public void testIsNumericHost() {
		assertFalse(LocatorUtils.isNumeric("example.org"));
	}
}
