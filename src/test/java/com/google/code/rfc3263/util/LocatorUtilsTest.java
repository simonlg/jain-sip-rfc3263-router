package com.google.code.rfc3263.util;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import org.apache.log4j.BasicConfigurator;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.rfc3263.util.LocatorUtils;

public class LocatorUtilsTest {
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
	
	@Test(expected = IllegalArgumentException.class)
	public void defaultPortForInvalidTransportThrowsException() {
		LocatorUtils.getDefaultPortForTransport("FOO");
	}
	
	@Test
	public void defaultPortForUdpIs5060() {
		assertEquals(5060, LocatorUtils.getDefaultPortForTransport("UDP"));
	}
	
	@Test
	public void defaultPortForTcpIs5060() {
		assertEquals(5060, LocatorUtils.getDefaultPortForTransport("TCP"));
	}
	
	@Test
	public void defaultPortForSctpIs5060() {
		assertEquals(5060, LocatorUtils.getDefaultPortForTransport("SCTP"));
	}
	
	@Test
	public void defaultPortForTlsIs5061() {
		assertEquals(5061, LocatorUtils.getDefaultPortForTransport("TLS"));
	}
	
	@Test
	public void defaultPortForSctpTlsIs5061() {
		assertEquals(5061, LocatorUtils.getDefaultPortForTransport("SCTP-TLS"));
	}
	
	@Test
	public void shouldUpgradeTcpToTls() {
		assertEquals("TLS", LocatorUtils.upgradeTransport("TCP"));
	}
	
	@Test
	public void shouldUpgradeSctpToSctpTls() {
		assertEquals("SCTP-TLS", LocatorUtils.upgradeTransport("SCTP"));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void shouldFailToUpgradeUnknownTransport() {
		LocatorUtils.upgradeTransport("FOO");
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void shouldFailToUpgradeUdp() {
		LocatorUtils.upgradeTransport("UDP");
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void shouldFailToUpgradeTls() {
		LocatorUtils.upgradeTransport("TLS");
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void shouldFailToUpgradeSctpTls() {
		LocatorUtils.upgradeTransport("SCTP-TLS");
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void defaultTransportForInvalidSchemeThrowsException() {
		LocatorUtils.getDefaultTransportForScheme("foo");
	}

	@Test
	public void defaultTransportForSipIsUdp() {
		assertEquals("UDP", LocatorUtils.getDefaultTransportForScheme("sip"));
	}
	
	@Test
	public void defaultTransportForSipsIsTls() {
		assertEquals("TLS", LocatorUtils.getDefaultTransportForScheme("sips"));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testGetServiceIdentifierForInvalidTransport() {
		LocatorUtils.getServiceIdentifier("FOO", "example.org.");
	}
	
	@Test
	public void testGetServiceIdentifierForUdp() {
		assertEquals("_sip._udp.example.org.", LocatorUtils.getServiceIdentifier("UDP", "example.org."));
	}
	
	@Test
	public void testGetServiceIdentifierForTcp() {
		assertEquals("_sip._tcp.example.org.", LocatorUtils.getServiceIdentifier("TCP", "example.org."));
	}
	
	@Test
	public void testGetServiceIdentifierForTls() {
		assertEquals("_sips._tcp.example.org.", LocatorUtils.getServiceIdentifier("TLS", "example.org."));
	}
	
	@Test
	public void testGetServiceIdentifierForSctp() {
		assertEquals("_sip._sctp.example.org.", LocatorUtils.getServiceIdentifier("SCTP", "example.org."));
	}
	
	@Test
	public void testGetServiceIdentifierForSctpTls() {
		assertEquals("_sips._sctp.example.org.", LocatorUtils.getServiceIdentifier("SCTP-TLS", "example.org."));
	}
}
