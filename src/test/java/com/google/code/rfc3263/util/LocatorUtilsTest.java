package com.google.code.rfc3263.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;
import org.xbill.DNS.Name;

public class LocatorUtilsTest {
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
	public void defaultPortForTlsSctpIs5061() {
		assertEquals(5061, LocatorUtils.getDefaultPortForTransport("TLS-SCTP"));
	}
	
	@Test
	public void shouldUpgradeTcpToTls() {
		assertEquals("TLS", LocatorUtils.upgradeTransport("TCP"));
	}
	
	@Test
	public void shouldUpgradeSctpToSctpTls() {
		assertEquals("TLS-SCTP", LocatorUtils.upgradeTransport("SCTP"));
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
		LocatorUtils.upgradeTransport("TLS-SCTP");
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
	public void testGetServiceIdentifierForInvalidTransport() throws IOException {
		LocatorUtils.getServiceIdentifier("FOO", new Name("example.org."));
	}
	
	@Test
	public void testGetServiceIdentifierForUdp() throws IOException {
		assertEquals(new Name("_sip._udp.example.org."), LocatorUtils.getServiceIdentifier("UDP", new Name("example.org.")));
	}
	
	@Test
	public void testGetServiceIdentifierForTcp() throws IOException {
		assertEquals(new Name("_sip._tcp.example.org."), LocatorUtils.getServiceIdentifier("TCP", new Name("example.org.")));
	}
	
	@Test
	public void testGetServiceIdentifierForTls() throws IOException {
		assertEquals(new Name("_sips._tcp.example.org."), LocatorUtils.getServiceIdentifier("TLS", new Name("example.org.")));
	}
	
	@Test
	public void testGetServiceIdentifierForSctp() throws IOException {
		assertEquals(new Name("_sip._sctp.example.org."), LocatorUtils.getServiceIdentifier("SCTP", new Name("example.org.")));
	}
	
	@Test
	public void testGetServiceIdentifierForSctpTls() throws IOException {
		assertEquals(new Name("_sips._sctp.example.org."), LocatorUtils.getServiceIdentifier("TLS-SCTP", new Name("example.org.")));
	}
}
