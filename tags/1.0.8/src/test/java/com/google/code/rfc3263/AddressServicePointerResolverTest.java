package com.google.code.rfc3263;

import com.google.code.rfc3263.dns.AddressPointerServiceResolver;
import com.google.code.rfc3263.dns.Resolver;

/**
 * Tests for location in the following DNS environment:
 * 
 * NAPTR	Y
 * SRV		Y
 * A/AAAA	Y
 */
public class AddressServicePointerResolverTest extends AddressServiceResolverTest {
	@Override
	public Resolver getResolver() {
		return new AddressPointerServiceResolver();
	}
}
