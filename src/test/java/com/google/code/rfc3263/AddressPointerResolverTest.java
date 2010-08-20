package com.google.code.rfc3263;

import com.google.code.rfc3263.dns.AddressPointerResolver;
import com.google.code.rfc3263.dns.Resolver;

/**
 * Tests for location in the following DNS environment:
 * 
 * NAPTR	Y
 * SRV		N
 * A/AAAA	Y
 */
public class AddressPointerResolverTest extends AddressResolverTest {
	@Override
	public Resolver getResolver() {
		return new AddressPointerResolver();
	}
}
