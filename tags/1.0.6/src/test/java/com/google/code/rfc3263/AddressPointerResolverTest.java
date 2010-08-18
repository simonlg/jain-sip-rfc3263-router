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
	public AddressPointerResolverTest() {
		this(new AddressPointerResolver());
	}
	
	public AddressPointerResolverTest(Resolver resolver) {
		super(resolver);
	}
}
