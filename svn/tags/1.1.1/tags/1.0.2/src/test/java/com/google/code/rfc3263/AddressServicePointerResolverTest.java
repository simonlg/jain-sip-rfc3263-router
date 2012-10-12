package com.google.code.rfc3263;

import com.google.code.rfc3263.dns.AddressPointerServiceResolver;

/**
 * Tests for location in the following DNS environment:
 * 
 * NAPTR	Y
 * SRV		Y
 * A/AAAA	Y
 */
public class AddressServicePointerResolverTest extends AddressServiceResolverTest {
	public AddressServicePointerResolverTest() {
		super(new AddressPointerServiceResolver());
	}
}
