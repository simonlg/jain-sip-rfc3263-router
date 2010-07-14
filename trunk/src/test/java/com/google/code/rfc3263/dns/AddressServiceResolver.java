package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.List;

import com.google.code.rfc3263.AbstractResolverTest;

/**
 * DNS only declares TCP service.
 */
public class AddressServiceResolver extends AddressResolver {
	@Override
	public List<ServiceRecord> lookupServiceRecords(String domain) {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		
		final ServiceRecord service;
		if (domain.equals("_sip._tcp." + AbstractResolverTest.TEST_HOST + ".")) {
			service = new ServiceRecord(domain, 1, 1, 5060, "sip." + AbstractResolverTest.TEST_HOST + ".");
			services.add(service);
		}
		
		return services;
	}
}
