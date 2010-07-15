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
		
		if (domain.equals("_sip._tcp." + AbstractResolverTest.TEST_HOST + ".")) {
			services.add(new ServiceRecord(domain, 1, 0, 5060, "homer." + AbstractResolverTest.TEST_HOST + "."));
			services.add(new ServiceRecord(domain, 1, 10, 5060, "marge." + AbstractResolverTest.TEST_HOST + "."));
			services.add(new ServiceRecord(domain, 1, 50, 5060, "bart." + AbstractResolverTest.TEST_HOST + "."));
			services.add(new ServiceRecord(domain, 2, 1, 5060, "lisa." + AbstractResolverTest.TEST_HOST + "."));
			services.add(new ServiceRecord(domain, 2, 1, 5060, "maggie." + AbstractResolverTest.TEST_HOST + "."));
		}
		
		return services;
	}
}
