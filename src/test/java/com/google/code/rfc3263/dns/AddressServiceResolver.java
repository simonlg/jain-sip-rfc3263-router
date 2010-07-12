package com.google.code.rfc3263.dns;

import java.util.SortedSet;
import java.util.TreeSet;

import com.google.code.rfc3263.dns.ServiceRecord;

/**
 * DNS only declares TCP service.
 */
public class AddressServiceResolver extends AddressResolver {
	@Override
	public SortedSet<ServiceRecord> lookupServiceRecords(String domain) {
		SortedSet<ServiceRecord> services = new TreeSet<ServiceRecord>();
		
		final ServiceRecord service;
		if (domain.equals("_sip._tcp.example.org.")) {
			service = new ServiceRecord(domain, 1, 1, 5060, "sip.example.org.");
			services.add(service);
		}
		
		return services;
	}
}
