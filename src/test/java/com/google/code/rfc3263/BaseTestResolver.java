package com.google.code.rfc3263;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

public class BaseTestResolver implements Resolver {

	@Override
	public SortedSet<PointerRecord> lookupPointerRecords(String domain) {
		return new TreeSet<PointerRecord>();
	}

	@Override
	public SortedSet<ServiceRecord> lookupServiceRecords(String domain) {
		return new TreeSet<ServiceRecord>();
	}

	@Override
	public Set<AddressRecord> lookupAddressRecords(String domain) {
		Set<AddressRecord> addresses = new HashSet<AddressRecord>();
		
		try {
			if (domain.equals("example.org")) {
				addresses.add(new AddressRecord(domain, InetAddress.getByName(AbstractTest.TEST_RESOLVED_ADDRESS)));
			} else {
				addresses.add(new AddressRecord(domain, InetAddress.getByName(AbstractTest.TEST_RESOLVED_SERVICE_ADDRESS)));
			}
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}

		return addresses;
	}

}
