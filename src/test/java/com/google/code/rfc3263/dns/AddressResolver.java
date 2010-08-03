package com.google.code.rfc3263.dns;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;

import com.google.code.rfc3263.AbstractResolverTest;
import com.google.code.rfc3263.dns.AddressRecord;

public class AddressResolver extends BaseResolver {
	@Override
	public Set<AddressRecord> lookupAddressRecords(String domain) {
		Set<AddressRecord> addresses = new HashSet<AddressRecord>();
		
		try {
			if (domain.equals(AbstractResolverTest.TEST_HOST + ".")) {
				addresses.add(new AddressRecord(domain, InetAddress.getByName(AbstractResolverTest.TEST_RESOLVED_ADDRESS)));
			} else {
				addresses.add(new AddressRecord(domain, InetAddress.getByName(AbstractResolverTest.TEST_RESOLVED_SERVICE_ADDRESS)));
			}
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}

		return addresses;
	}

}
