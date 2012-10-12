package com.google.code.rfc3263.dns;

import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.google.code.rfc3263.dns.AddressRecord;
import com.google.code.rfc3263.dns.PointerRecord;
import com.google.code.rfc3263.dns.Resolver;
import com.google.code.rfc3263.dns.ServiceRecord;

public class BaseResolver implements Resolver {
	public SortedSet<PointerRecord> lookupPointerRecords(String domain) {
		return new TreeSet<PointerRecord>();
	}

	public SortedSet<ServiceRecord> lookupServiceRecords(String domain) {
		return new TreeSet<ServiceRecord>();
	}
	
	public Set<AddressRecord> lookupAddressRecords(String domain) {
		return new HashSet<AddressRecord>();
	}
}
