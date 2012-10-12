package com.google.code.rfc3263.dns;

import java.util.SortedSet;
import java.util.TreeSet;

import com.google.code.rfc3263.dns.PointerRecord;

public class AddressPointerServiceResolver extends AddressServiceResolver {
	@Override
	public SortedSet<PointerRecord> lookupPointerRecords(String domain) {
		SortedSet<PointerRecord> pointers = new TreeSet<PointerRecord>();
		
		pointers.add(new PointerRecord(domain, 1, 1, "s", "SIP+D2T", "", "_sip._tcp.example.org."));
		
		return pointers;
	}
}
