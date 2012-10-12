package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.List;

import com.google.code.rfc3263.AbstractResolverTest;

public class AddressPointerResolver extends AddressServiceResolver {
	@Override
	public List<ServiceRecord> lookupServiceRecords(String domain) {
		return new ArrayList<ServiceRecord>();
	}
	
	@Override
	public List<PointerRecord> lookupPointerRecords(String domain) {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		
		pointers.add(new PointerRecord(domain, 1, 1, "s", "SIP+D2T", "", "_sip._tcp." + AbstractResolverTest.TEST_HOST + "."));
		
		return pointers;
	}
}
