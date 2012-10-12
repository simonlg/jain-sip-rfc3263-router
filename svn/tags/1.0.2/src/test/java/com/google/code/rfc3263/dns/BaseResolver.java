package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class BaseResolver implements Resolver {
	public List<PointerRecord> lookupPointerRecords(String domain) {
		return new ArrayList<PointerRecord>();
	}

	public List<ServiceRecord> lookupServiceRecords(String domain) {
		return new ArrayList<ServiceRecord>();
	}
	
	public Set<AddressRecord> lookupAddressRecords(String domain) {
		return new HashSet<AddressRecord>();
	}
}
