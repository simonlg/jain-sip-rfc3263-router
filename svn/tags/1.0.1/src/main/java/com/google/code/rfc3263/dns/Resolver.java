package com.google.code.rfc3263.dns;

import java.util.Set;
import java.util.SortedSet;

public interface Resolver {
	SortedSet<PointerRecord> lookupPointerRecords(String domain);
	SortedSet<ServiceRecord> lookupServiceRecords(String domain);
	Set<AddressRecord> lookupAddressRecords(String domain);
}
