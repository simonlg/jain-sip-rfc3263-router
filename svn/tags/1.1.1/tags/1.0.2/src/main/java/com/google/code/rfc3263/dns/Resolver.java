package com.google.code.rfc3263.dns;

import java.util.List;
import java.util.Set;

public interface Resolver {
	List<PointerRecord> lookupPointerRecords(String domain);
	List<ServiceRecord> lookupServiceRecords(String domain);
	Set<AddressRecord> lookupAddressRecords(String domain);
}
