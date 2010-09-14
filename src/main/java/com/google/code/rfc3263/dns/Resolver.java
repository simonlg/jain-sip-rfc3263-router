package com.google.code.rfc3263.dns;

import java.util.List;
import java.util.Set;

import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.SRVRecord;

/**
 * This class encapsulates a partial DNS client.
 */
public interface Resolver {
	/**
	 * Returns a list of NAPTR records for the given domain.
	 * 
	 * @param domain the domain to query.
	 * @return a list of NAPTR records.
	 */
	List<NAPTRRecord> lookupPointerRecords(String domain);
	/**
	 * Returns a list of SRV records for the given domain.
	 * 
	 * @param domain the domain to query.
	 * @return a list of SRV records.
	 */
	List<SRVRecord> lookupServiceRecords(String domain);
	/**
	 * Returns a list of A or AAAA records for the given domain.
	 * 
	 * @param domain the domain to query.
	 * @return a list of A or AAAA records.
	 */
	Set<AddressRecord> lookupAddressRecords(String domain);
}
