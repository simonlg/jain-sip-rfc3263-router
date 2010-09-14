package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.Type;

/**
 * This class is the default DNS resolver, which uses dnsjava.
 * <p>
 * This class is thread-safe.
 */
@ThreadSafe
public class DefaultResolver implements Resolver {
	/**
	 * {@inheritDoc}
	 */
	public Set<ARecord> lookupARecords(Name domain) {
		final Set<ARecord> addresses = new HashSet<ARecord>();
		
		Record[] records = new Lookup(domain, Type.A).run();
		
		if (records == null) {
			return addresses;
		}
		for (Record record : records) {
			addresses.add((ARecord) record);
		}
		
		return addresses;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public Set<AAAARecord> lookupAAAARecords(Name domain) {
		final Set<AAAARecord> addresses = new HashSet<AAAARecord>();
		
		Record[] records = new Lookup(domain, Type.AAAA).run();
		
		if (records == null) {
			return addresses;
		}
		for (Record record : records) {
			addresses.add((AAAARecord) record);
		}
		
		return addresses;
	}

	/**
	 * {@inheritDoc}
	 */
	public List<SRVRecord> lookupSRVRecords(Name domain) {
		final List<SRVRecord> services = new ArrayList<SRVRecord>();
		
		final Record[] records = new Lookup(domain, Type.SRV).run();

		if (records == null) {
			return services;
		}
		for (Record record : records) {
			services.add((SRVRecord) record);
		}
		
		return services;
	}

	/**
	 * {@inheritDoc}
	 */
	public List<NAPTRRecord> lookupNAPTRRecords(Name domain) {
		final List<NAPTRRecord> pointers = new ArrayList<NAPTRRecord>();
		
		final Record[] records = new Lookup(domain, Type.NAPTR).run();

		if (records == null) {
			return pointers;
		}
		for (Record record : records) {
			pointers.add((NAPTRRecord) record);
		}
		
		return pointers;
	}
}
