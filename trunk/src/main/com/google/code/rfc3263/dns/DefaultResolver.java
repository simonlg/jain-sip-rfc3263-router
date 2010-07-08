package com.google.code.rfc3263.dns;

import java.util.SortedSet;
import java.util.TreeSet;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class DefaultResolver implements Resolver {
	public SortedSet<PointerRecord> lookupPointerRecords(String domain) {
		final SortedSet<PointerRecord> pointers = new TreeSet<PointerRecord>();
		
		final Record[] records;
		try {
			records = new Lookup(domain, Type.NAPTR).run();
		} catch (TextParseException e) {
			throw new RuntimeException(e);
		}
		if (records == null) {
			return pointers;
		}
		for (int i = 0; i < records.length; i++) {
			NAPTRRecord naptr = (NAPTRRecord) records[i];

			int order = naptr.getOrder();
			int preference = naptr.getPreference();
			String flags = naptr.getFlags();
			String service = naptr.getService();
			String regexp = naptr.getRegexp();
			String replacement = naptr.getReplacement().toString();
			
			PointerRecord pointer = new PointerRecord(order, preference, flags, service, regexp, replacement);
			pointers.add(pointer);
		}
		
		
		return pointers;
	}

	public SortedSet<ServiceRecord> lookupServiceRecords(String domain) {
		final SortedSet<ServiceRecord> services = new TreeSet<ServiceRecord>();
		
		final Record[] records;
		try {
			records = new Lookup(domain, Type.SRV).run();
		} catch (TextParseException e) {
			throw new RuntimeException(e);
		}
		if (records == null) {
			return services;
		}
		for (int i = 0; i < records.length; i++) {
			SRVRecord srv = (SRVRecord) records[i];

			int priority = srv.getPriority();
			int weight = srv.getWeight();
			int port = srv.getPort();
			String target = srv.getTarget().toString();
			
			ServiceRecord service = new ServiceRecord(priority, weight, port, target);
			services.add(service);
		}
		
		
		return services;
	}
}
