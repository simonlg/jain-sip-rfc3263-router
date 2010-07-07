package com.google.code.rfc3263.dns;

import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.NAPTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class DefaultResolver implements Resolver {
	private final Set<String> validServiceFields = new HashSet<String>();
	
	public DefaultResolver() {
		validServiceFields.add("SIP+D2T");
		validServiceFields.add("SIPS+D2T");
		validServiceFields.add("SIP+D2U");
		validServiceFields.add("SIP+D2S");
		validServiceFields.add("SIPS+D2S");
	}
	
	@Override
	public SortedSet<PointerRecord> lookupPointerRecords(String domain, boolean isSecure) {
		final SortedSet<PointerRecord> pointers = new TreeSet<PointerRecord>();
		
		final Record[] records;
		try {
			records = new Lookup(domain, Type.NAPTR).run();
		} catch (TextParseException e) {
			throw new RuntimeException(e);
		}
		for (int i = 0; i < records.length; i++) {
			NAPTRRecord naptr = (NAPTRRecord) records[i];
			if (validServiceFields.contains(naptr.getService()) == false) {
				continue;
			}
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

}
