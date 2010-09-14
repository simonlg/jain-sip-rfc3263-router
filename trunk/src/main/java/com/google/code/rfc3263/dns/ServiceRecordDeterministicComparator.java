package com.google.code.rfc3263.dns;

import java.util.Comparator;

import org.xbill.DNS.SRVRecord;

import net.jcip.annotations.ThreadSafe;

/**
 * This class sorts each ServiceRecord by weight field, and then by target field.
 * <p>
 * This algorithm is suggested by RFC 3263, and is deliberately different to the 
 * regular SRV sorting algorithm discussed in RFC 2782.  The difference serves to
 * eliminate randomness.
 */
@ThreadSafe
public class ServiceRecordDeterministicComparator implements Comparator<SRVRecord> {
	public int compare(SRVRecord o1, SRVRecord o2) {
		if (o1.getWeight() == o2.getWeight()) {
			return o1.getTarget().compareTo(o2.getTarget());
		} else if (o1.getWeight() > o2.getWeight()) {
			return -1;
		} else {
			return 1;
		}
	}
}
