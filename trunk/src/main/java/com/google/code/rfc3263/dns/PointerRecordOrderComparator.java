package com.google.code.rfc3263.dns;

import java.util.Comparator;

import org.xbill.DNS.NAPTRRecord;

import net.jcip.annotations.ThreadSafe;

/**
 * This class is used for sorting NAPTR records by order field.
 */
@ThreadSafe
class PointerRecordOrderComparator implements Comparator<NAPTRRecord> {
	public int compare(NAPTRRecord o1, NAPTRRecord o2) {
		if (o1.getOrder() < o2.getOrder()) {
			return -1;
		} else if (o1.getOrder() > o2.getOrder()) {
			return 1;
		} else {
			return 0;
		}
	}
}
