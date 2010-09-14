package com.google.code.rfc3263.dns;

import java.util.Comparator;

import org.xbill.DNS.NAPTRRecord;

import net.jcip.annotations.ThreadSafe;

/**
 * This class is used for sorting NAPTR records by preference field.
 */
@ThreadSafe
class PointerRecordPreferenceComparator implements Comparator<NAPTRRecord> {
	public int compare(NAPTRRecord o1, NAPTRRecord o2) {
		if (o1.getPreference() < o2.getPreference()) {
			return -1;
		} else if (o1.getPreference() > o2.getPreference()) {
			return 1;
		} else {
			return 0;
		}
	}
}
