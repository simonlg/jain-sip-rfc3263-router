package com.google.code.rfc3263.dns;

import java.util.Comparator;

import org.xbill.DNS.SRVRecord;

import net.jcip.annotations.ThreadSafe;

/**
 * This class is used for ordering ServiceRecord instances by weight field.
 * <p>
 * This class has been superceded by ServiceRecordDeterministicComparator.
 */
@Deprecated
@ThreadSafe
class ServiceRecordWeightComparator implements Comparator<SRVRecord> {
	public int compare(SRVRecord o1, SRVRecord o2) {
		if (o1.getWeight() == o2.getWeight()) {
			return 0;
		} else if (o1.getWeight() == 0) {
			return -1;
		} else if (o2.getWeight() == 0){
			return 1;
		} else {
			return 0;
		}
	}
}
