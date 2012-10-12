package com.google.code.rfc3263.dns;

import java.util.Comparator;

// Sorts by weight, then by target
class ServiceRecordDeterministicComparator implements Comparator<ServiceRecord> {
	public int compare(ServiceRecord o1, ServiceRecord o2) {
		if (o1.getWeight() == o2.getWeight()) {
			return o1.getTarget().compareTo(o2.getTarget());
		} else if (o1.getWeight() > o2.getWeight()) {
			return -1;
		} else {
			return 1;
		}
	}
}
