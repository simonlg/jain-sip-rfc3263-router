package com.google.code.rfc3263.dns;

import java.util.Comparator;

class ServiceRecordPriorityComparator implements Comparator<ServiceRecord> {
	public int compare(ServiceRecord o1, ServiceRecord o2) {
		if (o1.getPriority() < o2.getPriority()) {
			return -1;
		} else if (o1.getPriority() > o2.getPriority()) {
			return 1;
		} else {
			return 0;
		}
	}
}
