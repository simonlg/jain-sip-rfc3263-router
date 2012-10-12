package com.google.code.rfc3263.dns;

import java.util.Comparator;

public class ServiceRecordWeightComparator implements Comparator<ServiceRecord> {
	public int compare(ServiceRecord o1, ServiceRecord o2) {
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
