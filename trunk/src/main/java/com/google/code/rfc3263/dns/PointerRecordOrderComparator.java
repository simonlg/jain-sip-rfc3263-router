package com.google.code.rfc3263.dns;

import java.util.Comparator;

import net.jcip.annotations.ThreadSafe;

@ThreadSafe
class PointerRecordOrderComparator implements Comparator<PointerRecord> {
	public int compare(PointerRecord o1, PointerRecord o2) {
		if (o1.getOrder() < o2.getOrder()) {
			return -1;
		} else if (o1.getOrder() > o2.getOrder()) {
			return 1;
		} else {
			return 0;
		}
	}
}
