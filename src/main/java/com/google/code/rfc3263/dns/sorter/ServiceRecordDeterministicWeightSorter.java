package com.google.code.rfc3263.dns.sorter;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.xbill.DNS.SRVRecord;

import net.jcip.annotations.ThreadSafe;

@ThreadSafe
public class ServiceRecordDeterministicWeightSorter implements ServiceRecordWeightSorter {

	private Comparator<SRVRecord> weightComparator;

	public ServiceRecordDeterministicWeightSorter(Comparator<SRVRecord> weightComparator) {
		this.weightComparator = weightComparator;
	}

	@Override
	public void sort(List<SRVRecord> srvRecords) {
		Collections.sort(srvRecords, weightComparator);
	}

}
