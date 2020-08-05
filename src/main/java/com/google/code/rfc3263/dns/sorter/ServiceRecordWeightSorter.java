package com.google.code.rfc3263.dns.sorter;

import java.util.List;

import org.xbill.DNS.SRVRecord;

public interface ServiceRecordWeightSorter {

	public void sort(List<SRVRecord> srvRecords);

}
