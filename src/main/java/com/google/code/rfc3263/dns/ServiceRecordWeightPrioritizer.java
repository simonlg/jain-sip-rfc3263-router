package com.google.code.rfc3263.dns;

import java.util.List;

import org.xbill.DNS.SRVRecord;

public interface ServiceRecordWeightPrioritizer {

  public void prioritize(List<SRVRecord> srvRecords);

}
