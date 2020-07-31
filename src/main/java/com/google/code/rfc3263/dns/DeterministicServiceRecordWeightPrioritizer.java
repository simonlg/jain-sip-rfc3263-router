package com.google.code.rfc3263.dns;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.xbill.DNS.SRVRecord;

import net.jcip.annotations.ThreadSafe;

@ThreadSafe
public class DeterministicServiceRecordWeightPrioritizer implements ServiceRecordWeightPrioritizer {

  private Comparator<SRVRecord> weightComparator;

  public DeterministicServiceRecordWeightPrioritizer(Comparator<SRVRecord> weightComparator) {
    this.weightComparator = weightComparator;
  }

  @Override
  public void prioritize(List<SRVRecord> srvRecords) {
    Collections.sort(srvRecords, weightComparator);
  }

}
