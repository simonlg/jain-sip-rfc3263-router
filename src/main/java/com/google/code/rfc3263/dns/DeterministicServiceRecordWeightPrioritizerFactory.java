package com.google.code.rfc3263.dns;

public class DeterministicServiceRecordWeightPrioritizerFactory {

  public DeterministicServiceRecordWeightPrioritizer create() {
    return new DeterministicServiceRecordWeightPrioritizer(new ServiceRecordDeterministicComparator());
  }
}
