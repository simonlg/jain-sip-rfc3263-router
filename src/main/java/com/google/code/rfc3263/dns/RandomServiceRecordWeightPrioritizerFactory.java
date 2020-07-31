package com.google.code.rfc3263.dns;

public class RandomServiceRecordWeightPrioritizerFactory {

  public RandomServiceRecordWeightPrioritizer create() {
    return new RandomServiceRecordWeightPrioritizer(new ServiceRecordDeterministicComparator(),
                                                    new RandomWeightGenerator());
  }
}
