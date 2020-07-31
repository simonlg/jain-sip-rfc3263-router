package com.google.code.rfc3263.dns;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.SplittableRandom;

import org.xbill.DNS.SRVRecord;

import net.jcip.annotations.ThreadSafe;

@ThreadSafe
public class RandomServiceRecordWeightPrioritizer implements ServiceRecordWeightPrioritizer {

  private static final int FIRST_ELEMENT_POSITION = 0;

  private RandomWeightGenerator randomWeightGenerator;

  private Comparator<SRVRecord> weightComparator;

  public RandomServiceRecordWeightPrioritizer(Comparator<SRVRecord> weightComparator,
                                              RandomWeightGenerator randomWeightGenerator)
  {
    this.weightComparator = weightComparator;
    this.randomWeightGenerator = new RandomWeightGenerator();
  }

  @Override
  public void prioritize(List<SRVRecord> srvRecords) {
    Collections.sort(srvRecords, weightComparator);
    resolveWeightPriorityByRandomness(srvRecords);
  }

  private void resolveWeightPriorityByRandomness(List<SRVRecord> srvRecords) {
    int trafficWeightValue = randomWeightGenerator.generate(getTotalWeight(srvRecords));
    int minimumRange = 0;
    int maximumRange = 0;
    for (SRVRecord srvRecord : srvRecords) {
      minimumRange = maximumRange;
      maximumRange = minimumRange + srvRecord.getWeight();
      if (trafficWeightValue >= minimumRange && trafficWeightValue < maximumRange) {
        srvRecords.remove(srvRecord);
        srvRecords.add(FIRST_ELEMENT_POSITION, srvRecord);
        break;
      }
    }
  }

  private int getTotalWeight(List<SRVRecord> srvRecords) {
    int totalWeight = 0;
    for (SRVRecord srvRecord : srvRecords) {
      totalWeight = totalWeight + srvRecord.getWeight();
    }
    return totalWeight;
  }

  public int generateRandom(int bound) {
    if (bound <= 0) {
      return 0;
    } else {
      return new SplittableRandom().nextInt(bound);
    }
  }

}
