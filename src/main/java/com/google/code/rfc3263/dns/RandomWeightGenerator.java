package com.google.code.rfc3263.dns;

import java.util.SplittableRandom;

public class RandomWeightGenerator {

  public int generate(int bound) {
    if (bound <= 0) {
      return 0;
    } else {
      return new SplittableRandom().nextInt(bound);
    }
  }
}
