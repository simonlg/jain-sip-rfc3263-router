package com.google.code.rfc3263.dns.sorter;

import java.util.*;

import org.xbill.DNS.SRVRecord;

import net.jcip.annotations.ThreadSafe;

@ThreadSafe
public class ServiceRecordLoadBalanceWeightSorter implements ServiceRecordWeightSorter {

	private static final int FIRST_ELEMENT_POSITION = 0;

	private final SplittableRandom random = new SplittableRandom();
	private final Comparator<SRVRecord> weightComparator = new WeightComparator();

	public ServiceRecordLoadBalanceWeightSorter() {
	}

	@Override
	/**
	 * Algorithm from RFC 2782
	 *
	 *         To select a target to be contacted next, arrange all SRV RRs
	 *         (that have not been ordered yet) in any order, except that all
	 *         those with weight 0 are placed at the beginning of the list.
	 *
	 *         Compute the sum of the weights of those RRs, and with each RR
	 *         associate the running sum in the selected order. Then choose a
	 *         uniform random number between 0 and the sum computed
	 *         (inclusive), and select the RR whose running sum value is the
	 *         first in the selected order which is greater than or equal to
	 *         the random number selected. The target host specified in the
	 *         selected SRV RR is the next one to be contacted by the client.
	 *         Remove this SRV RR from the set of the unordered SRV RRs and
	 *         apply the described algorithm to the unordered SRV RRs to select
	 *         the next target host.  Continue the ordering process until there
	 *         are no unordered SRV RRs.
	 */
	public void sort(List<SRVRecord> srvRecords) {
		Collections.sort(srvRecords, weightComparator);
		loadBalanceSortBasedOnWeight(srvRecords);
	}

	private void loadBalanceSortBasedOnWeight(List<SRVRecord> srvRecords) {
		for(int i = 0; i < srvRecords.size(); i++) {
			List<SRVRecord> unorderedRecords = srvRecords.subList(i, srvRecords.size());
			int randomValue = generateRandom(getTotalWeight(unorderedRecords) + 1);
			int cumulativeWeight = 0;
			for (SRVRecord srvRecord : unorderedRecords) {
				cumulativeWeight += srvRecord.getWeight();
				if (randomValue <= cumulativeWeight) {
					srvRecords.remove(srvRecord);
					srvRecords.add(i, srvRecord);
					break;
				}
			}
		}
	}

	private int getTotalWeight(List<SRVRecord> srvRecords) {
		int totalWeight = 0;
		for (SRVRecord srvRecord : srvRecords) {
			totalWeight += srvRecord.getWeight();
		}
		return totalWeight;
	}

	public int generateRandom(int bound) {
		if (bound <= 0) {
			return 0;
		} else {
			return random.nextInt(bound);
		}
	}

	/**
	 * Ascending sort of SRVRecord based on weight to ensure records with weight of 0 are first
	 */
	private static class WeightComparator implements Comparator<SRVRecord> {
		public int compare(SRVRecord o1, SRVRecord o2) {
			return (o1.getWeight() < o2.getWeight()) ? -1 : ((o1.getWeight() == o2.getWeight()) ? 0 : 1);
		}
	}
}
