package com.google.code.rfc3263.dns;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.code.rfc3263.dns.sorter.ServiceRecordDeterministicWeightSorter;
import com.google.code.rfc3263.dns.sorter.ServiceRecordLoadBalanceWeightSorter;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TextParseException;

public class ServiceRecordSelectorTest {
	/**
	 * Tests four records, all with the same weight.
	 * @throws TextParseException
	 */
	@Test
	public void testSelectByTarget() throws TextParseException {
		List<SRVRecord> services = new ArrayList<SRVRecord>();

		SRVRecord a = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 0, 5060, new Name("a.sip.example.org."));
		SRVRecord b = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 0, 5060, new Name("b.sip.example.org."));
		SRVRecord c = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 0, 5060, new Name("c.sip.example.org."));
		SRVRecord d = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 0, 5060, new Name("d.sip.example.org."));

		services.add(b);
		services.add(c);
		services.add(d);
		services.add(a);

		ServiceRecordSelector selector = new ServiceRecordSelector(services, new ServiceRecordDeterministicWeightSorter(new ServiceRecordDeterministicComparator()));
		List<SRVRecord> sortedServices = selector.select();
		assertEquals(a, sortedServices.get(0));
		assertEquals(b, sortedServices.get(1));
		assertEquals(c, sortedServices.get(2));
		assertEquals(d, sortedServices.get(3));
	}

	/**
	 * Tests four records, all with the different weights.
	 * @throws TextParseException
	 */
	@Test
	public void testSelectByWeight() throws TextParseException {
		List<SRVRecord> services = new ArrayList<SRVRecord>();

		SRVRecord a = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 0, 5060, new Name("a.sip.example.org."));
		SRVRecord b = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 1, 5060, new Name("b.sip.example.org."));
		SRVRecord c = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 2, 5060, new Name("c.sip.example.org."));
		SRVRecord d = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 3, 5060, new Name("d.sip.example.org."));

		services.add(b);
		services.add(d);
		services.add(c);
		services.add(a);

		ServiceRecordSelector selector = new ServiceRecordSelector(services, new ServiceRecordDeterministicWeightSorter(new ServiceRecordDeterministicComparator()));
		List<SRVRecord> sortedServices = selector.select();
		assertEquals(d, sortedServices.get(0));
		assertEquals(c, sortedServices.get(1));
		assertEquals(b, sortedServices.get(2));
		assertEquals(a, sortedServices.get(3));
	}

	/**
	 * Tests four records, all with the different weights.
	 * @throws TextParseException
	 */
	@Test
	public void testSelectLoadBalancedByWeight() throws TextParseException {
		PositionCount aPositionCount = new PositionCount();
		PositionCount bPositionCount = new PositionCount();
		PositionCount cPositionCount = new PositionCount();

		for(int i = 0; i < 10000; i++) {
			List<SRVRecord> services = new ArrayList<SRVRecord>();

			SRVRecord a = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 30, 5060, new Name("a.sip.example.org."));
			SRVRecord b = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 15, 5060, new Name("b.sip.example.org."));
			SRVRecord c = new SRVRecord(new Name("_sip._tcp.example.org."), DClass.IN, 1000L, 1, 0, 5060, new Name("d.sip.example.org."));

			services.add(c);
			services.add(b);
			services.add(a);

			ServiceRecordSelector selector = new ServiceRecordSelector(services, new ServiceRecordLoadBalanceWeightSorter());
			List<SRVRecord> sortedServices = selector.select();

			aPositionCount.increment(sortedServices.indexOf(a));
			bPositionCount.increment(sortedServices.indexOf(b));
			cPositionCount.increment(sortedServices.indexOf(c));
		}

		assertTrue(aPositionCount.getCount(0) < 7000);
		assertTrue(aPositionCount.getCount(0) > 5000);
		assertTrue(aPositionCount.getCount(1) < 4500);
		assertTrue(aPositionCount.getCount(1) > 2500);
		assertTrue(aPositionCount.getCount(2) < 1000);
		assertTrue(aPositionCount.getCount(2) > 50);

		assertTrue(bPositionCount.getCount(0) < 4500);
		assertTrue(bPositionCount.getCount(0) > 2500);
		assertTrue(bPositionCount.getCount(1) < 7000);
		assertTrue(bPositionCount.getCount(1) > 5000);
		assertTrue(bPositionCount.getCount(2) < 1000);
		assertTrue(bPositionCount.getCount(2) > 50);

		assertTrue(cPositionCount.getCount(0) < 300);
		assertTrue(cPositionCount.getCount(0) > 50);
		assertTrue(cPositionCount.getCount(1) < 1000);
		assertTrue(cPositionCount.getCount(1) > 50);
		assertTrue(cPositionCount.getCount(2) < 9900);
		assertTrue(cPositionCount.getCount(2) > 8500);
	}

	private static class PositionCount {
		Map<Integer, Integer> counts = new HashMap<Integer, Integer>();

		public void increment(int position) {
			Integer currentCount = counts.get(position);
			if(currentCount == null) {
				currentCount = 0;
			}
			currentCount++;
			counts.put(position, currentCount);
		}

		public int getCount(int position) {
			return counts.get(position);
		}

		@Override
		public String toString() {
			return counts.toString();
		}
	}

}
