package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.theories.DataPoint;

import com.google.code.rfc3263.ObjectTest;

public class ServiceRecordTest extends ObjectTest {
	@DataPoint
	public static ServiceRecord a = new ServiceRecord("_sip._tcp.example.org.", 2, 1, 5060, "a.sip.example.org.");
	@DataPoint
	public static ServiceRecord b = new ServiceRecord("_sip._tcp.example.org.", 1, 1, 5060, "b.sip.example.org.");
	@DataPoint
	public static ServiceRecord c = new ServiceRecord("_sip._tcp.example.org.", 1, 1, 5060, "c.sip.example.org.");
	@DataPoint
	public static ServiceRecord nullRecord = null;
	
	@Test
	public void prioritySortingTest() {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		
		// Priority 2
		ServiceRecord one = new ServiceRecord("_sip._tcp.example.org.", 2, 1, 5060, "one.sip.example.org.");
		// Priority 1
		ServiceRecord two = new ServiceRecord("_sip._tcp.example.org.", 1, 1, 5060, "two.sip.example.org.");
		
		services.add(two);
		services.add(one);
		
		// Lower priorities should be first.
		Collections.sort(services, new ServiceRecordPriorityComparator());
		
		Assert.assertEquals(one, services.get(1));
		Assert.assertEquals(two, services.get(0));
	}
	
	@Test
	public void weightSortingTest() {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		
		// Weight 100
		ServiceRecord one = new ServiceRecord("_sip._tcp.example.org.", 1, 100, 5060, "one.sip.example.org.");
		// Weight 0
		ServiceRecord two = new ServiceRecord("_sip._tcp.example.org.", 1, 0, 5060, "two.sip.example.org.");
		
		services.add(one);
		services.add(two);
		
		// Zero weights should be first
		Collections.sort(services, new ServiceRecordWeightComparator());

		Assert.assertEquals(two, services.get(0));
		Assert.assertEquals(one, services.get(1));
	}
}
