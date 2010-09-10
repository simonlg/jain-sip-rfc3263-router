package com.google.code.rfc3263.dns;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class ServiceRecordSelectorTest {
	/**
	 * Tests four records, all with the same weight.
	 */
	@Test
	public void testSelectByTarget() {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		
		ServiceRecord a = new ServiceRecord("_sip._tcp.example.org.", 1, 0, 5060, "a.sip.example.org.");
		ServiceRecord b = new ServiceRecord("_sip._tcp.example.org.", 1, 0, 5060, "b.sip.example.org.");
		ServiceRecord c = new ServiceRecord("_sip._tcp.example.org.", 1, 0, 5060, "c.sip.example.org.");
		ServiceRecord d = new ServiceRecord("_sip._tcp.example.org.", 1, 0, 5060, "d.sip.example.org.");
		
		services.add(b);
		services.add(c);
		services.add(d);
		services.add(a);
		
		ServiceRecordSelector selector = new ServiceRecordSelector(services);
		List<ServiceRecord> sortedServices = selector.select();
		assertEquals(a, sortedServices.get(0));
		assertEquals(b, sortedServices.get(1));
		assertEquals(c, sortedServices.get(2));
		assertEquals(d, sortedServices.get(3));
	}
	
	/**
	 * Tests four records, all with the different weights.
	 */
	@Test
	public void testSelectByWeight() {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		
		ServiceRecord a = new ServiceRecord("_sip._tcp.example.org.", 1, 0, 5060, "a.sip.example.org.");
		ServiceRecord b = new ServiceRecord("_sip._tcp.example.org.", 1, 1, 5060, "b.sip.example.org.");
		ServiceRecord c = new ServiceRecord("_sip._tcp.example.org.", 1, 2, 5060, "c.sip.example.org.");
		ServiceRecord d = new ServiceRecord("_sip._tcp.example.org.", 1, 3, 5060, "d.sip.example.org.");
		
		services.add(b);
		services.add(d);
		services.add(c);
		services.add(a);
		
		ServiceRecordSelector selector = new ServiceRecordSelector(services);
		List<ServiceRecord> sortedServices = selector.select();
		assertEquals(d, sortedServices.get(0));
		assertEquals(c, sortedServices.get(1));
		assertEquals(b, sortedServices.get(2));
		assertEquals(a, sortedServices.get(3));
	}
}
