package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class ServiceRecordSelectorTest {
	@Test
	public void testSelect() {
		List<ServiceRecord> services = new ArrayList<ServiceRecord>();
		
		ServiceRecord one = new ServiceRecord("_sip._tcp.example.org.", 1, 100, 5060, "one.sip.example.org.");
		ServiceRecord two = new ServiceRecord("_sip._tcp.example.org.", 1, 0, 5060, "two.sip.example.org.");
		
		services.add(one);
		services.add(two);
		
		ServiceRecordSelector selector = new ServiceRecordSelector(services);
		selector.select();
	}

}
