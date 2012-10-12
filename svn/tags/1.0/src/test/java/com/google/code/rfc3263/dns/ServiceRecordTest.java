package com.google.code.rfc3263.dns;

import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import org.junit.Assert;
import org.junit.Test;


public class ServiceRecordTest {
	@Test
	public void sortingTest() {
		SortedSet<ServiceRecord> services = new TreeSet<ServiceRecord>();
		
		ServiceRecord baz = new ServiceRecord("_sip._tcp.example.org.", 3, 1, 5060, "gamma.example.org.");
		ServiceRecord bar = new ServiceRecord("_sip._tcp.example.org.", 1, 1, 5060, "beta.example.org.");
		ServiceRecord foo = new ServiceRecord("_sip._tcp.example.org.", 1, 3, 5060, "alpha.example.org.");
		
		services.add(baz);
		services.add(bar);
		services.add(foo);
		
		Iterator<ServiceRecord> iter = services.iterator();
		
		Assert.assertEquals(foo, iter.next());
		Assert.assertEquals(bar, iter.next());
		Assert.assertEquals(baz, iter.next());
	}
}
