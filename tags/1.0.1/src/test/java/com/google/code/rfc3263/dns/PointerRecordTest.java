package com.google.code.rfc3263.dns;

import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import org.junit.Assert;
import org.junit.Test;


public class PointerRecordTest {
	@Test
	public void sortingTest() {
		SortedSet<PointerRecord> pointers = new TreeSet<PointerRecord>();
		
		PointerRecord tls = new PointerRecord("example.org.", 3, 1, "s", "SIPS+D2T", "", "_sips._tcp.example.org.");
		PointerRecord tcp = new PointerRecord("example.org.", 1, 2, "s", "SIP+D2T", "", "_sip._tcp.example.org.");
		PointerRecord udp = new PointerRecord("example.org.", 1, 3, "s", "SIP+D2U", "", "_sip._udp.example.org.");
		
		pointers.add(tls);
		pointers.add(tcp);
		pointers.add(udp);
		
		Iterator<PointerRecord> iter = pointers.iterator();
		
		Assert.assertEquals(tcp, iter.next());
		Assert.assertEquals(udp, iter.next());
		Assert.assertEquals(tls, iter.next());
	}
}
