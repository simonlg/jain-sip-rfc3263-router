package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;


public class PointerRecordTest {
	@Ignore @Test
	public void sortingTest() {
		List<PointerRecord> pointers = new ArrayList<PointerRecord>();
		
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
