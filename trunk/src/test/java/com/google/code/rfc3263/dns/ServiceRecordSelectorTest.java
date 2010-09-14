package com.google.code.rfc3263.dns;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

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
		
		ServiceRecordSelector selector = new ServiceRecordSelector(services, new ServiceRecordDeterministicComparator());
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
		
		ServiceRecordSelector selector = new ServiceRecordSelector(services, new ServiceRecordDeterministicComparator());
		List<SRVRecord> sortedServices = selector.select();
		assertEquals(d, sortedServices.get(0));
		assertEquals(c, sortedServices.get(1));
		assertEquals(b, sortedServices.get(2));
		assertEquals(a, sortedServices.get(3));
	}
}
