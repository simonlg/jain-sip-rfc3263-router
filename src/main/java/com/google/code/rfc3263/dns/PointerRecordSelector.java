package com.google.code.rfc3263.dns;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import net.jcip.annotations.ThreadSafe;

import org.apache.log4j.Logger;
import org.xbill.DNS.NAPTRRecord;

/**
 * This class is used for sorting NAPTR records.
 * <p>
 * The algorithm employed by this class is the algorithm specified in RFC 2915,
 * that is, records are sorted first by order, and then by preference.
 */
@ThreadSafe
public class PointerRecordSelector {
	private final Logger LOGGER = Logger.getLogger(PointerRecordSelector.class);
	private final List<NAPTRRecord> pointers;
	
	public PointerRecordSelector(List<NAPTRRecord> pointers) {
		this.pointers = new LinkedList<NAPTRRecord>(pointers);
	}
	
	public List<NAPTRRecord> select() {
		LOGGER.debug("Sorting service records by priority");
		Collections.sort(this.pointers, new PointerRecordOrderComparator());
		
		// Split map into orders.
		final Map<Integer, List<NAPTRRecord>> orderMap = new TreeMap<Integer, List<NAPTRRecord>>(); 
		for (NAPTRRecord pointer : this.pointers) {
			if (orderMap.containsKey(pointer.getOrder()) == false) {
				orderMap.put(pointer.getOrder(), new LinkedList<NAPTRRecord>());
			}
			orderMap.get(pointer.getOrder()).add(pointer);
		}
		
		final Integer lowestOrder = orderMap.keySet().iterator().next();
		final List<NAPTRRecord> lowestOrderPointers = orderMap.get(lowestOrder);
		
		Collections.sort(lowestOrderPointers, new PointerRecordPreferenceComparator());
		
		return lowestOrderPointers;
	}
}
