package com.google.code.rfc3263.dns;

import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import net.jcip.annotations.ThreadSafe;

import org.apache.log4j.Logger;
import org.xbill.DNS.SRVRecord;

/**
 * This class is used for sorting ServiceRecords.
 * <p>
 * This class groups each ServiceRecord according to its priority into a TreeMap (indexed
 * by priority), and then sorts each group by weight, and then by target name. 
 */
@ThreadSafe
public class ServiceRecordSelector {
	private final Logger LOGGER = Logger.getLogger(ServiceRecordSelector.class);
	private final List<SRVRecord> services;
	private final Comparator<SRVRecord> weightingComparator;
	
	public ServiceRecordSelector(List<SRVRecord> services, Comparator<SRVRecord> weightingComparator) {
		this.services = new LinkedList<SRVRecord>(services);
		this.weightingComparator = weightingComparator;
	}
	
	public List<SRVRecord> select() {
		final List<SRVRecord> sortedList = new LinkedList<SRVRecord>();
		LOGGER.debug("Sorting service records by priority");
		Collections.sort(this.services, new ServiceRecordPriorityComparator());
		
		// Split map into priorities.
		final Map<Integer, List<SRVRecord>> priorityMap = new TreeMap<Integer, List<SRVRecord>>(); 
		for (SRVRecord service : this.services) {
			if (priorityMap.containsKey(service.getPriority()) == false) {
				priorityMap.put(service.getPriority(), new LinkedList<SRVRecord>());
			}
			priorityMap.get(service.getPriority()).add(service);
		}
		
		for (List<SRVRecord> priorityList : priorityMap.values()) {
			sortedList.addAll(selectPrioritised(priorityList));
		}
		
		LOGGER.debug("Finished sorting service records");
		return sortedList;
	}
	
	private List<SRVRecord> selectPrioritised(List<SRVRecord> services) {
		LOGGER.debug("Sorting service record(s) by weight for priority " + services.get(0).getPriority());
		
		if (services.size() == 1) {
			LOGGER.debug("Priority list has only one service record, no need to sort");
			return services;
		}
		
		Collections.sort(services, weightingComparator);
		
		return services;
	}
}
