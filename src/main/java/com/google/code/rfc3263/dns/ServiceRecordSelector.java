package com.google.code.rfc3263.dns;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.log4j.Logger;

public class ServiceRecordSelector {
	private final Logger LOGGER = Logger.getLogger(ServiceRecordSelector.class);
	private final List<ServiceRecord> services;
	
	public ServiceRecordSelector(List<ServiceRecord> services) {
		this.services = new LinkedList<ServiceRecord>(services);
	}
	
	public List<ServiceRecord> select() {
		final List<ServiceRecord> sortedList = new LinkedList<ServiceRecord>();
		LOGGER.debug("Sorting service records by priority");
		Collections.sort(this.services, new ServiceRecordPriorityComparator());
		
		// Split map into priorities.
		final Map<Integer, List<ServiceRecord>> priorityMap = new TreeMap<Integer, List<ServiceRecord>>(); 
		for (ServiceRecord service : this.services) {
			if (priorityMap.containsKey(service.getPriority()) == false) {
				priorityMap.put(service.getPriority(), new LinkedList<ServiceRecord>());
			}
			priorityMap.get(service.getPriority()).add(service);
		}
		
		for (List<ServiceRecord> priorityList : priorityMap.values()) {
			sortedList.addAll(selectPrioritised(priorityList));
		}
		
		LOGGER.debug("Finished sorting service records");
		return sortedList;
	}
	
	private List<ServiceRecord> selectPrioritised(List<ServiceRecord> services) {
		LOGGER.debug("Sorting service record(s) by weight for priority " + services.get(0).getPriority());
		
		if (services.size() == 1) {
			LOGGER.debug("Priority list has only one service record, no need to sort");
			return services;
		}
		
		Collections.sort(services, new ServiceRecordDeterministicComparator());
		
		return services;
	}
}
