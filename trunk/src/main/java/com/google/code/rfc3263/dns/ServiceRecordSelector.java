package com.google.code.rfc3263.dns;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

public class ServiceRecordSelector {
	private final List<ServiceRecord> services;
	
	public ServiceRecordSelector(List<ServiceRecord> services) {
		this.services = new ArrayList<ServiceRecord>(services);
	}
	
	public ServiceRecord select() {
		Collections.sort(this.services, new ServiceRecordPriorityComparator());
		
		// Split map into priorities.
		Map<Integer, List<ServiceRecord>> priorityMap = new TreeMap<Integer, List<ServiceRecord>>(); 
		for (ServiceRecord service : this.services) {
			if (priorityMap.containsKey(service.getPriority()) == false) {
				priorityMap.put(service.getPriority(), new ArrayList<ServiceRecord>());
			}
			priorityMap.get(service.getPriority()).add(service);
		}
		
		for (List<ServiceRecord> priorityList : priorityMap.values()) {
			Collections.sort(priorityList, new ServiceRecordWeightComparator());
			
			int sumWeight = 0;
			for (ServiceRecord service : priorityList) {
				sumWeight += service.getWeight();
			}
			Random rnd = new Random();
			int targetWeight = rnd.nextInt(sumWeight + 1);
			for (ServiceRecord service : priorityList) {
				targetWeight -= service.getWeight();
				if (targetWeight <= 0) {
					return service;
				}
			}
		}
		
		return null;
	}
}
