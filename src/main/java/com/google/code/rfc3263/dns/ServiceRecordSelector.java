package com.google.code.rfc3263.dns;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import com.google.code.rfc3263.dns.sorter.ServiceRecordWeightSorter;
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
	private final ServiceRecordWeightSorter weightingSorter;

	public ServiceRecordSelector(List<SRVRecord> services, ServiceRecordWeightSorter weightingSorter) {
		this.services = new LinkedList<SRVRecord>(services);
		this.weightingSorter = weightingSorter;
	}

	public List<SRVRecord> select() {
		final List<SRVRecord> sortedList = new LinkedList<SRVRecord>();
		LOGGER.debug("Sorting SRV records");

		if (services.size() == 1) {
			LOGGER.debug("One SRV record found, no sort required");
			sortedList.addAll(services);
		} else {
			LOGGER.debug("Multiple SRV records found, sorting by SRV priority field");
			Collections.sort(this.services, new ServiceRecordPriorityComparator());

			// Split map into priorities.
			final Map<Integer, List<SRVRecord>> priorityMap = new TreeMap<Integer, List<SRVRecord>>();
			for (SRVRecord service : this.services) {
				if (priorityMap.containsKey(service.getPriority()) == false) {
					priorityMap.put(service.getPriority(), new LinkedList<SRVRecord>());
				}
				priorityMap.get(service.getPriority()).add(service);
			}

			for (Entry<Integer, List<SRVRecord>> entry : priorityMap.entrySet()) {
				final Integer priority = entry.getKey();
				final List<SRVRecord> priorityList = entry.getValue();

				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Sorting SRV records for priority field value " + priority);
				}
				if (priorityList.size() != 1) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Multiple SRV records found at priority " + priority + ", using " + weightingSorter.getClass() + " as sorting algorithm");
					}
					weightingSorter.sort(priorityList);
				} else if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("One SRV record found at priority " + priority
							+ ", no further sort required");
				}
				sortedList.addAll(priorityList);
			}
		}

		LOGGER.debug("Finished sorting SRV records");
		return sortedList;
	}
}
