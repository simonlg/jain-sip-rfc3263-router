package com.google.code.rfc3263.dns;

/**
 * See http://www.ietf.org/rfc/rfc2782.txt
 */
public final class ServiceRecord implements Comparable<ServiceRecord> {
	private final int priority;
	private final int weight;
	private final int port;
	private final String target;
	
	public ServiceRecord(int priority, int weight, int port, String target) {
		this.priority = priority;
		this.weight = weight;
		this.port = port;
		this.target = target;
	}
	
	public int getPriority() {
		return priority;
	}
	
	public int getWeight() {
		return weight;
	}
	
	public int getPort() {
		return port;
	}
	
	public String getTarget() {
		return target;
	}

	@Override
	public int compareTo(ServiceRecord o) {
		// TODO: Compare properly.
		return 1;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		sb.append('[');
		sb.append("IN SRV ");
		sb.append(priority);
		sb.append(' ');
		sb.append(weight);
		sb.append(' ');
		sb.append(port);
		sb.append(' ');
		sb.append(target);
		sb.append(']');
		
		return sb.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + port;
		result = prime * result + priority;
		result = prime * result + ((target == null) ? 0 : target.hashCode());
		result = prime * result + weight;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof ServiceRecord)) {
			return false;
		}
		ServiceRecord other = (ServiceRecord) obj;
		if (port != other.port) {
			return false;
		}
		if (priority != other.priority) {
			return false;
		}
		if (target == null) {
			if (other.target != null) {
				return false;
			}
		} else if (!target.equals(other.target)) {
			return false;
		}
		if (weight != other.weight) {
			return false;
		}
		return true;
	}
}
