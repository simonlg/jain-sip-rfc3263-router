package com.google.code.rfc3263.dns;

/**
 * See http://www.ietf.org/rfc/rfc2782.txt
 */
public final class ServiceRecord extends Record implements Comparable<ServiceRecord> {
	private final int priority;
	private final int weight;
	private final int port;
	private final String target;
	
	public ServiceRecord(String name, int priority, int weight, int port, String target) {
		super(name);
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

	public int compareTo(ServiceRecord o) {
		if (priority < o.priority) {
			return -1;
		} else  if (priority > o.priority) {
			return 1;
		} else {
			if (weight > o.weight) {
				return -1;
			} else if (weight < o.weight) {
				return 1;
			}
			return getName().compareTo(o.getName());
		}
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		sb.append('[');
		sb.append(super.toString());
		sb.append(' ');
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
		int result = super.hashCode();
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
		if (!super.equals(obj)) {
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
