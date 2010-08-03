package com.google.code.rfc3263.dns;

/**
 * This is the representation of a RFC 2782 SRV DNS record.
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc2782.txt">RFC 2782</a>
 */
public final class ServiceRecord extends Record {
	private final int priority;
	private final int weight;
	private final int port;
	private final String target;
	
	/**
	 * Creates a new instance of this class.
	 * 
	 * @param name the name of the node to which this record pertains.
	 * @param priority
	 * @param weight
	 * @param port
	 * @param target
	 */
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
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
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
