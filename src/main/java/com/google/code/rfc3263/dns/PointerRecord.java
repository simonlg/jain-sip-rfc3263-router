package com.google.code.rfc3263.dns;

/**
 * This is the representation of a RFC 2915 NAPTR DNS record.
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc2915.txt">RFC 2915</a>
 */
public final class PointerRecord extends Record {
	private final int order;
	private final int preference;
	private final String flags;
	private final String service;
	private final String regexp;
	private final String replacement;
	
	public PointerRecord(String name, int order, int preference, String flags, String service, String regexp, String replacement) {
		super(name);
		this.order = order;
		this.preference = preference;
		this.flags = flags;
		this.service = service;
		this.regexp = regexp;
		this.replacement = replacement;
	}
	
	public int getOrder() {
		return order;
	}
	
	public int getPreference() {
		return preference;
	}
	
	public String getFlags() {
		return flags;
	}
	
	public String getService() {
		return service;
	}
	
	public String getRegexp() {
		return regexp;
	}
	
	public String getReplacement() {
		return replacement;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((flags == null) ? 0 : flags.hashCode());
		result = prime * result + order;
		result = prime * result + preference;
		result = prime * result + ((regexp == null) ? 0 : regexp.hashCode());
		result = prime * result
				+ ((replacement == null) ? 0 : replacement.hashCode());
		result = prime * result + ((service == null) ? 0 : service.hashCode());
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
		if (!(obj instanceof PointerRecord)) {
			return false;
		}
		PointerRecord other = (PointerRecord) obj;
		if (flags == null) {
			if (other.flags != null) {
				return false;
			}
		} else if (!flags.equals(other.flags)) {
			return false;
		}
		if (order != other.order) {
			return false;
		}
		if (preference != other.preference) {
			return false;
		}
		if (regexp == null) {
			if (other.regexp != null) {
				return false;
			}
		} else if (!regexp.equals(other.regexp)) {
			return false;
		}
		if (replacement == null) {
			if (other.replacement != null) {
				return false;
			}
		} else if (!replacement.equals(other.replacement)) {
			return false;
		}
		if (service == null) {
			if (other.service != null) {
				return false;
			}
		} else if (!service.equals(other.service)) {
			return false;
		}
		return true;
	}
	
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		
		sb.append('[');
		sb.append(super.toString());
		sb.append(' ');
		sb.append("IN NAPTR ");
		sb.append(order);
		sb.append(' ');
		sb.append(preference);
		sb.append(' ');
		sb.append('"');
		sb.append(flags);
		sb.append('"');
		sb.append(' ');
		sb.append('"');
		sb.append(service);
		sb.append('"');
		sb.append(' ');
		sb.append('"');
		sb.append(regexp);
		sb.append('"');
		sb.append(' ');
		sb.append(replacement);
		sb.append(']');
		
		return sb.toString();
	}
}
