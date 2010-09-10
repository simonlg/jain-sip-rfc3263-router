package com.google.code.rfc3263.dns;

import net.jcip.annotations.Immutable;

/**
 * Representation of an abstract DNS record.
 */
@Immutable
public abstract class Record {
	private final String name;
	
	/**
	 * Creates a new instance of this class with the given record name.
	 * 
	 * @param name the name of the node to which this record pertains.
	 */
	protected Record(String name) {
		this.name = name;
	}
	
	/**
	 * Returns the name of the node to which this record pertains.
	 * 
	 * @return the name of the node.
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return name;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof Record)) {
			return false;
		}
		Record other = (Record) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}
}
