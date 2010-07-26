package com.google.code.rfc3263.dns;

import java.net.InetAddress;

/**
 * This is the representation of either an A or AAAA DNS record.
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc1034.txt">RFC 1034</a>
 * @see <a href="http://www.ietf.org/rfc/rfc3596.txt">RFC 3596</a>
 */
public class AddressRecord extends Record {
	private final InetAddress address;
	
	public AddressRecord(String name, InetAddress address) {
		super(name);
		this.address = address;
	}
	
	public InetAddress getAddress() {
		 return address;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((address == null) ? 0 : address.hashCode());
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
		if (!(obj instanceof AddressRecord)) {
			return false;
		}
		AddressRecord other = (AddressRecord) obj;
		if (address == null) {
			if (other.address != null) {
				return false;
			}
		} else if (!address.equals(other.address)) {
			return false;
		}
		return true;
	}

	public String toString() {
		StringBuffer sb = new StringBuffer();
		
		sb.append('[');
		sb.append("IN A ");
		sb.append(address);
		sb.append(']');
		
		return sb.toString();
	}
}
