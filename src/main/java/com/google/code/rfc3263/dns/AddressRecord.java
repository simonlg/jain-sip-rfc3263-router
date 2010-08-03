package com.google.code.rfc3263.dns;

import java.net.InetAddress;

/**
 * This is the representation of an A or AAAA DNS record.
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc1035.txt">RFC 1035</a>
 * @see <a href="http://www.ietf.org/rfc/rfc3596.txt">RFC 3596</a>
 */
public class AddressRecord extends Record {
	private final InetAddress address;
	
	/**
	 * Creates a new instance of this class given 
	 * 
	 * @param name the name of the node to which this record pertains.
	 * @param address the IPv4 or IPv6 address of a host.
	 */
	public AddressRecord(String name, InetAddress address) {
		super(name);
		this.address = address;
	}
	
	/**
	 * Returns the IPv4 or IPv6 address for this record.
	 * 
	 * @return an IPv4 or IPv6 address.
	 */
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
		
		sb.append(super.toString());
		sb.append("IN A");
		sb.append(address.getHostAddress());
		
		return sb.toString();
	}
}
