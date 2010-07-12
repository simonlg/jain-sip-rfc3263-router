package com.google.code.rfc3263.dns;

import java.net.InetAddress;

public class AddressRecord extends Record {
	private final InetAddress address;
	
	public AddressRecord(String name, InetAddress address) {
		super(name);
		this.address = address;
	}
	
	public InetAddress getAddress() {
		 return address;
	}
}
