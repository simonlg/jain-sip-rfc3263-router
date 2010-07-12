package com.google.code.rfc3263.dns;

public abstract class Record {
	private final String name;
	
	public Record(String name) {
		this.name = name;
	}
	
	public String getName() {
		return name;
	}
}
