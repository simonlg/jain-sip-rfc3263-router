package com.google.code.rfc3263;

import java.util.Map;

public interface Resolver {
	Map<String, String> lookupPointers(String target);
}
