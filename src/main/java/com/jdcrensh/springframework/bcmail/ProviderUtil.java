package com.jdcrensh.springframework.bcmail;

import java.security.Provider;
import java.security.Security;

public class ProviderUtil {
	static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	static final String ALGORITHM = "RSA";

	private ProviderUtil() {}

	public static void ensureInstalled(Provider provider) {
		if (Security.getProvider(provider.getName()) == null) {
			Security.addProvider(provider);
		}
	}
}
