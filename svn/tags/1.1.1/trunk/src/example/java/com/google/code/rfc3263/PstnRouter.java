package com.google.code.rfc3263;

import javax.sip.SipException;
import javax.sip.SipStack;
import javax.sip.address.Hop;
import javax.sip.address.TelURL;
import javax.sip.message.Request;

public class PstnRouter extends DefaultRouter {
	public PstnRouter(SipStack sipStack, String outboundProxy) {
		super(sipStack, outboundProxy);
	}

	public Hop getNextHop(Request request) throws SipException {
		if (request.getRequestURI() instanceof TelURL) {
			return new Hop() {
				public String getHost() {
					return "pstn.example.org";
				}

				public int getPort() {
					return 5060;
				}

				public String getTransport() {
					return "UDP";
				}
			};
		} else {
			return super.getNextHop(request);
		}
	}
}
