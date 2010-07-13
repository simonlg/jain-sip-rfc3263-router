package com.google.code.rfc3263;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.sip.ListeningPoint;
import javax.sip.SipFactory;
import javax.sip.SipProvider;
import javax.sip.SipStack;
import javax.sip.address.Address;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.HeaderFactory;
import javax.sip.header.MaxForwardsHeader;
import javax.sip.header.ToHeader;
import javax.sip.header.ViaHeader;
import javax.sip.message.MessageFactory;
import javax.sip.message.Request;

import org.apache.log4j.BasicConfigurator;

public class Register {
	private SipStack stack;
	private MessageFactory messageFactory;
	private HeaderFactory headerFactory;
	private AddressFactory addressFactory;
	private SipProvider phone;

	public void start() throws Exception {
		SipFactory factory = SipFactory.getInstance();
		Properties properties = new Properties();
		properties.put("javax.sip.STACK_NAME", "Example");
		properties.put("javax.sip.ROUTER_PATH", "com.google.code.rfc3263.DefaultRouter");
		stack = factory.createSipStack(properties);
		ListeningPoint udp = stack.createListeningPoint("127.0.0.1", ListeningPoint.PORT_5060, ListeningPoint.UDP);
		phone = stack.createSipProvider(udp);
		addressFactory = factory.createAddressFactory();
		headerFactory = factory.createHeaderFactory();
		messageFactory = factory.createMessageFactory();
		
		stack.start();
	}
	
	public void sendRegister() throws Exception {
		SipURI aliceUri = addressFactory.createSipURI("alice", "atlanta.com");
		Address alice = addressFactory.createAddress("Alice", aliceUri);
		
		SipURI bobUri = addressFactory.createSipURI("bob", "dave-desktop");
		Address bob = addressFactory.createAddress("Bob", bobUri);
		
		FromHeader from = headerFactory.createFromHeader(alice, null);
		ToHeader to = headerFactory.createToHeader(bob, null);
		CSeqHeader cSeq = headerFactory.createCSeqHeader(1L, "INVITE");
		CallIdHeader callId = headerFactory.createCallIdHeader("1234");
		List<ViaHeader> via = new ArrayList<ViaHeader>();
//		via.add(headerFactory.createViaHeader("127.0.0.1", 5060, "UDP", null));
		MaxForwardsHeader maxForwards = headerFactory.createMaxForwardsHeader(70);
		
		Request register = messageFactory.createRequest(bobUri, "INVITE", callId, cSeq, from, to, via, maxForwards);
		phone.sendRequest(register);
	}
	
	public void stop() throws Exception {
		stack.stop();
	}
	
	public static void main(String[] args) throws Exception {
		BasicConfigurator.configure();
		Register reg = new Register();
		
		try {
			reg.start();
			reg.sendRegister();
		} finally {
			reg.stop();
		}
	}
}
