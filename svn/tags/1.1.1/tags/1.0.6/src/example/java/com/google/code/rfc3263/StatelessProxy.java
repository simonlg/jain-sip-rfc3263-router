package com.google.code.rfc3263;

import java.util.Date;
import java.util.Properties;
import java.util.TooManyListenersException;

import javax.sip.DialogTerminatedEvent;
import javax.sip.IOExceptionEvent;
import javax.sip.InvalidArgumentException;
import javax.sip.ListeningPoint;
import javax.sip.ObjectInUseException;
import javax.sip.RequestEvent;
import javax.sip.ResponseEvent;
import javax.sip.SipException;
import javax.sip.SipFactory;
import javax.sip.SipListener;
import javax.sip.SipProvider;
import javax.sip.SipStack;
import javax.sip.TimeoutEvent;
import javax.sip.TransactionTerminatedEvent;
import javax.sip.TransportAlreadySupportedException;
import javax.sip.TransportNotSupportedException;
import javax.sip.message.Request;
import javax.sip.message.Response;

import org.apache.log4j.BasicConfigurator;

public class StatelessProxy implements SipListener, Runnable {
	private final SipStack sipStack;
	private ListeningPoint udp;
	private ListeningPoint tcp;
	private SipProvider provider;
	
	public StatelessProxy(SipStack sipStack) {
		this.sipStack = sipStack;
	}
	
	public void configure() throws TransportNotSupportedException, InvalidArgumentException, ObjectInUseException, TransportAlreadySupportedException, TooManyListenersException {
		udp = sipStack.createListeningPoint("0.0.0.0", ListeningPoint.PORT_5060, ListeningPoint.UDP);
		tcp = sipStack.createListeningPoint("0.0.0.0", ListeningPoint.PORT_5060, ListeningPoint.TCP);
		
		provider = sipStack.createSipProvider(udp);
		provider.addListeningPoint(tcp);
		
		provider.addSipListener(this);
	}

	public void processDialogTerminated(DialogTerminatedEvent event) {
		System.out.println(event);
	}

	public void processIOException(IOExceptionEvent event) {
		System.out.println(event);
	}

	public void processRequest(RequestEvent event) {
		Request req = event.getRequest();
		System.out.println(new Date());
		System.out.println(req);
		try {
			provider.sendRequest(req);
		} catch (SipException e) {
			e.printStackTrace();
		}
	}

	public void processResponse(ResponseEvent event) {
		final Response res = event.getResponse();
		System.out.println(new Date());
		System.out.println(res);
		try {
			provider.sendResponse(res);
		} catch (SipException e) {
			e.printStackTrace();
		}
	}

	public void processTimeout(TimeoutEvent event) {
		System.out.println(event);
	}

	public void processTransactionTerminated(TransactionTerminatedEvent event) {
		System.out.println(event);
	}
	
	public void run() {
		try {
			sipStack.start();
		} catch (SipException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws Exception {
		BasicConfigurator.configure();
		
		final Properties properties = new Properties();
		properties.setProperty("javax.sip.ROUTER_PATH", "com.google.code.rfc3263.DefaultRouter");
		properties.setProperty("javax.sip.STACK_NAME", "StatelessProxy");
		
		SipFactory factory = SipFactory.getInstance();
		SipStack sipStack = factory.createSipStack(properties);
		
		StatelessProxy proxy = new StatelessProxy(sipStack);
		proxy.configure();
		
		Thread t = new Thread(proxy);
		t.start();
	}
}
