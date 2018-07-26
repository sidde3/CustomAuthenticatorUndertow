/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sid.redhat;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.security.idm.PasswordCredential;
import static io.undertow.security.impl.GenericHeaderAuthenticationMechanism.IDENTITY_HEADER;
import io.undertow.util.HeaderValues;
import org.jboss.logging.Logger;
import java.util.Map;
import java.util.Optional;

/*
 * @author sidde
 */
public class NewAuthenticator implements AuthenticationMechanism {

   protected Logger logger = Logger.getLogger(NewAuthenticator.class);
   private IdentityManager identityManager;
   private String name;

   public NewAuthenticator(String name, IdentityManager identityManager) {
	this.identityManager = identityManager;
	this.name = name;
   }

   @Override
   public AuthenticationMechanismOutcome authenticate(HttpServerExchange hse, SecurityContext sc) {
	logger.info("Authentication is in process ....");
	AuthenticationMechanismOutcome result = AuthenticationMechanismOutcome.NOT_AUTHENTICATED;

	String username = getUsername(hse);
	String password = getPassword(hse);
	if (username != null && password != null) {
	   PasswordCredential credential = new PasswordCredential(password.toCharArray());
	   identityManager = (IdentityManager) sc.getIdentityManager();
	   Account account = identityManager.verify(username, credential);
	   logger.info("validating credentials...");
	   if (account != null) {
		result = AuthenticationMechanismOutcome.AUTHENTICATED;
		logger.info("Authentication Seccessful...");
	   }
	}

	return result;
   }

   @Override
   public ChallengeResult sendChallenge(HttpServerExchange hse, SecurityContext sc) {
	throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
   }

   private String getUsername(HttpServerExchange hse) {
	String username = null;
	HeaderValues userValues = hse.getRequestHeaders().get("x-username");
	if (userValues != null && !userValues.isEmpty()) {
	   Optional<String> userString = userValues.stream().findFirst();
	   if (userString.isPresent()) {
		username = userString.get();
	   }
	}
	return username;
   }

   private String getPassword(HttpServerExchange hse) {
	String password = null;
	HeaderValues userValues = hse.getRequestHeaders().get("x-password");
	if (userValues != null && !userValues.isEmpty()) {
	   Optional<String> userString = userValues.stream().findFirst();
	   if (userString.isPresent()) {
		password = userString.get();
	   }
	}
	return password;
   }

   public static class CustomFactory implements AuthenticationMechanismFactory {

	@Override
	public AuthenticationMechanism create(String mechanismName, FormParserFactory fpf, Map<String, String> map) {
	   String identity = map.get(IDENTITY_HEADER);
	   if (identity == null) {
		System.out.println("No identity manager found during initialization");
	   }
	   return new NewAuthenticator(mechanismName, null);
	}
   }

}
