/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sid.redhat;

import java.security.Principal;
import java.security.acl.Group;
import javax.security.auth.login.LoginException;
import org.jboss.logging.Logger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;


/**
 *
 * @author sidde
 */
public class NewLogin extends UsernamePasswordLoginModule{
    private static Logger log = Logger.getLogger(NewLogin.class);
    private SimplePrincipal user;
    
    @Override
    protected Principal getIdentity() {
      Principal principal = user;
      if( principal == null ){
          log.info("Principal before setting explicitly: "+principal);
          principal = super.getIdentity();
      }
      log.info("Principal before return: "+principal);
      return principal;
     }
    @Override
    protected boolean validatePassword(String password, String username){
        if(username != null && password != null && username.length() > 1 && password.length() > 1){
            //log.info("Username: "+username+"; Password: "+password);
            return true;
        }
        return false;
    }
    
    @Override
    protected String getUsersPassword() throws LoginException {
        log.info(this.getUsername());
        return this.getUsername();
    }

    @Override
    protected Group[] getRoleSets() throws LoginException {
        Group[] roleSets = {new SimpleGroup("Roles")};
        roleSets[0].addMember(new SimplePrincipal("JBossAdmin"));
        log.info(roleSets[0]);
        return roleSets;
    }
    
}
