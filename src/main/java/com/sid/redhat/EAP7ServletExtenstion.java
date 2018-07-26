/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sid.redhat;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import javax.servlet.ServletContext;

/**
 *
 * @author sidde
 */
public class EAP7ServletExtenstion implements ServletExtension {
    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {

        deploymentInfo.addAuthenticationMechanism("TEST", new NewAuthenticator.CustomFactory());
    }
    
}
