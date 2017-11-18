package org.jenkinsci.plugins.comsec;

import hudson.security.SecurityRealm;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.acegisecurity.Authentication;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.ui.rememberme.RememberMeServices;

public class CompositeRememberMeServices implements RememberMeServices {

  List<SecurityRealm> securityRealms;

  public CompositeRememberMeServices(List<SecurityRealm> securityRealms) {
    this.securityRealms = securityRealms;
  }
  
  @Override
  public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
    for (SecurityRealm securityRealm : securityRealms) {
      SecurityRealm.SecurityComponents securityComponents = securityRealm.createSecurityComponents();
      return securityComponents.rememberMe.autoLogin(request, response);
    }
    return null;
  }

  @Override
  public void loginFail(HttpServletRequest request, HttpServletResponse response) {
    for (SecurityRealm securityRealm : securityRealms) {
      SecurityRealm.SecurityComponents securityComponents = securityRealm.createSecurityComponents();
      securityComponents.rememberMe.loginFail(request, response);
    }
  }

  @Override
  public void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
    for (SecurityRealm securityRealm : securityRealms) {
      SecurityRealm.SecurityComponents securityComponents = securityRealm.createSecurityComponents();
      securityComponents.rememberMe.loginSuccess(request, response, successfulAuthentication);
    }
  }

}
