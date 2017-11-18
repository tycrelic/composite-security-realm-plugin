package org.jenkinsci.plugins.comsec;

import hudson.security.SecurityRealm;
import hudson.security.SecurityRealm.SecurityComponents;
import java.util.List;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.LockedException;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

public class CompositeAuthenticationManager implements AuthenticationManager {

  List<SecurityRealm> securityRealms;

  public CompositeAuthenticationManager(List<SecurityRealm> securityRealms) {
    this.securityRealms = securityRealms;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    for (SecurityRealm securityRealm : securityRealms) {
      SecurityComponents securityComponents = securityRealm.createSecurityComponents();
      
      //try to check if a user exists in a security realm
      try {
        securityComponents.userDetails.loadUserByUsername(username);
      } catch (UsernameNotFoundException | DataAccessException ex) {
        continue;
      }

      return securityComponents.manager.authenticate(authentication);
    }

    throw new BadCredentialsException("No component security realm can authenticate the user " + username);
  }

}
