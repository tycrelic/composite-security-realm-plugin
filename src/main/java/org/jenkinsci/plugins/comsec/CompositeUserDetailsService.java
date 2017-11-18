package org.jenkinsci.plugins.comsec;

import hudson.security.SecurityRealm;
import java.util.List;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

public class CompositeUserDetailsService implements UserDetailsService {

  List<SecurityRealm> securityRealms;

  public CompositeUserDetailsService(List<SecurityRealm> securityRealms) {
    this.securityRealms = securityRealms;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
    Exception lastException = null;
    for (SecurityRealm securityRealm : securityRealms) {
      SecurityRealm.SecurityComponents securityComponents = securityRealm.createSecurityComponents();
      try {
        return securityComponents.userDetails.loadUserByUsername(username);
      } catch (UsernameNotFoundException | DataAccessException ex) {
        lastException = ex;
      }
    }
    throw lastException instanceof UsernameNotFoundException ? (UsernameNotFoundException) lastException : (DataAccessException) lastException;
  }

}
