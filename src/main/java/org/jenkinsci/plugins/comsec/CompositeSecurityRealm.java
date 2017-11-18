package org.jenkinsci.plugins.comsec;

import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

public class CompositeSecurityRealm extends AbstractPasswordBasedSecurityRealm {

  private List<SecurityRealm> securityRealms;

  @DataBoundConstructor
  public CompositeSecurityRealm(List<SecurityRealm> securityRealms) {
    this.securityRealms = securityRealms;
  }

  @Override
  protected UserDetails authenticate(String username, String password) throws AuthenticationException {
    for (SecurityRealm securityRealm : securityRealms) {
      UserDetails ud = null;
      try {
        ud = securityRealm.loadUserByUsername(username);
      } catch (UsernameNotFoundException | DataAccessException ex) {
      }

      if (ud != null && securityRealm instanceof AbstractPasswordBasedSecurityRealm) {
        Method method;
        try {
          method = AbstractPasswordBasedSecurityRealm.class.getMethod("authenticate", String.class, String.class);
          method.setAccessible(true);
          return (UserDetails) method.invoke((AbstractPasswordBasedSecurityRealm) securityRealm);
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
          throw new BadCredentialsException("Reflection method call failed in the composite security realm", ex);
        }
      }
    }

    throw new BadCredentialsException("No instance of AbstractPasswordBasedSecurityRealm can authenticate the user in the composite security realm");
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
    Exception lastException = null;
    for (SecurityRealm securityRealm : securityRealms) {
      try {
        return securityRealm.loadUserByUsername(username);
      } catch (UsernameNotFoundException | DataAccessException ex) {
        lastException = ex;
      }
    }
    throw lastException instanceof UsernameNotFoundException ? (UsernameNotFoundException) lastException : (DataAccessException) lastException;
  }

  @Override
  public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
    Exception lastException = null;
    for (SecurityRealm securityRealm : securityRealms) {
      try {
        return securityRealm.loadGroupByGroupname(groupname);
      } catch (UsernameNotFoundException | DataAccessException ex) {
        lastException = ex;
      }
    }
    throw lastException instanceof UsernameNotFoundException ? (UsernameNotFoundException) lastException : (DataAccessException) lastException;
  }

  @Override
  public SecurityComponents createSecurityComponents() {
    return new SecurityComponents(new CompositeAuthenticationManager(securityRealms), new CompositeUserDetailsService(securityRealms), new CompositeRememberMeServices(securityRealms));
  }
  
  /**
   * @return the securityRealms
   */
  public List<SecurityRealm> getSecurityRealms() {
    return securityRealms;
  }

  @Extension
  public static class DescriptorImpl extends Descriptor<SecurityRealm> {

    @Override
    public String getDisplayName() {
      return "Composite Security Realm";
    }

    public List<Descriptor<SecurityRealm>> getSecurityRealmDescriptors() {
      //DescriptorExtensionList<SecurityRealm, Descriptor<SecurityRealm>> del = SecurityRealm.all();
      return SecurityRealm.all();
    }
  }

}
