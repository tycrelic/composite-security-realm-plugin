# Composite Security Realm plugin

A workaround of missing multiple security realm feature for Jenkins.
It is in prototype stage and tested with some limited combinations of component security realms (Jenkins' own user database, LDAP, Unix user/group database) for Jenkin web UI login.
Functions of component security realms other than authentication may not work, see To Do.


## Building the Plugin

```bash
# cd to the repo folder and run
mvn clean install
```

## To Do

* Correct the logic of CompositeRememberMeServices so that it calls the methods of component security realm in effect instead of all component security realms.
* Try to make the extra functions other than authentication of some known security realms work when they are added as the component security realms, for instance, Manage users of Jenkins' Own User Database, Test LDAP settings of LDAP Plugin, etc., if it is ever possible...
* Examine if this plugin works / can be modified to work with non-password-based security realms, REST API, etc.
* Add tests.
