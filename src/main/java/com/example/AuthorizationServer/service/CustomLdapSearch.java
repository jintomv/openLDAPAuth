package com.example.AuthorizationServer.service;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.stereotype.Component;

@Component
public class CustomLdapSearch implements LdapUserSearch{

	public static final String SAM_FILTER="(&(sAMAccountName={0})(objectclass=user))";

		    final LdapUserSearch users;
		    //final LdapUserSearch staff;

		    public CustomLdapSearch(BaseLdapPathContextSource contextSource) {
		        users = new FilterBasedLdapUserSearch("CN=Users,DC=my-domain,DC=com", SAM_FILTER, contextSource);
		       // staff = new FilterBasedLdapUserSearch("CN=Staff,DC=my-domain,DC=com", SAM_FILTER, contextSource);

		    }

		    public DirContextOperations searchForUser(String username) {
		        try {
		            return users.searchForUser(username);
		        } catch(UsernameNotFoundException e) {
		           // return staff.searchForUser(username);
		        }
				return null;
		    }
}
