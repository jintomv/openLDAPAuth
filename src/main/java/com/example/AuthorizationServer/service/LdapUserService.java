package com.example.AuthorizationServer.service;

import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class LdapUserService extends LdapUserDetailsService {

	public LdapUserService(LdapUserSearch userSearch) {
		super(userSearch);
	}

}
