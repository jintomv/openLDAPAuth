package com.example.AuthorizationServer.service;

import java.util.Optional;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.data.ldap.repository.Query;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.query.SearchScope;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.stereotype.Service;

import com.example.AuthorizationServer.models.MyUserDetails;
import com.example.AuthorizationServer.models.User;
import com.example.AuthorizationServer.repository.UserRepository;

@Service
public class MyUserDetailsService implements UserDetailsService {


	@Value("${ldap.enabled}")
	private String ldapEnabled;
	
	@Value("${ldap.urls}")
    private String ldapUrls;

    @Value("${ldap.base.dn}")
    private String ldapBaseDn;

    @Value("${ldap.username}")
    private String ldapSecurityPrincipal;

    @Value("${ldap.password}")
    private String ldapPrincipalPassword;

    @Value("${ldap.user.dn.pattern}")
    private String ldapUserDnPattern;
    
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	CustomLdapSearch userSearch;
	
//	@Autowired
//	private LdapTemplate ldapTemplate;
	
//	@Autowired
//	LdapServiceDetails ldapService;
//	
//	public LdapTemplate getLdapTemplate() {
//		return ldapTemplate;
//	}
//
//
//	public void setLdapTemplate(LdapTemplate ldapTemplate) {
//		this.ldapTemplate = ldapTemplate;
//	}


//	@Autowired
//	LdapRepository ldapRepository;
	
	//final Integer THREE_SECONDS = 3000;
	
//	@Autowired
//	LdapUserService ldapService;
	

	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		
		LdapUserService ldapService = new LdapUserService(userSearch);
		UserDetails loadUserByUsername = ldapService.loadUserByUsername(userName);
		
//		UserDetails loadUserByUsername = ldapService.setUserDetailsMapper(userDetailsMapper);
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		Object principal = authentication.getPrincipal();
//		LdapQuery query = LdapQueryBuilder
//				.query()
//                .searchScope(SearchScope.SUBTREE)
//                .timeLimit(THREE_SECONDS)
//                .countLimit(10)
//                .attributes("cn")
//                .base(ldapBaseDn)
//                .where("objectclass").is("person")
//                //.attributes(identifierAttribute, "givenname", "sn", "mail")
//                //.and("sn").not().is(lastName)
//                //.and("sn").like("j*hn")
//                .and("uid").like(userName);
//		ldapTemplate.find(query, User.class);
//		
//		ldapTemplate.search(query, new AttributesMapper<String>() {
//
//			@Override
//			public String mapFromAttributes(Attributes attributes) throws NamingException {
//				return attributes.get("cn").get().toString();
//			}
//		});
		
		//User findOne = ldapRepository.findOne(query);
		
		//ldapTemplate.findOne(query, clazz)

		Optional<User> user = userRepository.findByUserName(userName);

		try {
			user.orElseThrow(() -> new UsernameNotFoundException("Not found: " + userName));

		} catch (Exception e) {
			System.out.println("userName Not found" + e);
		}
		return user.map(MyUserDetails::new).get();
	}
	

}
