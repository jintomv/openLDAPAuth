package com.example.AuthorizationServer.config;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.ldap.repository.config.EnableLdapRepositories;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.example.AuthorizationServer.service.MyUserDetailsService;


@Configuration
@EnableWebSecurity

public class UserConfig extends WebSecurityConfigurerAdapter{
	
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
	MyUserDetailsService userDetailsService;
	
	@Autowired
	BCryptPasswordEncoder passwordEncoder;
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			//.addFilterAfter(switchUserFilter(), FilterSecurityInterceptor.class)
			.addFilter(corsFilter())
			.authorizeRequests()
				.mvcMatchers("/save").permitAll()
				.mvcMatchers("/switchUser").access("hasAnyRole('ADMIN', 'ROLE_PREVIOUS_ADMINISTRATOR')")
				.mvcMatchers("/.well-known/jwks.json").permitAll()
				.anyRequest().authenticated()
				.and()
			.httpBasic()
				.and()
			.csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()));
	}

	
	
	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		if(Boolean.parseBoolean(ldapEnabled))
		{
			auth.ldapAuthentication()
			//.userDetailsContextMapper(userDetailsContextMapper())
	        .userDnPatterns(ldapUserDnPattern)
	        .userSearchBase("ou=sales")
	        .userSearchFilter("uid={0}")
	        .groupSearchBase("ou=sales")
	        //.groupSearchFilter("uniqueMember={0}")
	        .contextSource()
	        .url(ldapUrls+ldapBaseDn)
	        .managerDn(ldapSecurityPrincipal)
	        .managerPassword(ldapPrincipalPassword)
	        .and()
	        .passwordCompare()
	        .passwordEncoder(new LdapShaPasswordEncoder())
	        .passwordAttribute("userPassword");
	        //.and()
	        //.ldapAuthoritiesPopulator(myAuthPopulator);
			
		}
		else {
			//auth.authenticationProvider(authenticationProvider());
			auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
		}
    }

//	@Bean
//	public PasswordEncoder passwordEncoder() {
//	    return new BCryptPasswordEncoder();
//	}
	
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.addAllowedOrigin("*");
		config.addAllowedHeader("*");
		config.addAllowedMethod("*");
		source.registerCorsConfiguration("/**", config);
		return new CorsFilter(source);
	}
	
//	@Bean
//    public UserDetailsContextMapper userDetailsContextMapper() {
//        return new LdapUserDetailsMapper() {
//            @Override
//            public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
//                UserDetails details = super.mapUserFromContext(ctx, username, authorities);
//                return new CustomLdapUserDetails((LdapUserDetails) details, env);
//            }
//        };
//    }
	
//	@Bean
//    public DaoAuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        authenticationProvider.setUserDetailsService(userDetailsService);
//        authenticationProvider.setPasswordEncoder(passwordEncoder);
//        return authenticationProvider;
//    }
}
