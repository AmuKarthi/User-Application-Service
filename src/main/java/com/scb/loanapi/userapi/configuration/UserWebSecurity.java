package com.scb.loanapi.userapi.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.scb.loanapi.userapi.service.LoanUserService;

@Configuration
@CrossOrigin
@EnableWebSecurity
public class UserWebSecurity extends WebSecurityConfigurerAdapter{
	
	Logger logger=LoggerFactory.getLogger(UserWebSecurity.class);
	@Autowired
	private Environment env;
	
	@Autowired
	private LoanUserService loanUserService;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	//Constructor injection
	/*
	 * @Autowired public UserApiWebSecurity(Environment environment, LoanUserService
	 * loanUserService, BCryptPasswordEncoder bCryptPasswordEncoder) { this.env =
	 * environment; this.loanUserService = loanUserService;
	 * this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	 * 
	 * }
	 */
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		auth.userDetailsService(loanUserService).passwordEncoder(bCryptPasswordEncoder);
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		logger.info("gatewayIP from env----->"+env.getProperty("gateway.ip"));
		//http.hasIpAddress(env.getProperty("gateway.ip")).and()
		http.authorizeRequests().antMatchers(env.getProperty("login.url.path")).
		permitAll().and()
		.addFilter(getAuthenticationFilter());
		//http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
		http.headers().frameOptions().disable();
	}


	private AuthenticationFilter getAuthenticationFilter() throws Exception {
		AuthenticationFilter authenticationFilter=new AuthenticationFilter();
		// AuthenticationFilter(loanUserService,env,authenticationManagerBean());
		//authenticationFilter.setAuthenticationManager(authenticationManager());
		logger.info("login.url.path --->"+env.getProperty("login.url.path"));
		authenticationFilter.setAuthenticationManager(authenticationManagerBean());
		authenticationFilter.setFilterProcessesUrl(env.getProperty("login.url.path"));
		return authenticationFilter;
	}
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
	    return super.authenticationManagerBean();
	}
	
	
	
}
