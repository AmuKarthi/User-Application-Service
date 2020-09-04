package com.scb.loanapi.userapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient 
public class UserLoanManagementServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserLoanManagementServiceApplication.class, args);
	}

}
