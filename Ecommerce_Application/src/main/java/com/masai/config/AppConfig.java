package com.masai.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class AppConfig {

	@Bean
	public SecurityFilterChain springSecurityConfiguration(HttpSecurity http) throws Exception {

		http.sessionManagement(
				sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

				.cors(cors -> {

					cors.configurationSource(new CorsConfigurationSource() {

						@Override
						public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

							CorsConfiguration cfg = new CorsConfiguration();

							cfg.setAllowedOriginPatterns(Collections.singletonList("*"));
							cfg.setAllowedMethods(Collections.singletonList("*"));
							cfg.setAllowCredentials(true);
							cfg.setAllowedHeaders(Collections.singletonList("*"));
							cfg.setExposedHeaders(Arrays.asList("Authorization"));
							return cfg;

						}
					});

				}).authorizeHttpRequests(auth -> {
				
					auth
					.requestMatchers(HttpMethod.POST, "/registerCustomer").permitAll()
		            .requestMatchers(HttpMethod.GET, "/hello").permitAll()
		            .requestMatchers(HttpMethod.POST, "/Customer/registerCustomer").permitAll()
		            .requestMatchers(HttpMethod.GET, "/Products/getProductById/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Products/getAllProducts").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.POST, "/Products/addProduct").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.POST, "/Address/addAdress").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.POST, "/Category/addCategory").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Category/getAllProductsByCategoryId/**").hasRole("ADMIN") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.PUT, "/Category/updateCategoryById/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.DELETE, "/Category/deleteCategoryById/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Category/getAllCategory").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.POST, "/Feedback/addFeedback").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Feedback/getAllProductsByCategoryId/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.PUT, "/Feedback/updateCategoryById/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.DELETE, "/Feedback/deleteCategoryById/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Feedback/getAllCategory").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.POST, "/Orders/createOrder").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Orders/getOrderById/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.PUT, "/Orders/updateOrders/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.DELETE, "/Orders/deleteOrders/**").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Orders/getAllOrders").hasRole("ADMIN") // ✅
		            .requestMatchers(HttpMethod.GET, "/Address/getAddressByCustomerId/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.PUT, "/Address/updateAddressByCustomerId/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.DELETE, "/Address/deleteAddressByCustomerId/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.POST, "/Cart/addProductToCart/**/**/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.PUT, "/Cart/deleteProductFromCart/{cid}/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.GET, "/Cart/getCartById/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.PUT, "/Cart/updateProductQuantity/**/**/**").hasAnyRole("ADMIN", "USER") // ✅
		            .requestMatchers(HttpMethod.PUT, "/Cart/deleteProductFromCart/{cid}/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		           
		            // ❌ methods to be dubugged
		            
		            .requestMatchers(HttpMethod.GET, "/getCustomerById/**").hasAnyRole("ADMIN", "USER") // ✅ 
		            .requestMatchers(HttpMethod.PUT, "/updateCustomer/**").hasAnyRole("ADMIN", "USER") // ❌ controller method incorrect
		            .requestMatchers(HttpMethod.DELETE, "/deleteCustomer/**").hasAnyRole("ADMIN", "USER") // ✅
		            .requestMatchers(HttpMethod.GET, "/getCustomerByname/**").hasAnyRole("ADMIN", "USER") // ✅
		            .requestMatchers(HttpMethod.GET, "/getAllCustomers").hasAnyRole("ADMIN", "USER") // ✅
		            .requestMatchers(HttpMethod.GET, "/getCustomerByEmail/**").hasAnyRole("ADMIN", "USER") // ✅
		            .requestMatchers(HttpMethod.GET, "/getCustomerByPhone/**").hasAnyRole("ADMIN", "USER") // ✅
		            .anyRequest().authenticated();
				
					
				}).csrf(csrf -> csrf.disable())
				.addFilterAfter(new JwtTokenGeneratorFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(new JwtTokenValidatorFilter(), BasicAuthenticationFilter.class)
				.formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());

		return http.build();

	}

	@Bean
	public PasswordEncoder passwordEncoder() {

		return new BCryptPasswordEncoder();

	}

}
