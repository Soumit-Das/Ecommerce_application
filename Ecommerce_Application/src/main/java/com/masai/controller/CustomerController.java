package com.masai.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.masai.exception.CustomersException;
import com.masai.model.Customers;
import com.masai.repository.CustomerRepository;
import com.masai.service.CustomerService;

@RestController
public class CustomerController {

	@Autowired
	private CustomerService customerService;

	@Autowired
	private CustomerRepository customerRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@GetMapping("/hello")
	public String testHandler() {
		return "Welcome to Spring Security";
	}

	/*
	 * 
	 * { "name":"Charles Leclerc", "age":20, "gender":"MALE",
	 * "email":"leclerc1234@gmail.com", "password":"Purosangue@50",
	 * "confirm_password":"Purosangue@50", "phone":1234567890,
	 * "DateofBirth":"22-04-2006", "role":"admin" }
	 * 
	 * 
	 * 
	 * 
	 * 
	 */

	// add another Customer with only the role "user"

//	@PostMapping("/addCustomers")
//	public ResponseEntity<Customers> saveCustomerHandler(@RequestBody Customers customer){
//		
//		customer.setPassword(passwordEncoder.encode(customer.getPassword()));
//		
//		customer.setRole("ROLE_"+customer.getRole().toUpperCase());
//		
//		
//		Customers registeredCustomer= customerService.registerCustomer(customer);
//		
//		return new ResponseEntity<>(registeredCustomer,HttpStatus.ACCEPTED);
//		
//	}

//	@GetMapping("/customers/{email}")
//	public ResponseEntity<Customers> getCustomerByEmailHandler(@PathVariable("email") String email) {
//
//		Customers customer = customerService.getCustomerDetailsByEmail(email);
//
//		return new ResponseEntity<>(customer, HttpStatus.ACCEPTED);
//
//	}
//
//	@GetMapping("/customers")
//	public ResponseEntity<List<Customers>> getAllCustomerHandler() {
//
//		List<Customers> customers = customerService.getAllCustomerDetails();
//
//		return new ResponseEntity<>(customers, HttpStatus.ACCEPTED);
//
//	}

//	@GetMapping("/signIn")
//	public ResponseEntity<String> getLoggedInCustomerDetailsHandler(Authentication auth) {
//
//		System.out.println(auth); // this Authentication object having Principle object details
//
//		Customers customer = customerService.getCustomerDetailsByEmail(auth.getName());
//
//		return new ResponseEntity<>(customer.getName() + " Logged In Successfully", HttpStatus.ACCEPTED);
//	}

	@GetMapping("/signIn")
	public ResponseEntity<String> getLoggedInCustomerDetailsHandler(Authentication auth) throws CustomersException {
		System.out.println(auth); // this Authentication object having Principle object details
//	Customer customer = customerService.getCustomerDetailsByEmail(auth.getName());
		Optional<Customers> customer = customerRepository.findByEmail(auth.getName());
		System.out.println(customer);
		return new ResponseEntity<>(customer.get().getName() + " Logged In Successfully", HttpStatus.ACCEPTED);
	}

	@PostMapping("/registerCustomer") // ✅ Working
	public ResponseEntity<Customers> registerCustomer(@RequestBody Customers customer) throws CustomersException {

		customer.setPassword(passwordEncoder.encode(customer.getPassword()));

		customer.setRole("ROLE_" + customer.getRole().toUpperCase());

		Customers cat = customerService.registerCustomer(customer);

		return new ResponseEntity<>(cat, HttpStatus.CREATED);
	}

	@GetMapping("/getCustomerById/{cid}") // ✅ Working
	public ResponseEntity<Customers> getCustomerById(@PathVariable int cid) throws CustomersException {

		Customers cat = customerService.getCustomerById(cid);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@PutMapping("/updateCustomer/{cid}") // ✅ Working
	public ResponseEntity<Customers> updateCustomer(@PathVariable int cid, @RequestBody Customers customer)
			throws CustomersException {
		Customers cat = customerService.updateCustomer(cid, customer);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@DeleteMapping("/deleteCustomer/{cid}")
	public ResponseEntity<Customers> deleteCustomer(@PathVariable int cid) throws CustomersException {
		Customers cat = customerService.deleteCustomer(cid);
		return new ResponseEntity<>(cat, HttpStatus.OK);

	}

	@GetMapping("/getCustomerByname/{name}")
	public ResponseEntity<List<Customers>> getCustomerByname(@PathVariable String name) throws CustomersException {

		List<Customers> cat = customerService.getCustomerByname(name);
		return new ResponseEntity<>(cat, HttpStatus.OK);

	}

	@GetMapping("/getAllCustomers")
	public ResponseEntity<List<Customers>> getAllCustomers() throws CustomersException {
		List<Customers> list = customerService.getAllCustomers();
		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	@GetMapping("/getCustomerByEmail/{email}")
	public ResponseEntity<Customers> getCustomerByEmail(@PathVariable String email) throws CustomersException {

		Customers cat = customerService.searchByEmail(email);

		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@GetMapping("/getCustomerByPhone/{phone}")
	public ResponseEntity<Customers> getCustomerByPhone(@PathVariable Long phone) throws CustomersException {

		Customers cat = customerService.searchByPhone(phone);

		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

}
