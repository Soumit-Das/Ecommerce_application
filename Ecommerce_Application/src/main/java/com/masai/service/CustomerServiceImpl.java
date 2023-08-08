package com.masai.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.masai.exception.CustomersException;
import com.masai.model.Customers;
import com.masai.repository.CustomerRepository;

@Service
public class CustomerServiceImpl implements CustomerService {

	@Autowired
	private CustomerRepository customerRepository;

//	@Override
//	public Customers registerCustomer(Customers customer) throws CustomersException {
//		
//		return customerRepository.save(customer);
//		
//		
//	}

	@Override
	public Customers getCustomerDetailsByEmail(String email) throws CustomersException {

		return customerRepository.findByEmail(email)
				.orElseThrow(() -> new CustomersException("Customer Not found with Email: " + email));
	}

	@Override
	public List<Customers> getAllCustomerDetails() throws CustomersException {

		List<Customers> customers = customerRepository.findAll();

		if (customers.isEmpty())
			throw new CustomersException("No Customer find");

		return customers;

	}

	@Override
	public Customers registerCustomer(Customers customer) throws CustomersException {

		if (customerRepository.existsById(customer.getCustomerId())) {
			throw new CustomersException("Customer already exists with id " + customer.getCustomerId());
		}

		return customerRepository.save(customer);
	}

	@Override
	public Customers getCustomerById(int cid) throws CustomersException {

		Optional<Customers> customer = customerRepository.findById(cid);

		if (customer.isEmpty()) {
			throw new CustomersException("Customer doesn't exists with id " + cid);
		}

		return customer.get();
	}

	@Override
	public List<Customers> getAllCustomers() throws CustomersException {

		List<Customers> list = customerRepository.findAll();

		if (list.isEmpty()) {
			throw new CustomersException("No customer found");
		}

		return list;
	}

	@Override
	public Customers updateCustomer(int cid, Customers customer) throws CustomersException {

		Optional<Customers> customers = customerRepository.findById(cid);

		if (customers.isEmpty()) {
			throw new CustomersException("Customer doesn't exists with id " + cid);
		}

		Customers custo = customers.get();

		custo.setName(customer.getName());
		custo.setAge(customer.getAge());
		custo.setEmail(customer.getEmail());
		custo.setPhone(customer.getPhone());
		custo.setPassword(customer.getPassword());
		custo.setConfirm_password(customer.getConfirm_password());

		return customerRepository.save(custo);
	}

	@Override
	public Customers deleteCustomer(int cid) throws CustomersException {

		Optional<Customers> customer = customerRepository.findById(cid);

		if (customer.isEmpty()) {
			throw new CustomersException("No customer exists with id " + cid);
		}

		customerRepository.delete(customer.get());

		return customer.get();
	}

	@Override
	public List<Customers> getCustomerByname(String name) throws CustomersException {

		List<Customers> customer = customerRepository.findByName(name);

		if (customer == null) {
			throw new CustomersException("Customer not found with name " + name);
		}

		return customer;
	}

	@Override
	public Customers searchByEmail(String email) throws CustomersException {

		if (customerRepository.existsByEmail(email)) {
			Optional<Customers> customer = customerRepository.findByEmail(email);
			return customer.get();
		} else {
			throw new CustomersException("Customer doesn't exists with email " + email);
		}

	}

	@Override
	public Customers searchByPhone(Long phone) throws CustomersException {

		if (customerRepository.existsByPhone(phone)) {
			Customers customer = customerRepository.findByPhone(phone);
			return customer;
		} else {
			throw new CustomersException("Customer doesn't exists with phone " + phone);
		}

	}
}
