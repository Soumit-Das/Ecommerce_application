package com.masai.service;

import java.util.List;

import com.masai.exception.CustomersException;
import com.masai.model.Customers;

public interface CustomerService {

//public Customers registerCustomer(Customers customer);

	public Customers getCustomerDetailsByEmail(String email) throws CustomersException;

	public List<Customers> getAllCustomerDetails() throws CustomersException;

	public Customers registerCustomer(Customers customer) throws CustomersException;

	public Customers getCustomerById(int cid) throws CustomersException;

	public List<Customers> getAllCustomers() throws CustomersException;

	public Customers updateCustomer(int cid, Customers customer) throws CustomersException;

	public Customers deleteCustomer(int cid) throws CustomersException;

//	Testing purpose

	public List<Customers> getCustomerByname(String name) throws CustomersException;

	public Customers searchByEmail(String email) throws CustomersException;

	public Customers searchByPhone(Long phone) throws CustomersException;

}
