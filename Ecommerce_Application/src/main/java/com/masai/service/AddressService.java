package com.masai.service;

import com.masai.exception.AddressException;
import com.masai.exception.CustomersException;
import com.masai.model.Address;

public interface AddressService {

	public Address addAddress(Address address) throws AddressException;

	public Address getAddressByCustomerId(int cid) throws AddressException, CustomersException;

	public Address updateAddressByCustomerId(int cid, Address address) throws AddressException, CustomersException;

	public Address deleteAddressByCustomerId(int cid) throws AddressException, CustomersException;

}
