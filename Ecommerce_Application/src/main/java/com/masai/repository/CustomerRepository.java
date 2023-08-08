package com.masai.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.masai.model.Customers;

public interface CustomerRepository extends JpaRepository<Customers, Integer> {

	public Optional<Customers> findByEmail(String email);

	@Query("SELECT c FROM Customers c WHERE c.name = ?1")
	public List<Customers> findByName(String name);

	public boolean existsByEmail(String email);

	public boolean existsByPhone(Long phone);

//	public Customers findByEmail(String email);

	public Customers findByPhone(Long phone);

}