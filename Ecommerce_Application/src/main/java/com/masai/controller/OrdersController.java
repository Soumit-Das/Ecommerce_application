package com.masai.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.masai.exception.CategoryException;
import com.masai.exception.OrdersException;
import com.masai.model.Category;
import com.masai.model.Orders;
import com.masai.service.CategoryService;
import com.masai.service.OrdersService;

@RestController
@RequestMapping("/Orders")
public class OrdersController {

	@Autowired
	public OrdersService ordersService;

	@PostMapping("/createOrder")
	public ResponseEntity<Orders> createOrder(@RequestBody Orders order) throws OrdersException {
		Orders cat = ordersService.createOrder(order);
		return new ResponseEntity<>(cat, HttpStatus.CREATED);
	}

	@GetMapping("/getOrderById/{oid}")
	public ResponseEntity<Orders> getOrderById(@PathVariable int oid) throws OrdersException {

		Orders cat = ordersService.getOrderById(oid);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@PutMapping("/updateOrders/{oid}")
	public ResponseEntity<Orders> updateOrders(@PathVariable int oid, @RequestBody Orders orders)
			throws OrdersException {
		Orders cat = ordersService.updateOrders(oid, orders);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@DeleteMapping("/deleteOrders/{oid}")
	public ResponseEntity<Orders> deleteOrders(@PathVariable int oid) throws OrdersException {
		Orders cat = ordersService.deleteOrders(oid);
		return new ResponseEntity<>(cat, HttpStatus.OK);

	}

	@GetMapping("/getAllOrders")
	public ResponseEntity<List<Orders>> getAllOrders() throws OrdersException {
		List<Orders> list = ordersService.getAllOrders();
		return new ResponseEntity<>(list, HttpStatus.OK);
	}

}
