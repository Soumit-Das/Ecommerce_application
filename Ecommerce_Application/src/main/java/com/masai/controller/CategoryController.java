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

import com.masai.exception.AddressException;
import com.masai.exception.CategoryException;
import com.masai.exception.CustomersException;
import com.masai.model.Address;
import com.masai.model.Cart;
import com.masai.model.Category;
import com.masai.service.AddressService;
import com.masai.service.CategoryService;

@RestController
@RequestMapping("/Category")
public class CategoryController {

	@Autowired
	public CategoryService categoryService;

	@PostMapping("/addCategory")
	public ResponseEntity<Category> addCategory(@RequestBody Category category) throws CategoryException {
		Category cat = categoryService.addCategory(category);
		return new ResponseEntity<>(cat, HttpStatus.CREATED);
	}

	@GetMapping("/getAllProductsByCategoryId/{catid}")
	public ResponseEntity<Category> getAllProductsByCategoryId(@PathVariable int catid) throws CategoryException {

		Category cat = categoryService.getAllProductsByCategoryId(catid);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@PutMapping("/updateCategoryById/{catId}")
	public ResponseEntity<Category> updateCategoryById(@PathVariable int catId, @RequestBody Category category)
			throws CategoryException {
		Category cat = categoryService.updateCategoryById(catId, category);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@DeleteMapping("/deleteCategoryById/{catId}")
	public ResponseEntity<Category> deleteCategoryById(@PathVariable int catId) throws CategoryException {
		Category cat = categoryService.deleteCategoryById(catId);
		return new ResponseEntity<>(cat, HttpStatus.OK);

	}

	@GetMapping("/getAllCategory")
	public ResponseEntity<List<Category>> getAllCategory() throws CategoryException {
		List<Category> list = categoryService.getAllCategory();
		return new ResponseEntity<>(list, HttpStatus.OK);
	}

}
