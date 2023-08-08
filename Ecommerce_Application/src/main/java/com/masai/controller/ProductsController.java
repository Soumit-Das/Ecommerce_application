package com.masai.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.masai.exception.CategoryException;
import com.masai.exception.ProductsException;
import com.masai.model.Category;
import com.masai.model.Products;
import com.masai.service.CategoryService;
import com.masai.service.ProductsService;

@RestController
@RequestMapping("/Products")
public class ProductsController {

	@Autowired
	public ProductsService productsService;

//	@PostMapping("/addProduct")
//	public ResponseEntity<Products> addProduct(@ModelAttribute Products product)throws ProductsException{
//		Products cat = productsService.addProduct(product);
//		return new ResponseEntity<>(cat,HttpStatus.CREATED);
//	}

	@PostMapping("/addProduct")
	public ResponseEntity<Products> addProduct(@RequestBody Products product) throws ProductsException {

		Products newProduct = productsService.addProduct(product);
		return new ResponseEntity<>(newProduct, HttpStatus.CREATED);
	}

	@GetMapping("/getProductById/{prodId}")
	public ResponseEntity<Products> getProductById(@PathVariable int prodId) throws ProductsException {

		Products cat = productsService.getProductById(prodId);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@PutMapping("/updateProduct/{prodId}")
	public ResponseEntity<Products> updateProduct(@PathVariable int prodId, @RequestBody Products products)
			throws ProductsException {
		Products cat = productsService.updateProduct(prodId, products);
		return new ResponseEntity<>(cat, HttpStatus.OK);
	}

	@DeleteMapping("/deleteProduct/{prodId}")
	public ResponseEntity<Products> deleteProduct(@PathVariable int prodId) throws ProductsException {
		Products cat = productsService.deleteProduct(prodId);
		return new ResponseEntity<>(cat, HttpStatus.OK);

	}

	@GetMapping("/getAllProducts")
	public ResponseEntity<List<Products>> getAllProducts() throws ProductsException {
		List<Products> list = productsService.getAllProducts();
		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	@GetMapping("/searchByName/{productName}")
	public ResponseEntity<List<Products>> searchByName(@PathVariable String productName) throws ProductsException {

		List<Products> list = productsService.searchByName(productName);

		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	@GetMapping("/searchByBrand/{productBrand}")
	public ResponseEntity<List<Products>> searchByBrand(@PathVariable String productBrand) throws ProductsException {

		List<Products> list = productsService.searchByBrand(productBrand);

		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	@GetMapping("/searchByType/{productType}")
	public ResponseEntity<List<Products>> searchByType(@PathVariable String productType) throws ProductsException {

		List<Products> list = productsService.searchByType(productType);

		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	@GetMapping("/searchByRating/{rating}") // It will be done by Pagination and sorting method
	public ResponseEntity<List<Products>> searchByRating(@PathVariable double rating) throws ProductsException {

		List<Products> list = productsService.searchByRating(rating);

		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	@GetMapping("/searchByisAvailable/{isAvailable}")
	public ResponseEntity<List<Products>> searchByisAvailable(@PathVariable boolean isAvailable)
			throws ProductsException {

		List<Products> list = productsService.searchByisAvailable(isAvailable);

		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	// Pagination and Sorting methods

	@GetMapping("/sortProducts/{field}")
	public ResponseEntity<List<Products>> getSortedProductsListWithField(@PathVariable String field,
			@RequestParam String direction) {

		List<Products> list = productsService.getSortedProductsListWithField(field, direction);

		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	@GetMapping("/sortProductsByType/{Type}/{field}")
	public ResponseEntity<List<Products>> getSortedProductsTypeListWithField(@PathVariable String field,
			@RequestParam String direction, @PathVariable String Type) {

		List<Products> list = productsService.getSortedProductsTypeListWithField(field, direction, Type);

		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	// This method get the list of products of a specific type pagewise
	// http://localhost:8888/Products/getProductsTypeListPageWise/Men's
	// Casual/2?NumberofRecords=16

	@GetMapping("/getProductsTypeListPageWise/{Type}/{pageNumber}")
	public ResponseEntity<List<Products>> getProductsTypeListPageWise(@PathVariable Integer pageNumber,
			@RequestParam Integer NumberofRecords, @PathVariable String Type) {

		List<Products> list = productsService.getProductsTypeListPageWise(pageNumber, NumberofRecords, Type);

		return new ResponseEntity<>(list, HttpStatus.OK);

	}

	// This method get the list of products of a specific type pagewise and also
	// sorts them
	// http://localhost:8888/Products/getSortedProductsTypeListPageWise/Men's
	// Casual/salePrice/1/16?direction=asc

	@GetMapping("/getSortedProductsTypeListPageWise/{Type}/{field}/{pageNumber}/{NumberofRecords}")
	public ResponseEntity<List<Products>> getSortedProductsTypeListPageWise(@PathVariable Integer pageNumber,
			@PathVariable Integer NumberofRecords, @PathVariable String Type, @RequestParam String direction,
			@PathVariable String field) {

		List<Products> list = productsService.getSortedProductsTypeListPageWise(pageNumber, NumberofRecords, Type,
				direction, field);

		return new ResponseEntity<>(list, HttpStatus.OK);

	}

	// This method will filter the product by type and brand and show in pagination
	// http://localhost:8888/Products/filterByTypeAndBrand/Men's Casual/Scuderia
	// Ferrari/1?numberOfRecords=31

	@GetMapping("/filterByTypeAndBrand/{type}/{brand}/{pageNumber}")
	public ResponseEntity<List<Products>> filterByTypeAndBrand(@PathVariable String type, @PathVariable String brand,
			@PathVariable Integer pageNumber, @RequestParam Integer numberOfRecords) throws ProductsException {

		List<Products> list = productsService.filterByTypeAndBrand(type, brand, pageNumber, numberOfRecords);

		return new ResponseEntity<>(list, HttpStatus.OK);

	}

}
