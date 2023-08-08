package com.masai.service;

import com.masai.exception.CartException;
import com.masai.exception.ProductsException;
import com.masai.model.Cart;
import com.masai.model.Products;

public interface CartService {

	public Products addProductToCart(int pid, int quantity, int cid) throws ProductsException, CartException;

	public Cart updateProductQuantity(int newquantity, int pid, int cid) throws ProductsException, CartException;

	public String deleteProductFromCart(int pid, int cid) throws ProductsException, CartException;

	public Cart getCartById(int cid) throws CartException;

}
