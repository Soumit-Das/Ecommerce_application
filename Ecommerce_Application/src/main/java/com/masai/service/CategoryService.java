package com.masai.service;

import java.util.List;

import com.masai.exception.CategoryException;
import com.masai.model.Category;

public interface CategoryService {

	public Category addCategory(Category category) throws CategoryException;

	public Category getAllProductsByCategoryId(int catid) throws CategoryException;

	public Category updateCategoryById(int catId, Category category) throws CategoryException;

	public Category deleteCategoryById(int catId) throws CategoryException;

	public List<Category> getAllCategory() throws CategoryException;

}
