package com.cursos.springsecuritycourse.repository;

import com.cursos.springsecuritycourse.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {
}
