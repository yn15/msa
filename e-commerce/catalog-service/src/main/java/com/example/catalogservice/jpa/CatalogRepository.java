package com.example.catalogservice.jpa;

import org.springframework.data.repository.CrudRepository;

import javax.xml.catalog.Catalog;

public interface CatalogRepository extends CrudRepository<CatalogEntity, Long> {
    CatalogEntity findByProductId(String productId);
}
