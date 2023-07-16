package com.rabbbitmqconsumer;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Component;

import com.rabbbitmqconsumer.entity.ColaboradorEntity;


@Component
public interface ColaboradorRepository extends JpaRepository<ColaboradorEntity, Integer> {

}
