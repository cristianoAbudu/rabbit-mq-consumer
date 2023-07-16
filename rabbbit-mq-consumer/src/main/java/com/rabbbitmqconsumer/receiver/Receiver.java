package com.rabbbitmqconsumer.receiver;

import java.util.concurrent.CountDownLatch;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.backend.util.SenhaUtil;
import com.rabbbitmqconsumer.ColaboradorRepository;
import com.rabbbitmqconsumer.entity.ColaboradorEntity;

@Service
public class Receiver {

	@Autowired
	ColaboradorRepository colaboradorRepository;

	private CountDownLatch latch = new CountDownLatch(1);

	public void receiveMessage(Integer message) {
		System.out.println("Received <" + message + ">");

		ColaboradorEntity colaboradorEntity = colaboradorRepository.findById(message).get();

		colaboradorEntity.setScore(SenhaUtil.calculaComplexidade(colaboradorEntity.getSenha()));

		colaboradorEntity.setSenha(SenhaUtil.encryptPassword(colaboradorEntity.getSenha()));

		colaboradorEntity = colaboradorRepository.save(colaboradorEntity);

		latch.countDown();
	}

	public CountDownLatch getLatch() {
		return latch;
	}

}