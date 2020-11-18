package com.rh.cloudhsm;

import org.jpos.iso.ISOUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Key;
import java.security.KeyStore;
import java.security.Security;

@SpringBootApplication
public class CloudhsmTestApplication implements CommandLineRunner {
	private Logger log = LoggerFactory.getLogger(CloudhsmTestApplication.class);
	public static void main(String[] args) {
		SpringApplication.run(CloudhsmTestApplication.class, args);
	}

	@Value("${thread.size}")
	private int threadSize;
	@Value("${hsm.username}")
	private String username;
	@Value("${hsm.password}")
	private String password;


	@Override
	public void run(String... args) throws Exception {
		test(threadSize);
	}

	public void test(int threadSize) throws Exception {
		Security.addProvider(new com.cavium.provider.CaviumProvider());

		KeyStore keyStore = KeyStore.getInstance("CloudHSM");
		keyStore.load(null, null);

		final CloudHsmService cloudHsmService = new CloudHsmService(keyStore);
		cloudHsmService.loginWithExplicitCredentials(username, password, "PARTITION_1");

		for (int i=0; i<threadSize; i++) {
			Thread t = new Thread(() -> {
				Key macKey = cloudHsmService.getZak();
				byte[] result = cloudHsmService.genMac(macKey, ISOUtil.hex2byte("AABBCCDD"));
				log.info("Result: {}",  ISOUtil.hexString(result));
			});
			t.start();
		}


	}
}
