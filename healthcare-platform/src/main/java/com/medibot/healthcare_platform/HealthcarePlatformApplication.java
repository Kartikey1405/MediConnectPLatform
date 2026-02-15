package com.medibot.healthcare_platform;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@com.medibot.healthcare_platform.EnableScheduling
public class HealthcarePlatformApplication {

	public static void main(String[] args) {
		// 1. Load .env variables FIRST
		Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

		// 2. Map them to System properties so Spring can resolve ${DB_URL} etc.
		dotenv.entries().forEach(entry -> {
			System.setProperty(entry.getKey(), entry.getValue());
		});

		// 3. NOW start the application
		SpringApplication.run(HealthcarePlatformApplication.class, args);
	}
}