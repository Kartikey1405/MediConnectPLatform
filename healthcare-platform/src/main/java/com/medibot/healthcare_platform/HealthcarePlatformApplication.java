//package com.medibot.healthcare_platform;
//
//import io.github.cdimascio.dotenv.Dotenv;
//import org.springframework.boot.SpringApplication;
//import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.scheduling.annotation.EnableScheduling;
//
//@SpringBootApplication
//@EnableScheduling
//public class HealthcarePlatformApplication {
//
//	public static void main(String[] args) {
//		// 1. Load .env variables FIRST
//		Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();
//
//		// 2. Map them to System properties so Spring can resolve ${DB_URL} etc.
//		dotenv.entries().forEach(entry -> {
//			System.setProperty(entry.getKey(), entry.getValue());
//			System.out.println("AI Key Loaded: " + System.getenv("SPRING_AI_GOOGLE_GENAI_API_KEY"));
//		});
//
//		// 3. NOW start the application
//		SpringApplication.run(HealthcarePlatformApplication.class, args);
//	}
//}



package com.medibot.healthcare_platform;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class HealthcarePlatformApplication {

	public static void main(String[] args) {
		// 1. Load .env variables FIRST from the project root
		Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

		// 2. Map them to System properties so Spring can resolve ${DB_URL}, etc.
		dotenv.entries().forEach(entry -> {
			System.setProperty(entry.getKey(), entry.getValue());
		});

		// 3. LOGGING CHECK: Use getProperty to verify the keys are now in Java memory
		// This will now print your actual key instead of 'null'
		String aiKey = System.getProperty("SPRING_AI_GOOGLE_GENAI_API_KEY");
		System.out.println("AI Key Loaded: " + (aiKey != null ? "SUCCESS" : "FAILED"));

		// 4. Start the Spring Boot application
		SpringApplication.run(HealthcarePlatformApplication.class, args);
	}
}
