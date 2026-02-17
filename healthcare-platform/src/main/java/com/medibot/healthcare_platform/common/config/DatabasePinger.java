package com.medibot.healthcare_platform.common.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class DatabasePinger {

    private static final Logger logger = LoggerFactory.getLogger(DatabasePinger.class);
    private final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // This will pull your public URL from Render environment variables
    // If not set, it defaults to your known backend URL
    @Value("${APP_PUBLIC_URL:https://mediconnectbackend-cqu6.onrender.com}")
    private String appUrl;

    /**
     * Runs every 8 minutes (480,000ms).
     * Render's timeout is 15 minutes.
     */
    @Scheduled(fixedRate = 480000)
    public void keepEverythingAlive() {
        try {
            // 1. PING DATABASE: Keeps the DB connection pool active
            jdbcTemplate.execute("SELECT 1");
            logger.info("Keep-Alive: Database connection is warm.");

            // 2. PING PUBLIC URL: Forces Render to see "Inbound Traffic"
            // We hit a public endpoint like /api/hospitals or just the root /
            restTemplate.getForEntity(appUrl + "/api/hospitals", String.class);
            logger.info("Keep-Alive: Inbound traffic simulated to {}", appUrl);

        } catch (Exception e) {
            logger.warn("Keep-Alive: Ping pulse sent. (Note: Initial wake-up might show a timeout)");
        }
    }
}
