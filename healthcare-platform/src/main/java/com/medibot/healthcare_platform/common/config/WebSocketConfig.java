package com.medibot.healthcare_platform.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // 'topic' for public broadcasts, 'queue' for private user notifications
        config.enableSimpleBroker("/topic", "/queue");

        // Prefix for messages sent FROM client TO server
        config.setApplicationDestinationPrefixes("/app");

        // Required for user-specific messaging (e.g., /user/queue/notifications)
        config.setUserDestinationPrefix("/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws")
                .setAllowedOrigins("http://localhost:3000") // Your React URL
                .withSockJS(); // Fallback for browsers that don't support WebSockets
    }
}