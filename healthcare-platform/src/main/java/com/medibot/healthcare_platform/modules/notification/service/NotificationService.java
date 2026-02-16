package com.medibot.healthcare_platform.modules.notification.service;

import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
import com.medibot.healthcare_platform.modules.notification.entity.Notification;
import com.medibot.healthcare_platform.modules.notification.repository.NotificationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class NotificationService {
    private final NotificationRepository notificationRepository;
    private final UserRepository userRepository;

    @Transactional
    public void createNotification(UUID userId, String message, String type, String link) {
        var user = userRepository.findById(userId).orElseThrow();
        Notification note = Notification.builder()
                .user(user)
                .message(message)
                .type(type)
                .link(link)
                .build();
        notificationRepository.save(note);
    }
}