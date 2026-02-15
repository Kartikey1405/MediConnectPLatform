package com.medibot.healthcare_platform.modules.doctor.service;

import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class SlotCleanupService {

    private final SlotRepository slotRepository;

    /**
     * Runs every 60 seconds (60000 ms).
     * Finds slots LOCKED for more than 10 minutes and resets them.
     */
    @Scheduled(fixedRate = 60000)
    @Transactional
    public void releaseExpiredSlots() {
        LocalDateTime expiryTime = LocalDateTime.now().minusMinutes(10);

        // We use the custom query we added to the SlotRepository earlier
        List<Slot> expiredSlots = slotRepository.findExpiredLocks(expiryTime);

        if (!expiredSlots.isEmpty()) {
            log.info("Cleaning up {} expired slot locks", expiredSlots.size());
            for (Slot slot : expiredSlots) {
                slot.setStatus(SlotStatus.AVAILABLE);
                slot.setLockedAt(null);
            }
            slotRepository.saveAll(expiredSlots);
        }
    }
}