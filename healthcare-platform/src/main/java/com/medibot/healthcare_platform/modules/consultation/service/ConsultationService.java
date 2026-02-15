package com.medibot.healthcare_platform.modules.consultation.service;

import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ConsultationService {
    private final ConsultationRepository consultationRepository;
    private final BookingRepository bookingRepository;

    @Transactional
    public Consultation startConsultation(UUID bookingId) {
        var booking = bookingRepository.findById(bookingId).orElseThrow();
        Consultation consultation = Consultation.builder()
                .booking(booking)
                .startTime(LocalDateTime.now())
                .build();
        return consultationRepository.save(consultation);
    }

    @Transactional
    public void endConsultation(UUID consultationId, String notes) {
        Consultation consultation = consultationRepository.findById(consultationId).orElseThrow();
        consultation.setEndTime(LocalDateTime.now());
        consultation.setDoctorNotes(notes);
        consultation.setCompleted(true);
        consultationRepository.save(consultation);
    }
}