package com.medibot.healthcare_platform.modules.doctor.entity;

/**
 * Status Enum for clear state management of doctor availability.
 * Made public to allow cross-package access by Service and DTO layers.
 */
public enum SlotStatus {
    AVAILABLE,   // Open for patient booking
    LOCKED,      // Reserved during the payment process (prevents double-booking)
    OCCUPIED     // Successfully booked after payment confirmation
}