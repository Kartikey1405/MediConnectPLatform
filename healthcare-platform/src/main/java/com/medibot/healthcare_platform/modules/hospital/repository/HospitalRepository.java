//package com.medibot.healthcare_platform.modules.hospital.repository;
//
//import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.query.Param;
//import java.util.List;
//import java.util.UUID;
//
//public interface HospitalRepository extends JpaRepository<Hospital, UUID> {
//
//    // Haversine Formula: (6371 * acos(cos(radians(:userLat)) * cos(radians(h.latitude)) * ... ))
//    // This finds the closest hospitals within a specific radius (e.g., 50km)
//    @Query(value = "SELECT * FROM hospitals h WHERE " +
//            "(6371 * acos(cos(radians(:userLat)) * cos(radians(h.latitude)) * " +
//            "cos(radians(h.longitude) - radians(:userLng)) + " +
//            "sin(radians(:userLat)) * sin(radians(h.latitude)))) < :radius " +
//            "ORDER BY (6371 * acos(cos(radians(:userLat)) * cos(radians(h.latitude)) * " +
//            "cos(radians(h.longitude) - radians(:userLng)) + " +
//            "sin(radians(:userLat)) * sin(radians(h.latitude)))) ASC " +
//            "LIMIT 5", nativeQuery = true)
//    List<Hospital> findNearestHospitals(@Param("userLat") double userLat,
//                                        @Param("userLng") double userLng,
//                                        @Param("radius") double radius);
//}


package com.medibot.healthcare_platform.modules.hospital.repository;

import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.UUID;

public interface HospitalRepository extends JpaRepository<Hospital, UUID> {

    /**
     * SOS DISCOVERY: Uses the Haversine formula to calculate distance on a sphere.
     * 6371 is the Earth's radius in kilometers.
     * This query finds active hospitals within the specified radius.
     */
    @Query(value = "SELECT * FROM hospitals h WHERE h.is_active = true AND " +
            "(6371 * acos(least(1, max(-1, cos(radians(:userLat)) * cos(radians(h.latitude)) * " +
            "cos(radians(h.longitude) - radians(:userLng)) + " +
            "sin(radians(:userLat)) * sin(radians(h.latitude)))))) < :radius " +
            "ORDER BY (6371 * acos(least(1, max(-1, cos(radians(:userLat)) * cos(radians(h.latitude)) * " +
            "cos(radians(h.longitude) - radians(:userLng)) + " +
            "sin(radians(:userLat)) * sin(radians(h.latitude)))))) ASC " +
            "LIMIT 5", nativeQuery = true)
    List<Hospital> findNearestHospitals(@Param("userLat") double userLat,
                                        @Param("userLng") double userLng,
                                        @Param("radius") double radius);
}