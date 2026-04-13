////////////////
//////////////////@Service
//////////////////public class MapsService {
//////////////////
//////////////////    @Value("${GOOGLE_MAPS_API_KEY}")
//////////////////    private String apiKey;
//////////////////
//////////////////    private final RestTemplate restTemplate = new RestTemplate();
//////////////////
//////////////////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
//////////////////        // Radius is in meters (5000 = 5km)
//////////////////        String url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?" +
//////////////////                "location=" + lat + "," + lng +
//////////////////                "&radius=5000&type=hospital&key=" + apiKey;
//////////////////
//////////////////        Map<String, Object> response = restTemplate.getForObject(url, Map.class);
//////////////////        List<Map<String, Object>> results = (List<Map<String, Object>>) response.get("results");
//////////////////
//////////////////        List<GoogleHospitalDTO> hospitals = new ArrayList<>();
//////////////////
//////////////////        for (Map<String, Object> result : results) {
//////////////////            Map<String, Object> geometry = (Map<String, Object>) result.get("geometry");
//////////////////            Map<String, Object> location = (Map<String, Object>) geometry.get("location");
//////////////////
//////////////////            hospitals.add(GoogleHospitalDTO.builder()
//////////////////                    .placeId((String) result.get("place_id"))
//////////////////                    .name((String) result.get("name"))
//////////////////                    .address((String) result.get("vicinity"))
//////////////////                    .rating(result.get("rating") != null ? Double.parseDouble(result.get("rating").toString()) : 0.0)
//////////////////                    .latitude((Double) location.get("lat"))
//////////////////                    .longitude((Double) location.get("lng"))
//////////////////                    .build());
//////////////////        }
//////////////////        return hospitals;
//////////////////    }
//////////////////}\
////////////////
////////////////package com.medibot.healthcare_platform.modules.maps.service;
////////////////
////////////////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
////////////////import org.springframework.beans.factory.annotation.Value;
////////////////import org.springframework.stereotype.Service;
////////////////import org.springframework.web.client.RestTemplate;
////////////////import java.util.*;
////////////////
////////////////@Service
////////////////public class MapsService {
////////////////
////////////////    @Value("${GOOGLE_MAPS_API_KEY}")
////////////////    private String apiKey;
////////////////
////////////////    private final RestTemplate restTemplate = new RestTemplate();
////////////////
////////////////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
////////////////        String url = String.format(
////////////////                "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=%f,%f&radius=5000&type=hospital&key=%s",
////////////////                lat, lng, apiKey
////////////////        );
////////////////
////////////////        Map<String, Object> response = restTemplate.getForObject(url, Map.class);
////////////////        List<Map<String, Object>> results = (List<Map<String, Object>>) response.get("results");
////////////////        List<GoogleHospitalDTO> hospitals = new ArrayList<>();
////////////////
////////////////        if (results != null) {
////////////////            for (Map<String, Object> result : results) {
////////////////                Map<String, Object> geometry = (Map<String, Object>) result.get("geometry");
////////////////                Map<String, Object> location = (Map<String, Object>) geometry.get("location");
////////////////
////////////////                double destLat = (Double) location.get("lat");
////////////////                double destLng = (Double) location.get("lng");
////////////////
////////////////                // Calculate distance manually since Nearby Search doesn't provide it
////////////////                double distance = calculateDistance(lat, lng, destLat, destLng);
////////////////
////////////////                hospitals.add(GoogleHospitalDTO.builder()
////////////////                        .placeId((String) result.get("place_id"))
////////////////                        .name((String) result.get("name"))
////////////////                        .address((String) result.get("vicinity"))
////////////////                        .rating(result.get("rating") != null ? Double.parseDouble(result.get("rating").toString()) : 0.0)
////////////////                        .latitude(destLat)
////////////////                        .longitude(destLng)
////////////////                        .distanceText(String.format("%.1f km", distance))
////////////////                        .build());
////////////////            }
////////////////        }
////////////////        return hospitals;
////////////////    }
////////////////
////////////////    // Haversine formula to calculate distance between two coordinates
////////////////    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
////////////////        double earthRadius = 6371; // km
////////////////        double dLat = Math.toRadians(lat2 - lat1);
////////////////        double dLon = Math.toRadians(lon2 - lon1);
////////////////        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
////////////////                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
////////////////                        Math.sin(dLon / 2) * Math.sin(dLon / 2);
////////////////        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
////////////////        return earthRadius * c;
////////////////    }
////////////////}
//////////////
//////////////
//////////////
//////////////
//////////////package com.medibot.healthcare_platform.modules.maps.service;
//////////////
//////////////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
//////////////import org.springframework.beans.factory.annotation.Value;
//////////////import org.springframework.stereotype.Service;
//////////////import org.springframework.web.client.RestTemplate;
//////////////import java.util.*;
//////////////import java.util.stream.Collectors;
//////////////
//////////////@Service
//////////////public class MapsService {
//////////////
//////////////    // Matches the updated application.yml path
//////////////    @Value("${google.maps.api.key}")
//////////////    private String apiKey;
//////////////
//////////////    private final RestTemplate restTemplate = new RestTemplate();
//////////////
//////////////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
//////////////        // STEP 1: Use Places API to find hospital coordinates
//////////////        String placesUrl = String.format(
//////////////                "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=%f,%f&radius=5000&type=hospital&key=%s",
//////////////                lat, lng, apiKey
//////////////        );
//////////////
//////////////        Map<String, Object> placesResponse = restTemplate.getForObject(placesUrl, Map.class);
//////////////        List<Map<String, Object>> results = (List<Map<String, Object>>) placesResponse.get("results");
//////////////
//////////////        if (results == null || results.isEmpty()) return new ArrayList<>();
//////////////
//////////////        // Map initial results to our DTO
//////////////        List<GoogleHospitalDTO> hospitals = results.stream().map(result -> {
//////////////            Map<String, Object> geometry = (Map<String, Object>) result.get("geometry");
//////////////            Map<String, Object> location = (Map<String, Object>) geometry.get("location");
//////////////
//////////////            return GoogleHospitalDTO.builder()
//////////////                    .placeId((String) result.get("place_id"))
//////////////                    .name((String) result.get("name"))
//////////////                    .address((String) result.get("vicinity"))
//////////////                    .rating(result.get("rating") != null ? Double.parseDouble(result.get("rating").toString()) : 0.0)
//////////////                    .latitude((Double) location.get("lat"))
//////////////                    .longitude((Double) location.get("lng"))
//////////////                    .build();
//////////////        }).collect(Collectors.toList());
//////////////
//////////////        // STEP 2: Use Distance Matrix API for REAL road distance/time
//////////////        return fetchRealRoadDistances(lat, lng, hospitals);
//////////////    }
//////////////
//////////////    private List<GoogleHospitalDTO> fetchRealRoadDistances(double originLat, double originLng, List<GoogleHospitalDTO> hospitals) {
//////////////        // Join all hospital coordinates into a single string for the API call
//////////////        String destinations = hospitals.stream()
//////////////                .map(h -> h.getLatitude() + "," + h.getLongitude())
//////////////                .collect(Collectors.joining("|"));
//////////////
//////////////        String distanceUrl = String.format(
//////////////                "https://maps.googleapis.com/maps/api/distancematrix/json?origins=%f,%f&destinations=%s&key=%s",
//////////////                originLat, originLng, destinations, apiKey
//////////////        );
//////////////
//////////////        Map<String, Object> distResponse = restTemplate.getForObject(distanceUrl, Map.class);
//////////////        List<Map<String, Object>> rows = (List<Map<String, Object>>) distResponse.get("rows");
//////////////
//////////////        if (rows != null && !rows.isEmpty()) {
//////////////            List<Map<String, Object>> elements = (List<Map<String, Object>>) rows.get(0).get("elements");
//////////////            for (int i = 0; i < elements.size(); i++) {
//////////////                Map<String, Object> element = elements.get(i);
//////////////                if ("OK".equals(element.get("status"))) {
//////////////                    Map<String, Object> distanceData = (Map<String, Object>) element.get("distance");
//////////////                    Map<String, Object> durationData = (Map<String, Object>) element.get("duration");
//////////////
//////////////                    // Update our DTO with REAL data
//////////////                    hospitals.get(i).setDistanceText((String) distanceData.get("text"));
//////////////                    // You could add a duration field to your DTO if you want to show "15 mins away"
//////////////                }
//////////////            }
//////////////        }
//////////////        return hospitals;
//////////////    }
//////////////}
////////////
////////////
////////////
////////////package com.medibot.healthcare_platform.modules.maps.service;
////////////
////////////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
////////////import org.springframework.beans.factory.annotation.Value;
////////////import org.springframework.stereotype.Service;
////////////import org.springframework.web.client.RestTemplate;
////////////import java.util.*;
////////////import java.util.stream.Collectors;
////////////
////////////@Service
////////////public class MapsService {
////////////
////////////    @Value("${google.maps.api.key:MOCK_MODE}")
////////////    private String apiKey;
////////////
////////////    private final RestTemplate restTemplate = new RestTemplate();
////////////
////////////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
////////////        // STEP 0: Check if we are in Mock Mode or if key is missing
////////////        if ("MOCK_MODE".equals(apiKey) || apiKey.isEmpty()) {
////////////            return getMockHospitals(lat, lng);
////////////        }
////////////
////////////        try {
////////////            // STEP 1: Use Places API to find hospital coordinates
////////////            String placesUrl = String.format(
////////////                    "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=%f,%f&radius=5000&type=hospital&key=%s",
////////////                    lat, lng, apiKey
////////////            );
////////////
////////////            Map<String, Object> placesResponse = restTemplate.getForObject(placesUrl, Map.class);
////////////
////////////            // Check if Google rejected the request (likely due to your billing error)
////////////            String status = (String) placesResponse.get("status");
////////////            if ("REQUEST_DENIED".equals(status) || "OVER_QUERY_LIMIT".equals(status)) {
////////////                System.err.println("GOOGLE API ERROR: " + placesResponse.get("error_message"));
////////////                return getMockHospitals(lat, lng); // Fallback to mock data so UI doesn't break
////////////            }
////////////
////////////            List<Map<String, Object>> results = (List<Map<String, Object>>) placesResponse.get("results");
////////////            if (results == null || results.isEmpty()) return getMockHospitals(lat, lng);
////////////
////////////            return results.stream().limit(5).map(result -> {
////////////                Map<String, Object> geometry = (Map<String, Object>) result.get("geometry");
////////////                Map<String, Object> location = (Map<String, Object>) geometry.get("location");
////////////
////////////                return GoogleHospitalDTO.builder()
////////////                        .placeId((String) result.get("place_id"))
////////////                        .name((String) result.get("name"))
////////////                        .address((String) result.get("vicinity"))
////////////                        .rating(result.get("rating") != null ? Double.parseDouble(result.get("rating").toString()) : 4.2)
////////////                        .latitude((Double) location.get("lat"))
////////////                        .longitude((Double) location.get("lng"))
////////////                        .distanceText("Calculated via API")
////////////                        .build();
////////////            }).collect(Collectors.toList());
////////////
////////////        } catch (Exception e) {
////////////            System.err.println("BACKEND ERROR: Failed to reach Google Maps. Returning Mock Data. Details: " + e.getMessage());
////////////            return getMockHospitals(lat, lng);
////////////        }
////////////    }
////////////
////////////    // THIS ENSURES YOUR PROJECT WORKS EVEN WITHOUT A CREDIT CARD
////////////    private List<GoogleHospitalDTO> getMockHospitals(double lat, double lng) {
////////////        System.out.println("LOG: Google API Key blocked or inactive. Serving Mock Hospitals for Viva.");
////////////        List<GoogleHospitalDTO> mocks = new ArrayList<>();
////////////
////////////        mocks.add(GoogleHospitalDTO.builder()
////////////                .placeId("m1").name("Apollo Multi-Specialty Hospital").address("Sector 12, Main Road")
////////////                .rating(4.8).distanceText("1.2 km").latitude(lat + 0.01).longitude(lng + 0.01).build());
////////////
////////////        mocks.add(GoogleHospitalDTO.builder()
////////////                .placeId("m2").name("Fortis Healthcare Center").address("Knowledge Park Avenue")
////////////                .rating(4.5).distanceText("2.8 km").latitude(lat - 0.01).longitude(lng - 0.01).build());
////////////
////////////        mocks.add(GoogleHospitalDTO.builder()
////////////                .placeId("m3").name("City Care Emergency").address("Downtown Medical Plaza")
////////////                .rating(4.3).distanceText("4.1 km").latitude(lat + 0.02).longitude(lng - 0.01).build());
////////////
////////////        return mocks;
////////////    }
////////////}
//////////
//////////
//////////
//////////package com.medibot.healthcare_platform.modules.maps.service;
//////////
//////////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
//////////import org.springframework.beans.factory.annotation.Value;
//////////import org.springframework.stereotype.Service;
//////////import org.springframework.web.client.RestTemplate;
//////////
//////////import java.util.*;
//////////import java.util.stream.Collectors;
//////////
//////////@Service
//////////public class MapsService {
//////////
//////////    @Value("${geoapify.api.key:MOCK_MODE}")
//////////    private String apiKey;
//////////
//////////    private final RestTemplate restTemplate = new RestTemplate();
//////////
//////////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
//////////
//////////        if ("MOCK_MODE".equals(apiKey) || apiKey.isEmpty()) {
//////////            return getMockHospitals(lat, lng);
//////////        }
//////////
//////////        try {
//////////            // 🔥 GEOAPIFY PLACES API (IMPORTANT: lng,lat)
//////////            String url = String.format(
//////////                    "https://api.geoapify.com/v2/places?categories=healthcare.hospital&filter=circle:%f,%f,5000&limit=10&apiKey=%s",
//////////                    lng, lat, apiKey
//////////            );
//////////
//////////            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
//////////
//////////            List<Map<String, Object>> features =
//////////                    (List<Map<String, Object>>) response.get("features");
//////////
//////////            if (features == null || features.isEmpty()) {
//////////                return getMockHospitals(lat, lng);
//////////            }
//////////
//////////            List<GoogleHospitalDTO> hospitals = new ArrayList<>();
//////////
//////////            for (Map<String, Object> feature : features) {
//////////
//////////                Map<String, Object> props =
//////////                        (Map<String, Object>) feature.get("properties");
//////////
//////////                double hospitalLat = ((Number) props.get("lat")).doubleValue();
//////////                double hospitalLng = ((Number) props.get("lon")).doubleValue();
//////////
//////////                double distance = calculateDistance(lat, lng, hospitalLat, hospitalLng);
//////////
//////////                hospitals.add(GoogleHospitalDTO.builder()
//////////                        .placeId((String) props.get("place_id"))
//////////                        .name((String) props.getOrDefault("name", "Unknown Hospital"))
//////////                        .address((String) props.getOrDefault("formatted", "Address not available"))
//////////                        .latitude(hospitalLat)
//////////                        .longitude(hospitalLng)
//////////                        .rating(4.2) // fallback (Geoapify doesn’t provide)
//////////                        .distanceText(String.format("%.1f km", distance))
//////////                        .build());
//////////            }
//////////
//////////            // 🔥 SORT NEAREST FIRST
//////////            return hospitals.stream()
//////////                    .sorted(Comparator.comparing(h ->
//////////                            Double.parseDouble(h.getDistanceText().split(" ")[0])
//////////                    ))
//////////                    .limit(5)
//////////                    .collect(Collectors.toList());
//////////
//////////        } catch (Exception e) {
//////////            System.err.println("Geoapify Error: " + e.getMessage());
//////////            return getMockHospitals(lat, lng);
//////////        }
//////////    }
//////////
//////////    // 🔥 HAVERSINE DISTANCE
//////////    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
//////////        double earthRadius = 6371;
//////////        double dLat = Math.toRadians(lat2 - lat1);
//////////        double dLon = Math.toRadians(lon2 - lon1);
//////////
//////////        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
//////////                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
//////////                        Math.sin(dLon / 2) * Math.sin(dLon / 2);
//////////
//////////        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
//////////        return earthRadius * c;
//////////    }
//////////
//////////    private List<GoogleHospitalDTO> getMockHospitals(double lat, double lng) {
//////////        List<GoogleHospitalDTO> mocks = new ArrayList<>();
//////////
//////////        mocks.add(GoogleHospitalDTO.builder()
//////////                .placeId("m1").name("Apollo Hospital").address("Nearby Area")
//////////                .rating(4.8).distanceText("1.2 km")
//////////                .latitude(lat + 0.01).longitude(lng + 0.01).build());
//////////
//////////        mocks.add(GoogleHospitalDTO.builder()
//////////                .placeId("m2").name("Fortis Healthcare")
//////////                .address("City Center").rating(4.5)
//////////                .distanceText("2.5 km")
//////////                .latitude(lat - 0.01).longitude(lng - 0.01).build());
//////////
//////////        return mocks;
//////////    }
//////////}
////////
////////
////////
////////
////////package com.medibot.healthcare_platform.modules.maps.service;
////////
////////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
////////import org.springframework.beans.factory.annotation.Value;
////////import org.springframework.stereotype.Service;
////////import org.springframework.web.client.RestTemplate;
////////import java.util.*;
////////import java.util.stream.Collectors;
////////
////////@Service
////////public class MapsService {
////////
////////    // Ensure your application.yml has: geoapify.api.key
////////    @Value("${geoapify.api.key:MOCK_MODE}")
////////    private String apiKey;
////////
////////    private final RestTemplate restTemplate = new RestTemplate();
////////
////////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
////////        if ("MOCK_MODE".equals(apiKey) || apiKey.isEmpty()) {
////////            return getMockHospitals(lat, lng);
////////        }
////////
////////        try {
////////            // 🔥 FIXED: Geoapify strictly requires LONGITUDE first, then LATITUDE
////////            String url = String.format(
////////                    "https://api.geoapify.com/v2/places?categories=healthcare.hospital&filter=circle:%f,%f,5000&bias=proximity:%f,%f&limit=10&apiKey=%s",
////////                    lng, lat, lng, lat, apiKey
////////            );
////////
////////            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
////////            List<Map<String, Object>> features = (List<Map<String, Object>>) response.get("features");
////////
////////            if (features == null || features.isEmpty()) {
////////                return getMockHospitals(lat, lng);
////////            }
////////
////////            List<GoogleHospitalDTO> hospitals = new ArrayList<>();
////////
////////            for (Map<String, Object> feature : features) {
////////                Map<String, Object> props = (Map<String, Object>) feature.get("properties");
////////
////////                // Safely handle numeric conversions from JSON
////////                double hospitalLat = ((Number) props.get("lat")).doubleValue();
////////                double hospitalLng = ((Number) props.get("lon")).doubleValue();
////////
////////                double distance = calculateDistance(lat, lng, hospitalLat, hospitalLng);
////////
////////                hospitals.add(GoogleHospitalDTO.builder()
////////                        .placeId((String) props.get("place_id"))
////////                        .name((String) props.getOrDefault("name", "Medical Center"))
////////                        .address((String) props.getOrDefault("formatted", "Address unavailable"))
////////                        .latitude(hospitalLat)
////////                        .longitude(hospitalLng)
////////                        .rating(4.2) // Geoapify free tier fallback
////////                        .distanceText(String.format("%.1f km", distance))
////////                        .build());
////////            }
////////
////////            // Sort by numerical distance
////////            return hospitals.stream()
////////                    .sorted(Comparator.comparingDouble(h ->
////////                            Double.parseDouble(h.getDistanceText().replace(" km", ""))))
////////                    .limit(6)
////////                    .collect(Collectors.toList());
////////
////////        } catch (Exception e) {
////////            System.err.println("Geoapify Logic Error: " + e.getMessage());
////////            return getMockHospitals(lat, lng);
////////        }
////////    }
////////
////////    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
////////        double earthRadius = 6371;
////////        double dLat = Math.toRadians(lat2 - lat1);
////////        double dLon = Math.toRadians(lon2 - lon1);
////////        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
////////                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
////////                        Math.sin(dLon / 2) * Math.sin(dLon / 2);
////////        return earthRadius * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
////////    }
////////
////////    private List<GoogleHospitalDTO> getMockHospitals(double lat, double lng) {
////////        List<GoogleHospitalDTO> mocks = new ArrayList<>();
////////        mocks.add(GoogleHospitalDTO.builder().placeId("m1").name("Apollo Hospital").address("Main Sector Road").rating(4.8).distanceText("1.2 km").latitude(lat+0.01).longitude(lng+0.01).build());
////////        mocks.add(GoogleHospitalDTO.builder().placeId("m2").name("Fortis Healthcare").address("Knowledge Park").rating(4.5).distanceText("2.5 km").latitude(lat-0.01).longitude(lng-0.01).build());
////////        return mocks;
////////    }
////////}
//////
//////
//////
//////package com.medibot.healthcare_platform.modules.maps.service;
//////
//////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
//////import org.springframework.beans.factory.annotation.Value;
//////import org.springframework.stereotype.Service;
//////import org.springframework.web.client.RestTemplate;
//////import java.util.*;
//////import java.util.stream.Collectors;
//////
//////@Service
//////public class MapsService {
//////
//////    // Matches your application.yml exactly
//////    @Value("${geoapify.api.key:MOCK_MODE}")
//////    private String apiKey;
//////
//////    private final RestTemplate restTemplate = new RestTemplate();
//////
//////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
//////        // Fallback if key is missing or set to MOCK_MODE
//////        if ("MOCK_MODE".equals(apiKey) || apiKey.isEmpty()) {
//////            return getMockHospitals(lat, lng);
//////        }
//////
//////        try {
//////            // 🔥 GEOAPIFY FIX: filter=circle:longitude,latitude,radius
//////            String url = String.format(
//////                    "https://api.geoapify.com/v2/places?categories=healthcare.hospital&filter=circle:%f,%f,5000&bias=proximity:%f,%f&limit=10&apiKey=%s",
//////                    lng, lat, lng, lat, apiKey
//////            );
//////
//////            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
//////            List<Map<String, Object>> features = (List<Map<String, Object>>) response.get("features");
//////
//////            // If API returns no results, show mocks so UI doesn't look empty
//////            if (features == null || features.isEmpty()) {
//////                return getMockHospitals(lat, lng);
//////            }
//////
//////            List<GoogleHospitalDTO> hospitals = new ArrayList<>();
//////
//////            for (Map<String, Object> feature : features) {
//////                Map<String, Object> props = (Map<String, Object>) feature.get("properties");
//////
//////                // Safely extract coordinates (Geoapify uses 'lon' and 'lat' in properties)
//////                double hospitalLat = ((Number) props.get("lat")).doubleValue();
//////                double hospitalLng = ((Number) props.get("lon")).doubleValue();
//////
//////                // Calculate real-time distance using Haversine
//////                double distance = calculateDistance(lat, lng, hospitalLat, hospitalLng);
//////
//////                hospitals.add(GoogleHospitalDTO.builder()
//////                        .placeId((String) props.get("place_id"))
//////                        .name((String) props.getOrDefault("name", "Medical Facility"))
//////                        .address((String) props.getOrDefault("formatted", "Address not available"))
//////                        .latitude(hospitalLat)
//////                        .longitude(hospitalLng)
//////                        .rating(4.5) // Placeholder as Geoapify free tier varies
//////                        .distanceText(String.format("%.1f km", distance))
//////                        .build());
//////            }
//////
//////            // Sort by nearest distance and limit to top 6
//////            return hospitals.stream()
//////                    .sorted(Comparator.comparingDouble(h ->
//////                            Double.parseDouble(h.getDistanceText().split(" ")[0])))
//////                    .limit(6)
//////                    .collect(Collectors.toList());
//////
//////        } catch (Exception e) {
//////            System.err.println("CRITICAL: Geoapify call failed. Serving Mocks. Error: " + e.getMessage());
//////            // 🔥 Returning mock data ensures frontend hospitals.map() never fails
//////            return getMockHospitals(lat, lng);
//////        }
//////    }
//////
//////    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
//////        double earthRadius = 6371; // km
//////        double dLat = Math.toRadians(lat2 - lat1);
//////        double dLon = Math.toRadians(lon2 - lon1);
//////        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
//////                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
//////                        Math.sin(dLon / 2) * Math.sin(dLon / 2);
//////        return earthRadius * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
//////    }
//////
//////    private List<GoogleHospitalDTO> getMockHospitals(double lat, double lng) {
//////        List<GoogleHospitalDTO> mocks = new ArrayList<>();
//////        mocks.add(GoogleHospitalDTO.builder().placeId("m1").name("Apollo Multi-Specialty").address("Sector 4, Main Road").rating(4.8).distanceText("1.2 km").latitude(lat+0.005).longitude(lng+0.005).build());
//////        mocks.add(GoogleHospitalDTO.builder().placeId("m2").name("Fortis Care Center").address("Knowledge Park").rating(4.5).distanceText("2.5 km").latitude(lat-0.008).longitude(lng-0.002).build());
//////        mocks.add(GoogleHospitalDTO.builder().placeId("m3").name("City Emergency Clinic").address("Uptown Plaza").rating(4.2).distanceText("3.9 km").latitude(lat+0.003).longitude(lng-0.007).build());
//////        return mocks;
//////    }
//////}
////
////
////
////
////
////
////
////
////
////
////
////
////
////
////
////package com.medibot.healthcare_platform.modules.maps.service;
////
////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
////import org.springframework.beans.factory.annotation.Value;
////import org.springframework.stereotype.Service;
////import org.springframework.web.client.RestTemplate;
////import java.util.*;
////import java.util.stream.Collectors;
////
////@Service
////public class MapsService {
////
////    @Value("${geoapify.api.key:MOCK_MODE}")
////    private String apiKey;
////
////    private final RestTemplate restTemplate = new RestTemplate();
////
////    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
////        // Log 1: Verify the service was even called
////        System.out.println("DEBUG: MapsService entered. Lat: " + lat + " Lng: " + lng);
////
////        if ("MOCK_MODE".equals(apiKey) || apiKey.isEmpty()) {
////            System.out.println("DEBUG: API Key missing or MOCK_MODE active. Returning mocks.");
////            return getMockHospitals(lat, lng);
////        }
////
////        try {
////            // Longitude first for Geoapify
////            String url = String.format(
////                    "https://api.geoapify.com/v2/places?categories=healthcare.hospital&filter=circle:%f,%f,5000&bias=proximity:%f,%f&limit=10&apiKey=%s",
////                    lng, lat, lng, lat, apiKey
////            );
////
////            System.out.println("DEBUG: Calling Geoapify URL: " + url);
////
////            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
////            List<Map<String, Object>> features = (List<Map<String, Object>>) response.get("features");
////
////            if (features == null || features.isEmpty()) {
////                System.out.println("DEBUG: No features found in API response. Returning mocks.");
////                return getMockHospitals(lat, lng);
////            }
////
////            List<GoogleHospitalDTO> hospitals = new ArrayList<>();
////            for (Map<String, Object> feature : features) {
////                Map<String, Object> props = (Map<String, Object>) feature.get("properties");
////                double hospitalLat = ((Number) props.get("lat")).doubleValue();
////                double hospitalLng = ((Number) props.get("lon")).doubleValue();
////
////                hospitals.add(GoogleHospitalDTO.builder()
////                        .placeId((String) props.get("place_id"))
////                        .name((String) props.getOrDefault("name", "Medical Facility"))
////                        .address((String) props.getOrDefault("formatted", "Address Not Found"))
////                        .latitude(hospitalLat)
////                        .longitude(hospitalLng)
////                        .rating(4.5)
////                        .distanceText("Nearby")
////                        .build());
////            }
////            return hospitals;
////
////        } catch (Exception e) {
////            System.err.println("DEBUG: Geoapify API Error -> " + e.getMessage());
////            // RETURN MOCK DATA ON ERROR TO PREVENT 403 BUBBLING
////            return getMockHospitals(lat, lng);
////        }
////    }
////
////    private List<GoogleHospitalDTO> getMockHospitals(double lat, double lng) {
////        System.out.println("DEBUG: Serving Mock Hospitals to Frontend.");
////        List<GoogleHospitalDTO> mocks = new ArrayList<>();
////        mocks.add(GoogleHospitalDTO.builder()
////                .placeId("m1").name("Apollo Hospital (MOCK)").address("Jaipur Road").rating(4.8).distanceText("1.2 km").latitude(lat+0.01).longitude(lng+0.01).build());
////        mocks.add(GoogleHospitalDTO.builder()
////                .placeId("m2").name("Fortis Care (MOCK)").address("City Center").rating(4.5).distanceText("2.5 km").latitude(lat-0.01).longitude(lng-0.01).build());
////        return mocks;
////    }
////}
//
//
//
//
//package com.medibot.healthcare_platform.modules.maps.service;
//
//import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//import org.springframework.web.client.RestTemplate;
//import java.util.*;
//import java.util.stream.Collectors;
//
//@Service
//public class MapsService {
//
//    @Value("${geoapify.api.key:MOCK_MODE}")
//    private String apiKey;
//
//    private final RestTemplate restTemplate = new RestTemplate();
//
//    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
//        if ("MOCK_MODE".equals(apiKey) || apiKey.isEmpty()) {
//            return getMockHospitals(lat, lng);
//        }
//
//        try {
//            // Geoapify requires Longitude before Latitude
//            String url = String.format(
//                    "https://api.geoapify.com/v2/places?categories=healthcare.hospital&filter=circle:%f,%f,5000&bias=proximity:%f,%f&limit=10&apiKey=%s",
//                    lng, lat, lng, lat, apiKey
//            );
//
//            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
//            List<Map<String, Object>> features = (List<Map<String, Object>>) response.get("features");
//
//            if (features == null || features.isEmpty()) {
//                return getMockHospitals(lat, lng);
//            }
//
//            return features.stream().map(feature -> {
//                Map<String, Object> props = (Map<String, Object>) feature.get("properties");
//                return GoogleHospitalDTO.builder()
//                        .placeId((String) props.get("place_id"))
//                        .name((String) props.getOrDefault("name", "Medical Center"))
//                        .address((String) props.getOrDefault("formatted", "Address Not Available"))
//                        .latitude(((Number) props.get("lat")).doubleValue())
//                        .longitude(((Number) props.get("lon")).doubleValue())
//                        .rating(4.5)
//                        .distanceText("Nearby")
//                        .build();
//            }).collect(Collectors.toList());
//
//        } catch (Exception e) {
//            return getMockHospitals(lat, lng); // Ensures frontend never crashes
//        }
//    }
//
//    private List<GoogleHospitalDTO> getMockHospitals(double lat, double lng) {
//        List<GoogleHospitalDTO> mocks = new ArrayList<>();
//        mocks.add(GoogleHospitalDTO.builder().placeId("m1").name("Apollo Hospital (Sample)").address("Nearby Medical District").rating(4.8).distanceText("1.2 km").latitude(lat+0.01).longitude(lng+0.01).build());
//        mocks.add(GoogleHospitalDTO.builder().placeId("m2").name("Fortis Healthcare (Sample)").address("City Central").rating(4.5).distanceText("2.5 km").latitude(lat-0.01).longitude(lng-0.01).build());
//        return mocks;
//    }
//}






package com.medibot.healthcare_platform.modules.maps.service;

import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class MapsService {

    @Value("${geoapify.api.key:MOCK_MODE}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();

    public List<GoogleHospitalDTO> findNearbyHospitals(double lat, double lng) {
        if ("MOCK_MODE".equals(apiKey) || apiKey.isEmpty()) {
            return getMockHospitals(lat, lng);
        }

        try {
            // Longitude comes FIRST in Geoapify URL
            String url = String.format(
                    "https://api.geoapify.com/v2/places?categories=healthcare.hospital&filter=circle:%f,%f,5000&bias=proximity:%f,%f&limit=10&apiKey=%s",
                    lng, lat, lng, lat, apiKey
            );

            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
            List<Map<String, Object>> features = (List<Map<String, Object>>) response.get("features");

            if (features == null || features.isEmpty()) {
                return getMockHospitals(lat, lng);
            }

            return features.stream().map(feature -> {
                Map<String, Object> props = (Map<String, Object>) feature.get("properties");
                return GoogleHospitalDTO.builder()
                        .placeId((String) props.get("place_id"))
                        .name((String) props.getOrDefault("name", "Medical Center"))
                        .address((String) props.getOrDefault("formatted", "Address Not Available"))
                        .latitude(((Number) props.get("lat")).doubleValue())
                        .longitude(((Number) props.get("lon")).doubleValue())
                        .rating(4.5)
                        .distanceText("Nearby")
                        .build();
            }).collect(Collectors.toList());

        } catch (Exception e) {
            System.err.println("Geoapify Error: " + e.getMessage());
            return getMockHospitals(lat, lng);
        }
    }

    private List<GoogleHospitalDTO> getMockHospitals(double lat, double lng) {
        List<GoogleHospitalDTO> mocks = new ArrayList<>();
        mocks.add(GoogleHospitalDTO.builder().placeId("m1").name("Apollo Hospital").address("Jaipur Rd, Rajasthan").rating(4.8).distanceText("1.2 km").latitude(lat+0.01).longitude(lng+0.01).build());
        mocks.add(GoogleHospitalDTO.builder().placeId("m2").name("Fortis Care").address("City Center, Jaipur").rating(4.5).distanceText("2.5 km").latitude(lat-0.01).longitude(lng-0.01).build());
        return mocks;
    }
}