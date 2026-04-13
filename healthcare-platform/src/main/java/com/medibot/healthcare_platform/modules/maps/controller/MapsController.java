////package com.medibot.healthcare_platform.modules.maps.controller;
////
////import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
////import com.medibot.healthcare_platform.modules.maps.service.MapsService;
////import org.springframework.beans.factory.annotation.Autowired;
////import org.springframework.web.bind.annotation.*;
////import java.util.List;
////
////@RestController
////@RequestMapping("/api/maps")
////@CrossOrigin(origins = "*", allowedHeaders = "*") // Allow all for debugging
////public class MapsController {
////
////    @Autowired
////    private MapsService mapsService;
////
////    @GetMapping("/nearby")
////    public List<GoogleHospitalDTO> getNearby(@RequestParam double lat, @RequestParam double lng) {
////        System.out.println("DEBUG: Controller received Maps request for " + lat + "," + lng);
////        return mapsService.findNearbyHospitals(lat, lng);
////    }
////}
//
//
//
//
//package com.medibot.healthcare_platform.modules.maps.controller;
//
//import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
//import com.medibot.healthcare_platform.modules.maps.service.MapsService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.*;
//import java.util.List;
//
//@RestController
//@RequestMapping("/api/maps")
//public class MapsController {
//
//    @Autowired
//    private MapsService mapsService;
//
//    @GetMapping("/nearby")
//    public List<GoogleHospitalDTO> getNearby(@RequestParam double lat, @RequestParam double lng) {
//        // No @CrossOrigin needed here because SecurityConfig handles it globally
//        return mapsService.findNearbyHospitals(lat, lng);
//    }
//}

package com.medibot.healthcare_platform.modules.maps.controller;

import com.medibot.healthcare_platform.modules.maps.dto.GoogleHospitalDTO;
import com.medibot.healthcare_platform.modules.maps.service.MapsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/maps")
public class MapsController {

    @Autowired
    private MapsService mapsService;

    @GetMapping("/nearby")
    public List<GoogleHospitalDTO> getNearby(
            @RequestParam double lat,
            @RequestParam double lng) {
        return mapsService.findNearbyHospitals(lat, lng);
    }
}