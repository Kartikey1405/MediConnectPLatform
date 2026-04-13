// // // // // import { motion } from "framer-motion";
// // // // // import { MapPin, Star, Navigation, Phone, Clock } from "lucide-react";
// // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // import GlassCard from "@/components/GlassCard";

// // // // // const hospitals = [
// // // // //   { id: 1, name: "City General Hospital", distance: "1.2 km", rating: 4.8, address: "123 Medical Avenue, Downtown", phone: "+1 234 567 890", hours: "24/7 Emergency" },
// // // // //   { id: 2, name: "St. Mary's Medical Center", distance: "2.5 km", rating: 4.6, address: "456 Health Street, Midtown", phone: "+1 234 567 891", hours: "24/7 Emergency" },
// // // // //   { id: 3, name: "Unity Healthcare Complex", distance: "3.8 km", rating: 4.5, address: "789 Wellness Blvd, Uptown", phone: "+1 234 567 892", hours: "6 AM - 11 PM" },
// // // // //   { id: 4, name: "Green Valley Clinic", distance: "4.1 km", rating: 4.3, address: "321 Care Lane, Suburbs", phone: "+1 234 567 893", hours: "8 AM - 8 PM" },
// // // // //   { id: 5, name: "Metro Emergency Hospital", distance: "5.2 km", rating: 4.7, address: "654 Rescue Road, Eastside", phone: "+1 234 567 894", hours: "24/7 Emergency" },
// // // // // ];

// // // // // const NearbyHospitals = () => {
// // // // //   return (
// // // // //     <DashboardLayout role="patient">
// // // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // // //         <div>
// // // // //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // // //             <MapPin size={28} className="text-accent" />
// // // // //             Nearby Hospitals
// // // // //           </h1>
// // // // //           <p className="text-muted-foreground mt-1">Find healthcare facilities near you</p>
// // // // //         </div>

// // // // //         {/* Map Placeholder */}
// // // // //         <GlassCard className="p-1 overflow-hidden" tilt={false}>
// // // // //           <div className="w-full h-64 md:h-80 rounded-2xl bg-gradient-to-br from-primary/5 to-accent/5 flex items-center justify-center relative overflow-hidden">
// // // // //             <div className="absolute inset-0 mesh-gradient opacity-50" />
// // // // //             <div className="text-center z-10">
// // // // //               <MapPin size={48} className="text-accent mx-auto mb-3 animate-float" />
// // // // //               <p className="font-display font-bold text-foreground">Interactive Map</p>
// // // // //               <p className="text-sm text-muted-foreground">Enable location to see nearby hospitals</p>
// // // // //               <button className="mt-3 glass rounded-xl px-4 py-2 text-sm font-medium text-accent hover:shadow-glow-accent transition-all">
// // // // //                 Enable Location
// // // // //               </button>
// // // // //             </div>
// // // // //           </div>
// // // // //         </GlassCard>

// // // // //         {/* Hospital Cards */}
// // // // //         <div className="grid md:grid-cols-2 gap-4">
// // // // //           {hospitals.map((h, i) => (
// // // // //             <GlassCard key={h.id} delay={i * 0.08} className="p-5">
// // // // //               <div className="flex items-start justify-between mb-3">
// // // // //                 <h3 className="font-display font-bold text-foreground text-sm">{h.name}</h3>
// // // // //                 <div className="flex items-center gap-1 text-warning text-xs font-semibold">
// // // // //                   <Star size={12} fill="currentColor" /> {h.rating}
// // // // //                 </div>
// // // // //               </div>
// // // // //               <p className="text-xs text-muted-foreground mb-3">{h.address}</p>
// // // // //               <div className="flex flex-wrap gap-2 text-xs text-muted-foreground mb-3">
// // // // //                 <span className="flex items-center gap-1"><Navigation size={12} className="text-accent" />{h.distance}</span>
// // // // //                 <span className="flex items-center gap-1"><Phone size={12} />{h.phone}</span>
// // // // //                 <span className="flex items-center gap-1"><Clock size={12} />{h.hours}</span>
// // // // //               </div>
// // // // //               <button className="w-full glass rounded-xl py-2 text-sm font-medium text-accent hover:shadow-glow-accent hover:scale-[1.02] transition-all">
// // // // //                 Get Directions
// // // // //               </button>
// // // // //             </GlassCard>
// // // // //           ))}
// // // // //         </div>
// // // // //       </div>
// // // // //     </DashboardLayout>
// // // // //   );
// // // // // };

// // // // // export default NearbyHospitals;







// // // // import { useState } from "react";
// // // // import { motion } from "framer-motion";
// // // // import { MapPin, Star, Navigation, Phone, Clock, Loader2 } from "lucide-react";
// // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // import GlassCard from "@/components/GlassCard";
// // // // import axios from "axios"; // Ensure axios is installed

// // // // const NearbyHospitals = () => {
// // // //   // 1. State management for dynamic data
// // // //   const [hospitals, setHospitals] = useState([]);
// // // //   const [loading, setLoading] = useState(false);
// // // //   const [isLocationEnabled, setIsLocationEnabled] = useState(false);

// // // //   // 2. Logic to fetch from your Spring Boot Backend
// // // //   const fetchHospitals = async (lat: number, lng: number) => {
// // // //     setLoading(true);
// // // //     try {
// // // //       const token = localStorage.getItem("token"); // Assuming JWT storage
// // // //       const response = await axios.get(
// // // //         `http://localhost:8080/api/maps/nearby?lat=${lat}&lng=${lng}`,
// // // //         { headers: { Authorization: `Bearer ${token}` } }
// // // //       );
// // // //       setHospitals(response.data);
// // // //       setIsLocationEnabled(true);
// // // //     } catch (error) {
// // // //       console.error("Failed to fetch nearby hospitals", error);
// // // //     } finally {
// // // //       setLoading(false);
// // // //     }
// // // //   };

// // // //   // 3. Geolocation Trigger
// // // //   const handleEnableLocation = () => {
// // // //     if (navigator.geolocation) {
// // // //       navigator.geolocation.getCurrentPosition(
// // // //         (position) => {
// // // //           const { latitude, longitude } = position.coords;
// // // //           fetchHospitals(latitude, longitude);
// // // //         },
// // // //         () => {
// // // //           alert("Please allow location access to find nearby hospitals.");
// // // //         }
// // // //       );
// // // //     }
// // // //   };

// // // //   return (
// // // //     <DashboardLayout role="patient">
// // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // //         <div>
// // // //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // //             <MapPin size={28} className="text-accent" />
// // // //             Nearby Hospitals
// // // //           </h1>
// // // //           <p className="text-muted-foreground mt-1">Real-time facilities within 5km radius</p>
// // // //         </div>

// // // //         {/* Map Placeholder */}
// // // //         <GlassCard className="p-1 overflow-hidden" tilt={false}>
// // // //           <div className="w-full h-64 md:h-80 rounded-2xl bg-gradient-to-br from-primary/5 to-accent/5 flex items-center justify-center relative overflow-hidden">
// // // //             <div className="absolute inset-0 mesh-gradient opacity-50" />
// // // //             <div className="text-center z-10">
// // // //               {loading ? (
// // // //                 <Loader2 size={48} className="text-accent mx-auto mb-3 animate-spin" />
// // // //               ) : (
// // // //                 <MapPin size={48} className={`mx-auto mb-3 ${isLocationEnabled ? 'text-green-500' : 'text-accent animate-float'}`} />
// // // //               )}
// // // //               <p className="font-display font-bold text-foreground">
// // // //                 {isLocationEnabled ? "Location Active" : "Interactive Map"}
// // // //               </p>
// // // //               <p className="text-sm text-muted-foreground">
// // // //                 {isLocationEnabled ? "Hospitals found near you" : "Enable location to see real-world hospitals"}
// // // //               </p>
// // // //               <button 
// // // //                 onClick={handleEnableLocation}
// // // //                 disabled={loading}
// // // //                 className="mt-3 glass rounded-xl px-4 py-2 text-sm font-medium text-accent hover:shadow-glow-accent transition-all"
// // // //               >
// // // //                 {loading ? "Searching..." : isLocationEnabled ? "Update Location" : "Enable Location"}
// // // //               </button>
// // // //             </div>
// // // //           </div>
// // // //         </GlassCard>

// // // //         {/* Dynamic Hospital Cards */}
// // // //         <div className="grid md:grid-cols-2 gap-4">
// // // //           {hospitals.map((h, i) => (
// // // //             <GlassCard key={h.placeId} delay={i * 0.08} className="p-5">
// // // //               <div className="flex items-start justify-between mb-3">
// // // //                 <h3 className="font-display font-bold text-foreground text-sm">{h.name}</h3>
// // // //                 <div className="flex items-center gap-1 text-warning text-xs font-semibold">
// // // //                   <Star size={12} fill="currentColor" /> {h.rating || "New"}
// // // //                 </div>
// // // //               </div>
// // // //               <p className="text-xs text-muted-foreground mb-3">{h.address}</p>
// // // //               <div className="flex flex-wrap gap-2 text-xs text-muted-foreground mb-3">
// // // //                 <span className="flex items-center gap-1">
// // // //                   <Navigation size={12} className="text-accent" />
// // // //                   {h.distanceText}
// // // //                 </span>
// // // //                 <span className="flex items-center gap-1"><Phone size={12} />Available</span>
// // // //                 <span className="flex items-center gap-1"><Clock size={12} />Open Now</span>
// // // //               </div>
              
// // // //               {/* External Link to Google Maps */}
// // // //               <a 
// // // //                 href={`https://www.google.com/maps/search/?api=1&query=${h.latitude},${h.longitude}&query_place_id=${h.placeId}`}
// // // //                 target="_blank"
// // // //                 rel="noopener noreferrer"
// // // //                 className="block w-full text-center glass rounded-xl py-2 text-sm font-medium text-accent hover:shadow-glow-accent hover:scale-[1.02] transition-all"
// // // //               >
// // // //                 Get Directions
// // // //               </a>
// // // //             </GlassCard>
// // // //           ))}
// // // //         </div>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );
// // // // };

// // // // export default NearbyHospitals;




















// // // import { useState } from "react";
// // // import { MapPin, Star, Navigation, Phone, Clock, Loader2 } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import GlassCard from "@/components/GlassCard";
// // // import axios from "axios";

// // // const NearbyHospitals = () => {
// // //   const [hospitals, setHospitals] = useState([]);
// // //   const [loading, setLoading] = useState(false);
// // //   const [isLocationEnabled, setIsLocationEnabled] = useState(false);

// // //   const fetchHospitals = async (lat: number, lng: number) => {
// // //     setLoading(true);
// // //     try {
// // //       const token = localStorage.getItem("token");

// // //       const response = await axios.get(
// // //         `${import.meta.env.VITE_BACKEND_URL}/api/maps/nearby?lat=${lat}&lng=${lng}`,
// // //         { headers: { Authorization: `Bearer ${token}` } }
// // //       );

// // //       setHospitals(response.data);
// // //       setIsLocationEnabled(true);
// // //     } catch (error) {
// // //       console.error("Failed to fetch nearby hospitals", error);
// // //     } finally {
// // //       setLoading(false);
// // //     }
// // //   };

// // //   const handleEnableLocation = () => {
// // //     if (navigator.geolocation) {
// // //       navigator.geolocation.getCurrentPosition(
// // //         (position) => {
// // //           const { latitude, longitude } = position.coords;
// // //           fetchHospitals(latitude, longitude);
// // //         },
// // //         () => {
// // //           alert("Please allow location access to find nearby hospitals.");
// // //         }
// // //       );
// // //     }
// // //   };

// // //   return (
// // //     <DashboardLayout role="patient">
// // //       <div className="max-w-4xl mx-auto space-y-8">
// // //         <div>
// // //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // //             <MapPin size={28} className="text-accent" />
// // //             Nearby Hospitals
// // //           </h1>
// // //           <p className="text-muted-foreground mt-1">
// // //             Real-time facilities within 5km radius
// // //           </p>
// // //         </div>

// // //         <GlassCard className="p-1 overflow-hidden" tilt={false}>
// // //           <div className="w-full h-64 md:h-80 rounded-2xl bg-gradient-to-br from-primary/5 to-accent/5 flex items-center justify-center relative overflow-hidden">
// // //             <div className="absolute inset-0 mesh-gradient opacity-50" />
// // //             <div className="text-center z-10">
// // //               {loading ? (
// // //                 <Loader2 size={48} className="text-accent mx-auto mb-3 animate-spin" />
// // //               ) : (
// // //                 <MapPin
// // //                   size={48}
// // //                   className={`mx-auto mb-3 ${
// // //                     isLocationEnabled
// // //                       ? "text-green-500"
// // //                       : "text-accent animate-float"
// // //                   }`}
// // //                 />
// // //               )}
// // //               <p className="font-display font-bold text-foreground">
// // //                 {isLocationEnabled ? "Location Active" : "Interactive Map"}
// // //               </p>
// // //               <p className="text-sm text-muted-foreground">
// // //                 {isLocationEnabled
// // //                   ? "Hospitals found near you"
// // //                   : "Enable location to see real-world hospitals"}
// // //               </p>
// // //               <button
// // //                 onClick={handleEnableLocation}
// // //                 disabled={loading}
// // //                 className="mt-3 glass rounded-xl px-4 py-2 text-sm font-medium text-accent hover:shadow-glow-accent transition-all"
// // //               >
// // //                 {loading
// // //                   ? "Searching..."
// // //                   : isLocationEnabled
// // //                   ? "Update Location"
// // //                   : "Enable Location"}
// // //               </button>
// // //             </div>
// // //           </div>
// // //         </GlassCard>

// // //         <div className="grid md:grid-cols-2 gap-4">
// // //           {hospitals.map((h, i) => (
// // //             <GlassCard key={h.placeId} delay={i * 0.08} className="p-5">
// // //               <div className="flex items-start justify-between mb-3">
// // //                 <h3 className="font-display font-bold text-foreground text-sm">
// // //                   {h.name}
// // //                 </h3>
// // //                 <div className="flex items-center gap-1 text-warning text-xs font-semibold">
// // //                   <Star size={12} fill="currentColor" /> {h.rating || "New"}
// // //                 </div>
// // //               </div>

// // //               <p className="text-xs text-muted-foreground mb-3">
// // //                 {h.address}
// // //               </p>

// // //               <div className="flex flex-wrap gap-2 text-xs text-muted-foreground mb-3">
// // //                 <span className="flex items-center gap-1">
// // //                   <Navigation size={12} className="text-accent" />
// // //                   {h.distanceText}
// // //                 </span>
// // //                 <span className="flex items-center gap-1">
// // //                   <Phone size={12} />Available
// // //                 </span>
// // //                 <span className="flex items-center gap-1">
// // //                   <Clock size={12} />Open Now
// // //                 </span>
// // //               </div>

// // //               {/* 🔥 FIXED: OpenStreetMap instead of Google */}
// // //               <a
// // //                 href={`https://www.openstreetmap.org/?mlat=${h.latitude}&mlon=${h.longitude}#map=16/${h.latitude}/${h.longitude}`}
// // //                 target="_blank"
// // //                 rel="noopener noreferrer"
// // //                 className="block w-full text-center glass rounded-xl py-2 text-sm font-medium text-accent hover:shadow-glow-accent hover:scale-[1.02] transition-all"
// // //               >
// // //                 Get Directions
// // //               </a>
// // //             </GlassCard>
// // //           ))}
// // //         </div>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default NearbyHospitals;






// // import { useState } from "react";
// // import { MapPin, Star, Navigation, Phone, Clock, Loader2 } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import GlassCard from "@/components/GlassCard";
// // import axios from "axios";

// // const NearbyHospitals = () => {
// //   // 1. Initialize as an empty array to prevent immediate crash
// //   const [hospitals, setHospitals] = useState<any[]>([]); 
// //   const [loading, setLoading] = useState(false);
// //   const [isLocationEnabled, setIsLocationEnabled] = useState(false);

// //   const fetchHospitals = async (lat: number, lng: number) => {
// //     setLoading(true);
// //     try {
// //       const token = localStorage.getItem("token");
      
// //       // Use the environment variable for flexibility
// //       const backendUrl = import.meta.env.VITE_BACKEND_URL || "http://localhost:8080";
      
// //       const response = await axios.get(
// //         `${backendUrl}/api/maps/nearby?lat=${lat}&lng=${lng}`,
// //         { headers: { Authorization: `Bearer ${token}` } }
// //       );

// //       // 🔥 CRITICAL SAFETY CHECK: Only set if the response is an array
// //       if (Array.isArray(response.data)) {
// //         setHospitals(response.data);
// //       } else {
// //         console.error("Backend error response:", response.data);
// //         setHospitals([]); // Fallback to empty list
// //       }
      
// //       setIsLocationEnabled(true);
// //     } catch (error) {
// //       console.error("Failed to fetch nearby hospitals", error);
// //       setHospitals([]); // 🔥 RESET on error to prevent .map() crash
// //     } finally {
// //       setLoading(false);
// //     }
// //   };

// //   const handleEnableLocation = () => {
// //     if (navigator.geolocation) {
// //       navigator.geolocation.getCurrentPosition(
// //         (position) => {
// //           const { latitude, longitude } = position.coords;
// //           fetchHospitals(latitude, longitude);
// //         },
// //         () => {
// //           alert("Please allow location access to find nearby hospitals.");
// //         }
// //       );
// //     }
// //   };

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-4xl mx-auto space-y-8">
// //         <div>
// //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// //             <MapPin size={28} className="text-accent" />
// //             Nearby Hospitals
// //           </h1>
// //           <p className="text-muted-foreground mt-1">Real-time facilities via Geoapify Intelligence</p>
// //         </div>

// //         <GlassCard className="p-1 overflow-hidden" tilt={false}>
// //           <div className="w-full h-64 md:h-80 rounded-2xl bg-gradient-to-br from-primary/5 to-accent/5 flex items-center justify-center relative overflow-hidden">
// //             <div className="absolute inset-0 mesh-gradient opacity-50" />
// //             <div className="text-center z-10">
// //               {loading ? (
// //                 <Loader2 size={48} className="text-accent mx-auto mb-3 animate-spin" />
// //               ) : (
// //                 <MapPin size={48} className={`mx-auto mb-3 ${isLocationEnabled ? 'text-green-500' : 'text-accent animate-float'}`} />
// //               )}
// //               <p className="font-display font-bold text-foreground">
// //                 {isLocationEnabled ? "Hospitals Located" : "Interactive Map"}
// //               </p>
// //               <button 
// //                 onClick={handleEnableLocation}
// //                 disabled={loading}
// //                 className="mt-3 glass rounded-xl px-4 py-2 text-sm font-medium text-accent hover:shadow-glow-accent transition-all"
// //               >
// //                 {loading ? "Searching..." : isLocationEnabled ? "Refresh List" : "Enable Location"}
// //               </button>
// //             </div>
// //           </div>
// //         </GlassCard>

// //         <div className="grid md:grid-cols-2 gap-4">
// //           {/* 🔥 FIXED: Guard the map function with Array.isArray */}
// //           {Array.isArray(hospitals) && hospitals.length > 0 ? (
// //             hospitals.map((h, i) => (
// //               <GlassCard key={h.placeId || i} delay={i * 0.08} className="p-5">
// //                 <div className="flex items-start justify-between mb-3">
// //                   <h3 className="font-display font-bold text-foreground text-sm pr-2">{h.name}</h3>
// //                   <div className="flex items-center gap-1 text-warning text-xs font-semibold shrink-0">
// //                     <Star size={12} fill="currentColor" /> {h.rating || "4.5"}
// //                   </div>
// //                 </div>
// //                 <p className="text-xs text-muted-foreground mb-3 h-8 overflow-hidden">{h.address}</p>
// //                 <div className="flex flex-wrap gap-2 text-xs text-muted-foreground mb-3">
// //                   <span className="flex items-center gap-1">
// //                     <Navigation size={12} className="text-accent" />
// //                     {h.distanceText}
// //                   </span>
// //                 </div>
                
// //                 {/* Direct Link to OpenStreetMap for Directions */}
// //                 <a 
// //                   href={`https://www.openstreetmap.org/?mlat=${h.latitude}&mlon=${h.longitude}#map=16/${h.latitude}/${h.longitude}`}
// //                   target="_blank"
// //                   rel="noopener noreferrer"
// //                   className="block w-full text-center glass rounded-xl py-2 text-sm font-medium text-accent hover:shadow-glow-accent hover:scale-[1.02] transition-all"
// //                 >
// //                   Get Directions
// //                 </a>
// //               </GlassCard>
// //             ))
// //           ) : isLocationEnabled && !loading ? (
// //             <div className="col-span-2 text-center p-10 glass rounded-2xl">
// //               <p className="text-muted-foreground">No hospitals found or access restricted.</p>
// //             </div>
// //           ) : null}
// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default NearbyHospitals;





















// import { useState } from "react";
// import { MapPin, Star, Navigation, Loader2 } from "lucide-react";
// import DashboardLayout from "@/components/DashboardLayout";
// import GlassCard from "@/components/GlassCard";
// import axios from "axios";

// const NearbyHospitals = () => {
//   const [hospitals, setHospitals] = useState<any[]>([]); 
//   const [loading, setLoading] = useState(false);
//   const [isLocationEnabled, setIsLocationEnabled] = useState(false);

//   const fetchHospitals = async (lat: number, lng: number) => {
//     setLoading(true);
//     console.log("FRONTEND DEBUG: Starting fetch for", lat, lng);
//     try {
//       const token = localStorage.getItem("token");
//       const backendUrl = import.meta.env.VITE_BACKEND_URL || "http://localhost:8080";
      
//       const response = await axios.get(
//         `${backendUrl}/api/maps/nearby?lat=${lat}&lng=${lng}`,
//         { headers: { Authorization: `Bearer ${token}` } }
//       );

//       console.log("FRONTEND DEBUG: Received response status:", response.status);
//       console.log("FRONTEND DEBUG: Response data type:", typeof response.data);

//       if (Array.isArray(response.data)) {
//         setHospitals(response.data);
//       } else {
//         console.warn("FRONTEND DEBUG: Data is not an array!", response.data);
//         setHospitals([]); 
//       }
//       setIsLocationEnabled(true);
//     } catch (error: any) {
//       console.error("FRONTEND DEBUG: Axios Error!", error.response?.status, error.message);
//       setHospitals([]); 
//     } finally {
//       setLoading(false);
//     }
//   };

//   const handleEnableLocation = () => {
//     if (navigator.geolocation) {
//       navigator.geolocation.getCurrentPosition(
//         (pos) => fetchHospitals(pos.coords.latitude, pos.coords.longitude),
//         () => alert("Location denied.")
//       );
//     }
//   };

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-4xl mx-auto space-y-8 p-4">
//         <h1 className="text-3xl font-bold flex items-center gap-3">
//           <MapPin className="text-accent" /> Nearby Hospitals
//         </h1>

//         <GlassCard className="p-8 text-center">
//           <button 
//             onClick={handleEnableLocation} 
//             disabled={loading}
//             className="bg-accent text-white px-6 py-3 rounded-xl font-bold hover:opacity-90"
//           >
//             {loading ? "Searching..." : "Find Nearby Hospitals"}
//           </button>
//         </GlassCard>

//         <div className="grid md:grid-cols-2 gap-4">
//           {Array.isArray(hospitals) && hospitals.length > 0 ? (
//             hospitals.map((h, i) => (
//               <GlassCard key={h.placeId || i} className="p-5">
//                 <h3 className="font-bold text-lg">{h.name}</h3>
//                 <p className="text-sm text-muted-foreground">{h.address}</p>
//                 <div className="flex items-center gap-2 mt-2 text-accent">
//                    <Navigation size={16} /> <span>{h.distanceText}</span>
//                 </div>
//                 <a 
//                   href={`https://www.openstreetmap.org/?mlat=${h.latitude}&mlon=${h.longitude}#map=16/${h.latitude}/${h.longitude}`}
//                   target="_blank" 
//                   className="block mt-4 text-center border border-accent rounded-lg py-2 text-accent font-medium"
//                 >
//                   Get Directions
//                 </a>
//               </GlassCard>
//             ))
//           ) : isLocationEnabled && !loading ? (
//             <p className="col-span-2 text-center text-muted-foreground">No data received from server.</p>
//           ) : null}
//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default NearbyHospitals;





import { useState } from "react";
import { MapPin, Star, Navigation, Phone, Clock, Loader2 } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import axios from "axios";

const NearbyHospitals = () => {
  const [hospitals, setHospitals] = useState<any[]>([]); 
  const [loading, setLoading] = useState(false);
  const [isLocationEnabled, setIsLocationEnabled] = useState(false);

  const fetchHospitals = async (lat: number, lng: number) => {
    setLoading(true);
    try {
      const token = localStorage.getItem("accessToken");
      const backendUrl = import.meta.env.VITE_BACKEND_URL || "http://localhost:8080";
      
      const response = await axios.get(
        `${backendUrl}/api/maps/nearby?lat=${lat}&lng=${lng}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      // Type Guard: Prevents the .map() crash if backend fails
      if (Array.isArray(response.data)) {
        setHospitals(response.data);
      } else {
        setHospitals([]); 
      }
      setIsLocationEnabled(true);
    } catch (error) {
      console.error("API Error:", error);
      setHospitals([]); 
    } finally {
      setLoading(false);
    }
  };

  const handleEnableLocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (pos) => fetchHospitals(pos.coords.latitude, pos.coords.longitude),
        () => alert("Please allow location access.")
      );
    }
  };

  return (
    <DashboardLayout role="patient">
      <div className="max-w-4xl mx-auto space-y-8 p-4">
        <div className="flex justify-between items-end">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <MapPin className="text-accent" /> Nearby Hospitals
            </h1>
            <p className="text-muted-foreground mt-1">Real-time medical facilities near you</p>
          </div>
          <button 
            onClick={handleEnableLocation} 
            disabled={loading}
            className="bg-accent text-white px-5 py-2.5 rounded-xl font-semibold shadow-glow-accent hover:opacity-90 transition-all flex items-center gap-2"
          >
            {loading ? <Loader2 className="animate-spin" size={18} /> : <MapPin size={18} />}
            {isLocationEnabled ? "Refresh Location" : "Find Nearby"}
          </button>
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          {Array.isArray(hospitals) && hospitals.length > 0 ? (
            hospitals.map((h, i) => (
              <GlassCard key={h.placeId || i} className="p-6 flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-start mb-2">
                    <h3 className="font-bold text-lg text-foreground">{h.name}</h3>
                    <div className="flex items-center gap-1 text-warning font-bold text-sm">
                      <Star size={14} fill="currentColor" /> {h.rating}
                    </div>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4 line-clamp-2">{h.address}</p>
                </div>
                
                <div className="flex items-center justify-between mt-4">
                  <div className="flex items-center gap-2 text-accent font-medium text-sm">
                    <Navigation size={16} /> <span>{h.distanceText}</span>
                  </div>
                  <a 
                    href={`https://www.openstreetmap.org/?mlat=${h.latitude}&mlon=${h.longitude}#map=16/${h.latitude}/${h.longitude}`}
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-xs font-bold uppercase tracking-wider text-accent hover:underline"
                  >
                    Get Directions
                  </a>
                </div>
              </GlassCard>
            ))
          ) : !loading && isLocationEnabled ? (
            <div className="col-span-2 text-center py-20 glass rounded-3xl">
              <p className="text-muted-foreground">No medical facilities found in this range.</p>
            </div>
          ) : (
            <div className="col-span-2 text-center py-20 border-2 border-dashed border-muted rounded-3xl">
              <p className="text-muted-foreground italic">Click the button above to discover local hospitals.</p>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default NearbyHospitals;