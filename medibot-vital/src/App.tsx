// // import { Toaster } from "@/components/ui/toaster";
// // import { Toaster as Sonner } from "@/components/ui/sonner";
// // import { TooltipProvider } from "@/components/ui/tooltip";
// // import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
// // import { BrowserRouter, Routes, Route } from "react-router-dom";
// // import Index from "./pages/Index";
// // import NotFound from "./pages/NotFound";
// // import Login from "./pages/Login";
// // import Signup from "./pages/Signup";
// // import PatientDashboard from "./pages/patient/Dashboard";
// // import TriageChat from "./pages/patient/TriageChat";
// // import Timeline from "./pages/patient/Timeline";
// // import MedicalRecords from "./pages/patient/MedicalRecords";
// // import Consultations from "./pages/patient/Consultations";
// // import NearbyHospitals from "./pages/patient/NearbyHospitals";
// // import BookAppointment from "./pages/patient/BookAppointment";
// // import VideoConsultation from "./pages/patient/VideoConsultation";
// // import DoctorDashboard from "./pages/doctor/Dashboard";
// // import DoctorAppointments from "./pages/doctor/Appointments";
// // import DoctorConsultationRoom from "./pages/doctor/ConsultationRoom";
// // import AdminLogin from "./pages/admin/Login";
// // import AdminDashboard from "./pages/admin/Dashboard";

// // const queryClient = new QueryClient();

// // const App = () => (
// //   <QueryClientProvider client={queryClient}>
// //     <TooltipProvider>
// //       <Toaster />
// //       <Sonner />
// //       <BrowserRouter>
// //         <Routes>
// //           <Route path="/" element={<Index />} />
// //           <Route path="/login" element={<Login />} />
// //           <Route path="/signup" element={<Signup />} />
// //           <Route path="/patient/dashboard" element={<PatientDashboard />} />
// //           <Route path="/patient/triage" element={<TriageChat />} />
// //           <Route path="/patient/timeline" element={<Timeline />} />
// //           <Route path="/patient/records" element={<MedicalRecords />} />
// //           <Route path="/patient/consultations" element={<Consultations />} />
// //           <Route path="/patient/hospitals" element={<NearbyHospitals />} />
// //           <Route path="/patient/book" element={<BookAppointment />} />
// //           <Route path="/patient/consultation" element={<VideoConsultation />} />
// //           <Route path="/doctor/dashboard" element={<DoctorDashboard />} />
// //           <Route path="/doctor/appointments" element={<DoctorAppointments />} />
// //           <Route path="/doctor/consultation" element={<DoctorConsultationRoom />} />
// //           <Route path="/admin/login" element={<AdminLogin />} />
// //           <Route path="/admin/dashboard" element={<AdminDashboard />} />
// //           <Route path="*" element={<NotFound />} />
// //         </Routes>
// //       </BrowserRouter>
// //     </TooltipProvider>
// //   </QueryClientProvider>
// // );

// // export default App;



// import { Toaster } from "@/components/ui/toaster";
// import { Toaster as Sonner } from "@/components/ui/sonner";
// import { TooltipProvider } from "@/components/ui/tooltip";
// import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
// import { BrowserRouter, Routes, Route } from "react-router-dom";
// import ProtectedRoute from "@/components/auth/ProtectedRoute"; // Make sure this exists

// // Page Imports
// import Index from "./pages/Index";
// import NotFound from "./pages/NotFound";
// import Login from "./pages/Login";
// import Signup from "./pages/Signup";
// import PatientDashboard from "./pages/patient/Dashboard";
// import TriageChat from "./pages/patient/TriageChat";
// import Timeline from "./pages/patient/Timeline";
// import MedicalRecords from "./pages/patient/MedicalRecords";
// import Consultations from "./pages/patient/Consultations";
// import NearbyHospitals from "./pages/patient/NearbyHospitals";
// import BookAppointment from "./pages/patient/BookAppointment";
// import VideoConsultation from "./pages/patient/VideoConsultation";
// import DoctorDashboard from "./pages/doctor/Dashboard";
// import DoctorAppointments from "./pages/doctor/Appointments";
// import DoctorConsultationRoom from "./pages/doctor/ConsultationRoom";
// import AdminLogin from "./pages/admin/Login";
// import AdminDashboard from "./pages/admin/Dashboard";

// const queryClient = new QueryClient();

// const App = () => (
//   <QueryClientProvider client={queryClient}>
//     <TooltipProvider>
//       <Toaster />
//       <Sonner />
//       <BrowserRouter>
//         <Routes>
//           {/* Public Routes */}
//           <Route path="/" element={<Index />} />
//           <Route path="/login" element={<Login />} />
//           <Route path="/signup" element={<Signup />} />
//           <Route path="/admin/login" element={<AdminLogin />} />

//           {/* Patient Protected Routes */}
//           <Route element={<ProtectedRoute allowedRoles={['PATIENT']} />}>
//             <Route path="/patient/dashboard" element={<PatientDashboard />} />
//             <Route path="/patient/triage" element={<TriageChat />} />
//             <Route path="/patient/timeline" element={<Timeline />} />
//             <Route path="/patient/records" element={<MedicalRecords />} />
//             <Route path="/patient/consultations" element={<Consultations />} />
//             <Route path="/patient/hospitals" element={<NearbyHospitals />} />
//             <Route path="/patient/book" element={<BookAppointment />} />
//             <Route path="/patient/consultation" element={<VideoConsultation />} />
//           </Route>

//           {/* Doctor Protected Routes */}
//           <Route element={<ProtectedRoute allowedRoles={['DOCTOR']} />}>
//             <Route path="/doctor/dashboard" element={<DoctorDashboard />} />
//             <Route path="/doctor/appointments" element={<DoctorAppointments />} />
//             <Route path="/doctor/consultation" element={<DoctorConsultationRoom />} />
//           </Route>

//           {/* Admin Protected Routes */}
//           <Route element={<ProtectedRoute allowedRoles={['ADMIN']} />}>
//             <Route path="/admin/dashboard" element={<AdminDashboard />} />
//           </Route>

//           {/* Fallback */}
//           <Route path="*" element={<NotFound />} />
//         </Routes>
//       </BrowserRouter>
//     </TooltipProvider>
//   </QueryClientProvider>
// );

// export default App;






import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ProtectedRoute from "@/components/auth/ProtectedRoute";

// Page Imports
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import PatientDashboard from "./pages/patient/Dashboard";
import TriageChat from "./pages/patient/TriageChat";
import Timeline from "./pages/patient/Timeline";
import MedicalRecords from "./pages/patient/MedicalRecords";
import Consultations from "./pages/patient/Consultations";
import NearbyHospitals from "./pages/patient/NearbyHospitals";
import BookAppointment from "./pages/patient/BookAppointment";
import VideoConsultation from "./pages/patient/VideoConsultation";
import DoctorDashboard from "./pages/doctor/Dashboard";
import DoctorAppointments from "./pages/doctor/Appointments";
import DoctorConsultationRoom from "./pages/doctor/ConsultationRoom";
import AdminLogin from "./pages/admin/Login";
import AdminDashboard from "./pages/admin/Dashboard";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          {/* 1. PUBLIC ROUTES */}
          <Route path="/" element={<Index />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/admin/login" element={<AdminLogin />} />

          {/* 2. PATIENT PROTECTED ROUTES */}
          <Route element={<ProtectedRoute allowedRoles={['PATIENT']} />}>
            <Route path="/patient/dashboard" element={<PatientDashboard />} />
            <Route path="/patient/triage" element={<TriageChat />} />
            <Route path="/patient/timeline" element={<Timeline />} />
            <Route path="/patient/records" element={<MedicalRecords />} />
            <Route path="/patient/consultations" element={<Consultations />} />
            <Route path="/patient/hospitals" element={<NearbyHospitals />} />
            <Route path="/patient/book" element={<BookAppointment />} />
            {/* UPDATED: Added :bookingId so patients can join specific calls */}
            <Route path="/patient/consultation/:bookingId" element={<VideoConsultation />} />
          </Route>

          {/* 3. DOCTOR PROTECTED ROUTES */}
          <Route element={<ProtectedRoute allowedRoles={['DOCTOR']} />}>
            <Route path="/doctor/dashboard" element={<DoctorDashboard />} />
            <Route path="/doctor/appointments" element={<DoctorAppointments />} />
            {/* FIX: Added :bookingId to resolve the 404 error when clicking Start Call */}
            <Route path="/doctor/consultation/:bookingId" element={<DoctorConsultationRoom />} />
          </Route>

          {/* 4. ADMIN PROTECTED ROUTES */}
          <Route element={<ProtectedRoute allowedRoles={['ADMIN']} />}>
            <Route path="/admin/dashboard" element={<AdminDashboard />} />
          </Route>

          {/* 5. FALLBACK */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;