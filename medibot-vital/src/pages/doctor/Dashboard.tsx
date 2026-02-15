// // // import { motion } from "framer-motion";
// // // import { Users, Calendar, Video, TrendingUp, Clock } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import GlassCard from "@/components/GlassCard";

// // // const stats = [
// // //   { label: "Patients Seen", value: "1,247", icon: Users, color: "text-accent", trend: "+12%" },
// // //   { label: "Today's Appointments", value: "8", icon: Calendar, color: "text-success", trend: "+2" },
// // //   { label: "Upcoming Meetings", value: "3", icon: Video, color: "text-warning", trend: "Next: 2 PM" },
// // // ];

// // // const appointments = [
// // //   { id: 1, patient: "Alex Thompson", time: "10:00 AM", type: "Video", status: "completed" },
// // //   { id: 2, patient: "Maria Garcia", time: "11:30 AM", type: "Video", status: "completed" },
// // //   { id: 3, patient: "John Smith", time: "2:00 PM", type: "Video", status: "upcoming" },
// // //   { id: 4, patient: "Sarah Johnson", time: "3:30 PM", type: "In-Person", status: "upcoming" },
// // //   { id: 5, patient: "David Lee", time: "4:30 PM", type: "Video", status: "upcoming" },
// // // ];

// // // const DoctorDashboard = () => {
// // //   return (
// // //     <DashboardLayout role="doctor">
// // //       <div className="max-w-6xl mx-auto space-y-8">
// // //         <div>
// // //           <h1 className="font-display text-3xl font-bold text-foreground">Doctor Dashboard</h1>
// // //           <p className="text-muted-foreground mt-1">Welcome back, Dr. Sarah Chen</p>
// // //         </div>

// // //         {/* Stats */}
// // //         <div className="grid md:grid-cols-3 gap-4">
// // //           {stats.map((stat, i) => (
// // //             <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
// // //               <div className="flex items-center justify-between mb-4">
// // //                 <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center">
// // //                   <stat.icon size={24} className={stat.color} />
// // //                 </div>
// // //                 <span className="text-xs text-success font-semibold flex items-center gap-1">
// // //                   <TrendingUp size={12} /> {stat.trend}
// // //                 </span>
// // //               </div>
// // //               <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 + i * 0.1 }}>
// // //                 <div className="font-display text-3xl font-bold text-foreground">{stat.value}</div>
// // //                 <div className="text-sm text-muted-foreground mt-1">{stat.label}</div>
// // //               </motion.div>
// // //             </GlassCard>
// // //           ))}
// // //         </div>

// // //         {/* Appointments Feed */}
// // //         <GlassCard className="p-6" tilt={false} delay={0.3}>
// // //           <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// // //             <Calendar size={18} className="text-accent" /> Today's Schedule
// // //           </h3>
// // //           <div className="space-y-3">
// // //             {appointments.map((apt, i) => (
// // //               <motion.div
// // //                 key={apt.id}
// // //                 initial={{ opacity: 0, x: -10 }}
// // //                 animate={{ opacity: 1, x: 0 }}
// // //                 transition={{ delay: 0.5 + i * 0.08 }}
// // //                 className="glass rounded-xl p-4 flex items-center justify-between hover:shadow-glow-accent transition-all duration-300"
// // //               >
// // //                 <div className="flex items-center gap-3">
// // //                   <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center text-sm font-bold text-accent">
// // //                     {apt.patient.charAt(0)}
// // //                   </div>
// // //                   <div>
// // //                     <p className="font-medium text-foreground text-sm">{apt.patient}</p>
// // //                     <p className="text-xs text-muted-foreground flex items-center gap-1"><Clock size={10} /> {apt.time} · {apt.type}</p>
// // //                   </div>
// // //                 </div>
// // //                 {apt.status === "upcoming" ? (
// // //                   <motion.button
// // //                     animate={apt.time === "2:00 PM" ? { scale: [1, 1.05, 1] } : {}}
// // //                     transition={{ repeat: Infinity, duration: 2 }}
// // //                     className="text-xs px-4 py-2 rounded-xl bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold hover:scale-105 transition-all shadow-glow-accent"
// // //                   >
// // //                     Join Now
// // //                   </motion.button>
// // //                 ) : (
// // //                   <span className="text-xs px-3 py-1 rounded-full bg-success/10 text-success">Done</span>
// // //                 )}
// // //               </motion.div>
// // //             ))}
// // //           </div>
// // //         </GlassCard>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default DoctorDashboard;








// // import { useState, useEffect } from "react";
// // import { motion } from "framer-motion";
// // import { Users, Calendar, Video, TrendingUp, Clock, Loader2 } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import GlassCard from "@/components/GlassCard";
// // import api from "@/lib/api";
// // import { toast } from "sonner";

// // const DoctorDashboard = () => {
// //   const [appointments, setAppointments] = useState<any[]>([]);
// //   const [doctorProfile, setDoctorProfile] = useState<any>(null);
// //   const [loading, setLoading] = useState(true);

// //   const loadDoctorData = async () => {
// //     try {
// //       setLoading(true);
// //       // 1. Get current user from LocalStorage
// //       const user = JSON.parse(localStorage.getItem("user") || "{}");
      
// //       // 2. Fetch Doctor Profile to get the doctorId
// //       // We'll use a specific endpoint or filter the list to find this user
// //       const allDocs = await api.get("/admin/doctors");
// //       const currentDoc = allDocs.data.find((d: any) => d.userId === user.userId || d.user?.id === user.userId);
// //       setDoctorProfile(currentDoc);

// //       if (currentDoc) {
// //         // 3. Fetch Today's Bookings for this Doctor
// //         const bookingsRes = await api.get(`/bookings/doctor/${currentDoc.id}`);
// //         setAppointments(Array.isArray(bookingsRes.data) ? bookingsRes.data : []);
// //       }
// //     } catch (err) {
// //       console.error("Doctor Load Error:", err);
// //       toast.error("Failed to load clinical schedule.");
// //     } finally {
// //       setLoading(false);
// //     }
// //   };

// //   useEffect(() => { loadDoctorData(); }, []);

// //   // --- ACTION: START CONSULTATION ---
// //   const handleStartSession = async (bookingId: string) => {
// //     try {
// //       const res = await api.post(`/consultations/start/${bookingId}`);
// //       toast.success("Consultation session initialized.");
// //       // Redirect to a video call or notes page
// //       window.location.href = `/doctor/consultation/${res.data.id}`; 
// //     } catch (err) {
// //       toast.error("Could not start session. Verify booking status.");
// //     }
// //   };

// //   // Derived Stats
// //   const stats = [
// //     { label: "Patients Seen", value: appointments.filter(a => a.status === 'COMPLETED').length.toString(), icon: Users, color: "text-accent", trend: "+12%" },
// //     { label: "Today's Appointments", value: appointments.length.toString(), icon: Calendar, color: "text-success", trend: "Live" },
// //     { label: "Next Session", value: appointments.find(a => a.status === 'CONFIRMED')?.patientName || "None", icon: Video, color: "text-warning", trend: "Ready" },
// //   ];

// //   if (loading) return <div className="min-h-screen flex items-center justify-center"><Loader2 className="animate-spin text-accent" /></div>;

// //   return (
// //     <DashboardLayout role="doctor">
// //       <div className="max-w-6xl mx-auto space-y-8">
// //         <div>
// //           <h1 className="font-display text-3xl font-bold text-foreground">Clinical Workspace</h1>
// //           <p className="text-muted-foreground mt-1">Welcome back, Dr. {doctorProfile?.fullName || "Specialist"}</p>
// //         </div>

// //         {/* Stats Grid */}
// //         <div className="grid md:grid-cols-3 gap-4">
// //           {stats.map((stat, i) => (
// //             <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
// //               <div className="flex items-center justify-between mb-4">
// //                 <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center">
// //                   <stat.icon size={24} className={stat.color} />
// //                 </div>
// //                 <span className="text-xs text-success font-semibold flex items-center gap-1"><TrendingUp size={12} /> {stat.trend}</span>
// //               </div>
// //               <div className="font-display text-3xl font-bold text-foreground">{stat.value}</div>
// //               <div className="text-sm text-muted-foreground mt-1">{stat.label}</div>
// //             </GlassCard>
// //           ))}
// //         </div>

// //         {/* Appointments Feed */}
// //         <GlassCard className="p-6" tilt={false}>
// //           <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// //             <Calendar size={18} className="text-accent" /> Today's Schedule
// //           </h3>
// //           <div className="space-y-3">
// //             {appointments.length > 0 ? appointments.map((apt, i) => (
// //               <motion.div key={apt.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.08 }}
// //                 className="glass rounded-xl p-4 flex items-center justify-between hover:shadow-glow-accent transition-all"
// //               >
// //                 <div className="flex items-center gap-3">
// //                   <div className="w-10 h-10 rounded-full bg-accent/10 flex items-center justify-center text-sm font-bold text-accent">
// //                     {apt.patientName?.charAt(0) || "P"}
// //                   </div>
// //                   <div>
// //                     <p className="font-medium text-foreground text-sm">{apt.patientName}</p>
// //                     <p className="text-xs text-muted-foreground flex items-center gap-1">
// //                       <Clock size={10} /> {new Date(apt.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · Video
// //                     </p>
// //                   </div>
// //                 </div>
// //                 {apt.status !== "COMPLETED" ? (
// //                   <button 
// //                     onClick={() => handleStartSession(apt.id)}
// //                     className="text-xs px-4 py-2 rounded-xl bg-gradient-to-r from-primary to-accent text-accent-foreground font-bold hover:scale-105 transition-all shadow-glow-accent"
// //                   >
// //                     Start Session
// //                   </button>
// //                 ) : (
// //                   <span className="text-xs px-3 py-1 rounded-full bg-success/10 text-success">Completed</span>
// //                 )}
// //               </motion.div>
// //             )) : (
// //               <div className="text-center py-10 text-muted-foreground text-sm">No appointments scheduled for today.</div>
// //             )}
// //           </div>
// //         </GlassCard>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default DoctorDashboard;


















// import { useState, useEffect } from "react";
// import { motion } from "framer-motion";
// import { Users, Calendar, Video, TrendingUp, Clock, Loader2, UserCheck } from "lucide-react";
// import DashboardLayout from "@/components/DashboardLayout";
// import GlassCard from "@/components/GlassCard";
// import api from "@/lib/api";
// import { toast } from "sonner";
// import { useNavigate } from "react-router-dom";

// const DoctorDashboard = () => {
//   const navigate = useNavigate();
//   const [appointments, setAppointments] = useState<any[]>([]);
//   const [userProfile, setUserProfile] = useState<any>(null);
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     const loadDashboard = async () => {
//       try {
//         setLoading(true);
        
//         // 1. Use the pre-established auth data from LocalStorage
//         const user = JSON.parse(localStorage.getItem("user") || "{}");
//         const doctorId = localStorage.getItem("doctorId") || localStorage.getItem("userId");
//         setUserProfile(user);

//         if (!doctorId) {
//           toast.error("Doctor identity not found. Please re-login.");
//           navigate("/login");
//           return;
//         }

//         // 2. FIX: Fetch from the correct DOCTOR endpoint (Avoids 403 Forbidden)
//         const bookingsRes = await api.get(`/bookings/doctor/${doctorId}`);
//         setAppointments(Array.isArray(bookingsRes.data) ? bookingsRes.data : []);
        
//       } catch (err) {
//         console.error("Dashboard Sync Failed:", err);
//       } finally {
//         setLoading(false);
//       }
//     };
//     loadDashboard();
//   }, [navigate]);

//   // --- ACTION: INITIALIZE LIVE SESSION ---
//   const handleStartSession = async (bookingId: string) => {
//     try {
//       // Hits @PostMapping("/start/{bookingId}") to record session start in DB
//       await api.post(`/consultations/start/${bookingId}`);
//       toast.success("Medical room initialized.");
//       // Redirect to the consultation room using the standardized booking reference
//       navigate(`/doctor/consultation/${bookingId}`);
//     } catch (err) {
//       toast.error("Handshake failed. Verify appointment status.");
//     }
//   };

//   // Stats Derived from real BookingResponse DTO
//   const stats = [
//     { 
//         label: "Total Sessions", 
//         value: appointments.length.toString(), 
//         icon: Users, color: "text-accent", trend: "Today" 
//     },
//     { 
//         label: "Confirmed Calls", 
//         value: appointments.filter(a => a.status === 'CONFIRMED').length.toString(), 
//         icon: Calendar, color: "text-success", trend: "Live" 
//     },
//     { 
//         label: "Completed", 
//         value: appointments.filter(a => a.status === 'COMPLETED').length.toString(), 
//         icon: UserCheck, color: "text-primary", trend: "History" 
//     },
//   ];

//   if (loading) return (
//     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
//       <Loader2 className="animate-spin text-accent h-12 w-12 mb-4" />
//       <p className="text-muted-foreground animate-pulse font-medium">Syncing clinical schedule...</p>
//     </div>
//   );

//   return (
//     <DashboardLayout role="doctor">
//       <div className="max-w-6xl mx-auto space-y-8">
//         <div>
//           <h1 className="font-display text-3xl font-bold text-foreground">Doctor Workspace</h1>
//           <p className="text-muted-foreground mt-1">
//             Welcome back, Dr. {userProfile?.firstName || "Specialist"}
//           </p>
//         </div>

//         {/* Stats Section */}
//         <div className="grid md:grid-cols-3 gap-4">
//           {stats.map((stat, i) => (
//             <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
//               <div className="flex items-center justify-between mb-4">
//                 <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center">
//                   <stat.icon size={24} className={stat.color} />
//                 </div>
//                 <span className="text-[10px] font-black uppercase tracking-wider text-muted-foreground opacity-40">{stat.trend}</span>
//               </div>
//               <div className="font-display text-3xl font-bold text-foreground">{stat.value}</div>
//               <div className="text-xs text-muted-foreground mt-1 font-medium">{stat.label}</div>
//             </GlassCard>
//           ))}
//         </div>

//         {/* Real Schedule Feed mapped from BookingResponse DTO */}
//         <GlassCard className="p-8" delay={0.3}>
//           <h3 className="font-display text-lg font-bold text-foreground mb-6 flex items-center gap-2">
//             <Clock size={18} className="text-accent" /> Clinical Queue
//           </h3>
//           <div className="space-y-4">
//             {appointments.length > 0 ? appointments.slice(0, 5).map((apt, i) => (
//               <motion.div
//                 key={apt.bookingId}
//                 initial={{ opacity: 0, x: -10 }}
//                 animate={{ opacity: 1, x: 0 }}
//                 transition={{ delay: 0.5 + i * 0.08 }}
//                 className="glass rounded-2xl p-5 flex items-center justify-between hover:shadow-glow-accent transition-all border-white/5"
//               >
//                 <div className="flex items-center gap-4">
//                   <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center text-sm font-bold text-accent border border-accent/20">
//                     {apt.patientName?.charAt(0) || "P"}
//                   </div>
//                   <div>
//                     <p className="font-bold text-foreground text-sm">{apt.patientName || "Verified Patient"}</p>
//                     <p className="text-[10px] text-muted-foreground flex items-center gap-1 mt-0.5">
//                         <Clock size={10} /> 
//                         {new Date(apt.appointmentTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}
//                     </p>
//                   </div>
//                 </div>
                
//                 <div className="flex items-center gap-4">
//                     <span className={`text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-tighter ${
//                         apt.status === 'CONFIRMED' ? 'bg-success/10 text-success' : 'bg-white/5 text-muted-foreground'
//                     }`}>
//                         {apt.status}
//                     </span>
//                     {apt.status === 'CONFIRMED' && (
//                         <button 
//                             onClick={() => handleStartSession(apt.bookingId)}
//                             className="text-xs px-6 py-2.5 rounded-xl bg-accent text-accent-foreground font-bold hover:scale-105 transition-all shadow-glow-accent active:scale-95"
//                         >
//                             Enter Room
//                         </button>
//                     )}
//                 </div>
//               </motion.div>
//             )) : (
//               <div className="text-center py-20 bg-white/5 rounded-3xl border border-dashed border-white/10">
//                  <UserCheck size={40} className="mx-auto text-muted-foreground/20 mb-3" />
//                  <p className="text-muted-foreground text-sm italic font-medium">No clinical sessions on the radar today.</p>
//               </div>
//             )}
//           </div>
//         </GlassCard>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default DoctorDashboard;







import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Users, Calendar, Video, TrendingUp, Clock, Loader2, UserCheck, ArrowRight } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import api from "@/lib/api";
import { toast } from "sonner";
import { useNavigate } from "react-router-dom";

const DoctorDashboard = () => {
  const navigate = useNavigate();
  const [appointments, setAppointments] = useState<any[]>([]);
  const [userProfile, setUserProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        setLoading(true);
        
        // 1. Retrieve the identity data stored by authService
        const user = JSON.parse(localStorage.getItem("user") || "{}");
        const doctorId = localStorage.getItem("doctorId");
        setUserProfile(user);

        if (!doctorId) {
          toast.error("Clinical identity not found. Please log in again.");
          navigate("/login");
          return;
        }

        // 2. Fetch the queue using the correct DOCTOR ID
        // This avoids hitting the /api/admin paths that caused 403 Forbidden errors.
        const bookingsRes = await api.get(`/bookings/doctor/${doctorId}`);
        setAppointments(Array.isArray(bookingsRes.data) ? bookingsRes.data : []);
        
      } catch (err) {
        console.error("Dashboard Sync Failed:", err);
      } finally {
        setLoading(false);
      }
    };
    loadDashboard();
  }, [navigate]);

  // --- ACTION: START CONSULTATION ---
  const handleStartSession = async (bookingId: string) => {
    try {
      // Handshake with backend to mark the session as 'Active' in DB
      await api.post(`/consultations/start/${bookingId}`);
      toast.success("Medical room initialized.");
      // Redirect to the consultation workspace
      navigate(`/doctor/consultation/${bookingId}`);
    } catch (err) {
      toast.error("Could not start session. Verify appointment status.");
    }
  };

  // Stats Derived from real BookingResponse DTO
  const stats = [
    { 
        label: "Total Sessions", 
        value: appointments.length.toString(), 
        icon: Users, color: "text-accent", trend: "Today" 
    },
    { 
        label: "Confirmed Calls", 
        value: appointments.filter(a => a.status === 'CONFIRMED').length.toString(), 
        icon: Video, color: "text-success", trend: "Live" 
    },
    { 
        label: "Completed", 
        value: appointments.filter(a => a.status === 'COMPLETED').length.toString(), 
        icon: UserCheck, color: "text-primary", trend: "History" 
    },
  ];

  if (loading) return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background">
      <Loader2 className="animate-spin text-accent h-10 w-10 mb-4" />
      <p className="text-muted-foreground animate-pulse font-medium">Syncing clinical workspace...</p>
    </div>
  );

  return (
    <DashboardLayout role="doctor">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="font-display text-3xl font-bold text-foreground">Doctor Workspace</h1>
            <p className="text-muted-foreground mt-1">
              Welcome back, Dr. {userProfile?.firstName || "Specialist"}
            </p>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 glass rounded-2xl text-[10px] font-bold text-success uppercase tracking-widest">
            <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" /> Clinical Sync Active
          </div>
        </div>

        {/* Real-Time Stats Grid */}
        <div className="grid md:grid-cols-3 gap-4">
          {stats.map((stat, i) => (
            <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center">
                  <stat.icon size={24} className={stat.color} />
                </div>
                <span className="text-[10px] font-black uppercase tracking-wider text-muted-foreground opacity-40">{stat.trend}</span>
              </div>
              <div className="font-display text-3xl font-bold text-foreground">{stat.value}</div>
              <div className="text-xs text-muted-foreground mt-1 font-medium">{stat.label}</div>
            </GlassCard>
          ))}
        </div>

        {/* Real Clinical Queue mapped from BookingResponse DTO */}
        <GlassCard className="p-8" delay={0.3}>
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-display text-lg font-bold text-foreground flex items-center gap-2">
              <Clock size={18} className="text-accent" /> Clinical Queue
            </h3>
            <button onClick={() => navigate("/doctor/appointments")} className="text-xs font-bold text-accent hover:underline">View Full Schedule</button>
          </div>
          
          <div className="space-y-4">
            {appointments.length > 0 ? appointments.slice(0, 5).map((apt, i) => (
              <motion.div
                key={apt.bookingId}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.5 + i * 0.08 }}
                className="glass rounded-2xl p-5 flex items-center justify-between hover:shadow-glow-accent transition-all border-white/5"
              >
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center text-sm font-bold text-accent border border-accent/20">
                    {apt.patientName?.charAt(0) || "P"}
                  </div>
                  <div>
                    <p className="font-bold text-foreground text-sm">{apt.patientName || "Verified Patient"}</p>
                    <p className="text-[10px] text-muted-foreground flex items-center gap-1 mt-0.5 font-medium uppercase tracking-tighter">
                        <Calendar size={10} className="text-accent" /> 
                        {new Date(apt.appointmentTime).toLocaleDateString()} at {new Date(apt.appointmentTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center gap-4">
                    <span className={`text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-tighter ${
                        apt.status === 'CONFIRMED' ? 'bg-success/10 text-success' : 'bg-white/5 text-muted-foreground'
                    }`}>
                        {apt.status}
                    </span>
                    {apt.status === 'CONFIRMED' && (
                        <button 
                            onClick={() => handleStartSession(apt.bookingId)}
                            className="text-xs px-6 py-2.5 rounded-xl bg-accent text-accent-foreground font-bold hover:scale-105 transition-all shadow-glow-accent active:scale-95 flex items-center gap-2"
                        >
                            Start Call <ArrowRight size={14} />
                        </button>
                    )}
                </div>
              </motion.div>
            )) : (
              <div className="text-center py-20 bg-white/5 rounded-3xl border border-dashed border-white/10">
                 <UserCheck size={40} className="mx-auto text-muted-foreground/20 mb-3" />
                 <p className="text-muted-foreground text-sm italic font-medium">No clinical sessions on the radar for today.</p>
              </div>
            )}
          </div>
        </GlassCard>
      </div>
    </DashboardLayout>
  );
};

export default DoctorDashboard;