// // // // import { motion } from "framer-motion";
// // // // import { Calendar, Clock, Video, User, Filter } from "lucide-react";
// // // // import DashboardLayout from "@/components/DashboardLayout";

// // // // const appointments = [
// // // //   { id: 1, patient: "Alex Thompson", date: "Feb 13, 2026", time: "10:00 AM", type: "Video", condition: "Follow-up Cardiology", status: "confirmed" },
// // // //   { id: 2, patient: "Maria Garcia", date: "Feb 13, 2026", time: "11:30 AM", type: "Video", condition: "Skin Allergy", status: "confirmed" },
// // // //   { id: 3, patient: "John Smith", date: "Feb 13, 2026", time: "2:00 PM", type: "Video", condition: "Migraine Assessment", status: "pending" },
// // // //   { id: 4, patient: "Sarah Johnson", date: "Feb 14, 2026", time: "9:00 AM", type: "In-Person", condition: "Annual Checkup", status: "confirmed" },
// // // //   { id: 5, patient: "David Lee", date: "Feb 14, 2026", time: "10:30 AM", type: "Video", condition: "Chest Pain", status: "confirmed" },
// // // //   { id: 6, patient: "Emma Wilson", date: "Feb 14, 2026", time: "2:00 PM", type: "Video", condition: "General Consultation", status: "pending" },
// // // // ];

// // // // const DoctorAppointments = () => {
// // // //   return (
// // // //     <DashboardLayout role="doctor">
// // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // //         <div className="flex items-center justify-between">
// // // //           <div>
// // // //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // //               <Calendar size={28} className="text-accent" /> Appointments
// // // //             </h1>
// // // //             <p className="text-muted-foreground mt-1">Manage your upcoming appointments</p>
// // // //           </div>
// // // //           <button className="glass rounded-xl px-4 py-2 text-sm font-medium text-foreground hover:shadow-glow-accent transition-all flex items-center gap-2">
// // // //             <Filter size={14} /> Filter
// // // //           </button>
// // // //         </div>

// // // //         <div className="space-y-3">
// // // //           {appointments.map((apt, i) => (
// // // //             <motion.div
// // // //               key={apt.id}
// // // //               initial={{ opacity: 0, y: 20 }}
// // // //               whileInView={{ opacity: 1, y: 0 }}
// // // //               viewport={{ once: true }}
// // // //               transition={{ delay: i * 0.08 }}
// // // //               className="glass rounded-2xl p-5 shadow-float hover:shadow-float-lg transition-all duration-500 group"
// // // //             >
// // // //               <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
// // // //                 <div className="flex items-center gap-3">
// // // //                   <div className="w-11 h-11 rounded-full bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center text-accent font-bold">
// // // //                     {apt.patient.charAt(0)}
// // // //                   </div>
// // // //                   <div>
// // // //                     <h3 className="font-display font-bold text-foreground text-sm">{apt.patient}</h3>
// // // //                     <p className="text-xs text-muted-foreground">{apt.condition}</p>
// // // //                   </div>
// // // //                 </div>
// // // //                 <div className="flex items-center gap-4">
// // // //                   <div className="text-xs text-muted-foreground space-y-0.5">
// // // //                     <div className="flex items-center gap-1"><Calendar size={12} /> {apt.date}</div>
// // // //                     <div className="flex items-center gap-1"><Clock size={12} /> {apt.time}</div>
// // // //                   </div>
// // // //                   <div className="flex items-center gap-2">
// // // //                     <span className={`text-xs px-2 py-1 rounded-full ${
// // // //                       apt.status === "confirmed" ? "bg-success/10 text-success" : "bg-warning/10 text-warning"
// // // //                     }`}>
// // // //                       {apt.status}
// // // //                     </span>
// // // //                     {apt.type === "Video" && (
// // // //                       <button className="text-xs px-3 py-2 rounded-xl bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold hover:scale-105 transition-all opacity-0 group-hover:opacity-100">
// // // //                         <Video size={12} />
// // // //                       </button>
// // // //                     )}
// // // //                   </div>
// // // //                 </div>
// // // //               </div>
// // // //             </motion.div>
// // // //           ))}
// // // //         </div>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );
// // // // };

// // // // export default DoctorAppointments;









// // // import { useState, useEffect } from "react";
// // // import { motion } from "framer-motion";
// // // import { Calendar, Clock, Video, User, Filter, Loader2 } from "lucide-react";
// // // import { useNavigate } from "react-router-dom";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import api from "@/lib/api";

// // // const DoctorAppointments = () => {
// // //   const navigate = useNavigate();
// // //   const [appointments, setAppointments] = useState<any[]>([]);
// // //   const [loading, setLoading] = useState(true);

// // //   useEffect(() => {
// // //     const fetchAppointments = async () => {
// // //       try {
// // //         setLoading(true);
// // //         // Get doctorId from storage
// // //         const doctorId = localStorage.getItem("doctorId") || localStorage.getItem("userId");
// // //         const res = await api.get(`/bookings/doctor/${doctorId}`);
// // //         setAppointments(Array.isArray(res.data) ? res.data : []);
// // //       } catch (err) {
// // //         console.error("Fetch failed", err);
// // //       } finally {
// // //         setLoading(false);
// // //       }
// // //     };
// // //     fetchAppointments();
// // //   }, []);

// // //   return (
// // //     <DashboardLayout role="doctor">
// // //       <div className="max-w-4xl mx-auto space-y-8">
// // //         <div className="flex items-center justify-between">
// // //           <div>
// // //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // //               <Calendar size={28} className="text-accent" /> Appointments
// // //             </h1>
// // //             <p className="text-muted-foreground mt-1">Manage your patient schedule</p>
// // //           </div>
// // //           <button className="glass rounded-xl px-4 py-2 text-sm font-medium text-foreground hover:shadow-glow-accent transition-all flex items-center gap-2">
// // //             <Filter size={14} /> Filter
// // //           </button>
// // //         </div>

// // //         {loading ? (
// // //           <div className="flex justify-center py-20"><Loader2 className="animate-spin text-accent" /></div>
// // //         ) : (
// // //           <div className="space-y-3">
// // //             {appointments.map((apt, i) => (
// // //               <motion.div
// // //                 key={apt.bookingId}
// // //                 initial={{ opacity: 0, y: 20 }}
// // //                 animate={{ opacity: 1, y: 0 }}
// // //                 transition={{ delay: i * 0.08 }}
// // //                 className="glass rounded-2xl p-5 shadow-float hover:shadow-float-lg transition-all duration-500 group"
// // //               >
// // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
// // //                   <div className="flex items-center gap-3">
// // //                     <div className="w-11 h-11 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold">
// // //                       {apt.patientName?.charAt(0) || "P"}
// // //                     </div>
// // //                     <div>
// // //                       <h3 className="font-display font-bold text-foreground text-sm">{apt.patientName || "Patient"}</h3>
// // //                       <p className="text-xs text-muted-foreground">Digital Consultation</p>
// // //                     </div>
// // //                   </div>
// // //                   <div className="flex items-center gap-4">
// // //                     <div className="text-xs text-muted-foreground space-y-0.5">
// // //                       <div className="flex items-center gap-1"><Calendar size={12} /> {new Date(apt.appointmentTime).toLocaleDateString()}</div>
// // //                       <div className="flex items-center gap-1"><Clock size={12} /> {new Date(apt.appointmentTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
// // //                     </div>
// // //                     <div className="flex items-center gap-3">
// // //                       <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-full ${
// // //                         apt.status === "CONFIRMED" ? "bg-success/10 text-success" : "bg-warning/10 text-warning"
// // //                       }`}>
// // //                         {apt.status}
// // //                       </span>
// // //                       {/* Navigate to the room for this specific bookingId */}
// // //                       <button 
// // //                         onClick={() => navigate(`/doctor/consultation/${apt.bookingId}`)}
// // //                         className="text-xs px-4 py-2 rounded-xl bg-accent text-accent-foreground font-bold hover:scale-105 transition-all shadow-glow-accent"
// // //                       >
// // //                         Join Call
// // //                       </button>
// // //                     </div>
// // //                   </div>
// // //                 </div>
// // //               </motion.div>
// // //             ))}
// // //           </div>
// // //         )}
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default DoctorAppointments;














// // import { useState, useEffect } from "react";
// // import { motion } from "framer-motion";
// // import { Calendar, Clock, Filter, Loader2, UserCheck, ArrowRight } from "lucide-react";
// // import { useNavigate } from "react-router-dom";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import api from "@/lib/api";

// // const DoctorAppointments = () => {
// //   const navigate = useNavigate();
// //   const [appointments, setAppointments] = useState<any[]>([]);
// //   const [loading, setLoading] = useState(true);

// //   useEffect(() => {
// //     const fetchAppointments = async () => {
// //       try {
// //         setLoading(true);
// //         // Identify the doctor from LocalStorage
// //         const doctorId = localStorage.getItem("doctorId") || localStorage.getItem("userId");
        
// //         // Fetch from: http://localhost:8080/api/bookings/doctor/{id}
// //         const res = await api.get(`/bookings/doctor/${doctorId}`);
// //         setAppointments(Array.isArray(res.data) ? res.data : []);
// //       } catch (err) {
// //         console.error("Schedule sync failed:", err);
// //       } finally {
// //         setLoading(false);
// //       }
// //     };
// //     fetchAppointments();
// //   }, []);

// //   return (
// //     <DashboardLayout role="doctor">
// //       <div className="max-w-5xl mx-auto space-y-8">
// //         <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
// //           <div>
// //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// //               <UserCheck size={28} className="text-accent" /> Patient Schedule
// //             </h1>
// //             <p className="text-muted-foreground mt-1">Confirmed clinical sessions for today and beyond</p>
// //           </div>
// //           <div className="flex gap-2">
// //              <button className="glass rounded-xl px-5 py-2.5 text-sm font-bold text-foreground hover:shadow-glow-accent transition-all flex items-center gap-2">
// //                <Filter size={14} /> Filter List
// //              </button>
// //           </div>
// //         </div>

// //         {loading ? (
// //           <div className="flex flex-col items-center justify-center py-32 space-y-4">
// //              <Loader2 className="animate-spin text-accent" size={40} />
// //              <p className="text-sm text-muted-foreground">Synchronizing clinical data...</p>
// //           </div>
// //         ) : (
// //           <div className="grid gap-4">
// //             {appointments.length > 0 ? appointments.map((apt, i) => (
// //               <motion.div
// //                 key={apt.bookingId}
// //                 initial={{ opacity: 0, x: -20 }}
// //                 animate={{ opacity: 1, x: 0 }}
// //                 transition={{ delay: i * 0.05 }}
// //                 className="glass rounded-3xl p-6 hover:shadow-glow-accent border-white/5 transition-all group"
// //               >
// //                 <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
// //                   <div className="flex items-center gap-4">
// //                     <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center text-accent font-bold text-xl border border-accent/20">
// //                       {apt.patientName?.charAt(0) || "P"}
// //                     </div>
// //                     <div>
// //                       <h3 className="font-display text-lg font-bold text-foreground">{apt.patientName || "Verified Patient"}</h3>
// //                       <p className="text-xs text-muted-foreground uppercase tracking-widest font-medium opacity-60">Digital Consultation</p>
// //                     </div>
// //                   </div>

// //                   <div className="flex flex-wrap items-center gap-6">
// //                     <div className="text-xs text-muted-foreground space-y-1">
// //                       <div className="flex items-center gap-2 font-medium bg-white/5 px-3 py-1 rounded-lg">
// //                         <Calendar size={14} className="text-accent" /> {new Date(apt.appointmentTime).toLocaleDateString()}
// //                       </div>
// //                       <div className="flex items-center gap-2 font-medium bg-white/5 px-3 py-1 rounded-lg">
// //                         <Clock size={14} className="text-accent" /> {new Date(apt.appointmentTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// //                       </div>
// //                     </div>
                    
// //                     <div className="flex items-center gap-4">
// //                       <span className={`text-[10px] font-black uppercase tracking-tighter px-3 py-1 rounded-full ${
// //                         apt.status === "CONFIRMED" ? "bg-success/10 text-success" : "bg-white/5 text-muted-foreground"
// //                       }`}>
// //                         {apt.status}
// //                       </span>
// //                       {/* Enters the live room using the specific booking reference */}
// //                       <button 
// //                         onClick={() => navigate(`/doctor/consultation/${apt.bookingId}`)}
// //                         className="flex items-center gap-2 px-6 py-3 rounded-2xl bg-accent text-accent-foreground font-bold hover:scale-105 transition-all shadow-glow-accent active:scale-95"
// //                       >
// //                         Start Session <ArrowRight size={16} />
// //                       </button>
// //                     </div>
// //                   </div>
// //                 </div>
// //               </motion.div>
// //             )) : (
// //               <div className="text-center py-24 glass rounded-3xl border-dashed border-2 border-white/5">
// //                  <UserCheck size={48} className="mx-auto text-muted-foreground/20 mb-4" />
// //                  <p className="text-muted-foreground text-sm italic">No patients scheduled at the moment.</p>
// //               </div>
// //             )}
// //           </div>
// //         )}
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default DoctorAppointments;







// import { useState, useEffect } from "react";
// import { motion } from "framer-motion";
// import { Calendar, Clock, Filter, Loader2, UserCheck, ArrowRight } from "lucide-react";
// import { useNavigate } from "react-router-dom";
// import DashboardLayout from "@/components/DashboardLayout";
// import api from "@/lib/api";

// const DoctorAppointments = () => {
//   const navigate = useNavigate();
//   const [appointments, setAppointments] = useState<any[]>([]);
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     const fetchAppointments = async () => {
//       try {
//         setLoading(true);
//         // Ensure we use 'userId' as the doctor's identifier
//         const doctorId = localStorage.getItem("userId");
//         if (!doctorId) throw new Error("Doctor session not found.");
        
//         // Correct endpoint matching your BookingController
//         const res = await api.get(`/bookings/doctor/${doctorId}`);
//         setAppointments(Array.isArray(res.data) ? res.data : []);
//       } catch (err) {
//         console.error("Fetch failed", err);
//       } finally {
//         setLoading(false);
//       }
//     };
//     fetchAppointments();
//   }, []);

//   return (
//     <DashboardLayout role="doctor">
//       <div className="max-w-5xl mx-auto space-y-8">
//         <div>
//           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
//             <Calendar size={28} className="text-accent" /> Appointments
//           </h1>
//           <p className="text-muted-foreground mt-1">Manage your upcoming patient sessions</p>
//         </div>

//         {loading ? (
//           <div className="flex justify-center py-20"><Loader2 className="animate-spin text-accent" /></div>
//         ) : (
//           <div className="space-y-3">
//             {appointments.length > 0 ? appointments.map((apt, i) => (
//               <motion.div
//                 key={apt.bookingId}
//                 initial={{ opacity: 0, y: 15 }}
//                 animate={{ opacity: 1, y: 0 }}
//                 transition={{ delay: i * 0.05 }}
//                 className="glass rounded-2xl p-5 hover:shadow-glow-accent transition-all group border-white/5"
//               >
//                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
//                   <div className="flex items-center gap-4">
//                     <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center text-accent font-bold">
//                       {apt.patientName?.charAt(0) || "P"}
//                     </div>
//                     <div>
//                       {/* Note: This depends on the DTO change mentioned above */}
//                       <h3 className="font-display font-bold text-foreground">{apt.patientName || "Verified Patient"}</h3>
//                       <p className="text-[10px] uppercase tracking-widest text-muted-foreground">Digital Consultation</p>
//                     </div>
//                   </div>
//                   <div className="flex items-center gap-6">
//                     <div className="text-xs text-muted-foreground">
//                       <div className="flex items-center gap-1"><Clock size={12} className="text-accent"/> {new Date(apt.appointmentTime).toLocaleString()}</div>
//                     </div>
//                     <button 
//                       onClick={() => navigate(`/doctor/consultation/${apt.bookingId}`)}
//                       className="px-6 py-2.5 rounded-xl bg-accent text-accent-foreground text-xs font-bold hover:scale-105 transition-all shadow-glow-accent"
//                     >
//                       Start Session
//                     </button>
//                   </div>
//                 </div>
//               </motion.div>
//             )) : (
//               <div className="text-center py-20 glass rounded-3xl border-dashed border-2">
//                  <p className="text-muted-foreground italic">No confirmed appointments found in your schedule.</p>
//               </div>
//             )}
//           </div>
//         )}
//       </div>
//     </DashboardLayout>
//   );
// };

// export default DoctorAppointments;
















import { useState, useEffect } from "react";
import { motion } from "framer-motion";
// FIX: Kept UserCheck here as an import from Lucide
import { Calendar, Clock, Loader2, UserCheck, ArrowRight, Filter } from "lucide-react"; 
import { useNavigate } from "react-router-dom";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";
import { toast } from "sonner";

const DoctorAppointments = () => {
  const navigate = useNavigate();
  const [appointments, setAppointments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAppointments = async () => {
      try {
        setLoading(true);
        // 1. CRITICAL: Identify the doctor using the specific Specialist ID
        const doctorId = localStorage.getItem("doctorId") || localStorage.getItem("userId");
        
        if (!doctorId) {
          toast.error("Session expired. Please log in again.");
          navigate("/login");
          return;
        }

        // 2. Fetch schedule from http://localhost:8080/api/bookings/doctor/{id}
        const res = await api.get(`/bookings/doctor/${doctorId}`);
        setAppointments(Array.isArray(res.data) ? res.data : []);
      } catch (err) {
        console.error("Schedule sync failure:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchAppointments();
  }, [navigate]);

  return (
    <DashboardLayout role="doctor">
      <div className="max-w-5xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
              <Calendar size={28} className="text-accent" /> Appointments
            </h1>
            <p className="text-muted-foreground mt-1">Manage your upcoming patient sessions</p>
          </div>
          <button className="glass rounded-xl px-4 py-2 text-sm font-bold text-foreground hover:shadow-glow-accent transition-all flex items-center gap-2">
            <Filter size={14} /> Today
          </button>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-32 space-y-4">
             <Loader2 className="animate-spin text-accent" size={40} />
             <p className="text-sm text-muted-foreground italic">Synchronizing patient data...</p>
          </div>
        ) : (
          <div className="space-y-3">
            {appointments.length > 0 ? appointments.map((apt, i) => (
              <motion.div
                key={apt.bookingId}
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="glass rounded-2xl p-5 hover:shadow-glow-accent transition-all group border-white/5"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center text-accent font-bold">
                      {apt.patientName?.charAt(0) || "P"}
                    </div>
                    <div>
                      {/* Uses patientName from updated BookingResponse DTO */}
                      <h3 className="font-display font-bold text-foreground">{apt.patientName || "Verified Patient"}</h3>
                      <p className="text-[10px] uppercase tracking-widest text-muted-foreground">Video Consultation</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6">
                    <div className="text-xs text-muted-foreground font-medium">
                      <div className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-lg">
                        <Clock size={12} className="text-accent"/> 
                        {new Date(apt.appointmentTime).toLocaleString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}
                      </div>
                    </div>
                    
                    <button 
                      onClick={() => navigate(`/doctor/consultation/${apt.bookingId}`)}
                      className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-accent text-accent-foreground text-xs font-bold hover:scale-105 transition-all shadow-glow-accent active:scale-95"
                    >
                      Start Session <ArrowRight size={14} />
                    </button>
                  </div>
                </div>
              </motion.div>
            )) : (
              <div className="text-center py-20 glass rounded-3xl border-dashed border-2 border-white/10">
                 {/* FIX: Renamed local call to EmptyScheduleIcon to avoid conflict */}
                 <EmptyScheduleIcon size={48} className="mx-auto text-muted-foreground/20 mb-4" />
                 <p className="text-muted-foreground text-sm italic font-medium">Your schedule is currently clear.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

// FIX: Renamed this local component to solve the TS2440 error
const EmptyScheduleIcon = ({ size, className }: { size: number; className?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></svg>
);

export default DoctorAppointments;