// // // // // // // // // // import { motion } from "framer-motion";
// // // // // // // // // // import { Calendar, Download, User, Clock } from "lucide-react";
// // // // // // // // // // import DashboardLayout from "@/components/DashboardLayout";

// // // // // // // // // // const consultations = [
// // // // // // // // // //   { id: 1, doctor: "Dr. Sarah Chen", specialization: "Cardiologist", date: "Feb 5, 2026", time: "10:30 AM", notes: "Routine heart checkup. All vitals normal. Follow-up in 6 months.", status: "completed" },
// // // // // // // // // //   { id: 2, doctor: "Dr. James Wilson", specialization: "General Physician", date: "Jan 15, 2026", time: "2:00 PM", notes: "Annual physical examination completed. Overall health status: Good.", status: "completed" },
// // // // // // // // // //   { id: 3, doctor: "Dr. Priya Sharma", specialization: "Dermatologist", date: "Dec 20, 2025", time: "11:00 AM", notes: "Skin allergy treatment. Prescribed antihistamines. Review in 2 weeks.", status: "completed" },
// // // // // // // // // //   { id: 4, doctor: "Dr. Michael Park", specialization: "Neurologist", date: "Dec 5, 2025", time: "3:30 PM", notes: "Migraine assessment. Recommended lifestyle changes and preventive medication.", status: "completed" },
// // // // // // // // // // ];

// // // // // // // // // // const Consultations = () => {
// // // // // // // // // //   return (
// // // // // // // // // //     <DashboardLayout role="patient">
// // // // // // // // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // // // // // // // //         <div>
// // // // // // // // // //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // // // // // // // //             <Calendar size={28} className="text-accent" />
// // // // // // // // // //             Consultations
// // // // // // // // // //           </h1>
// // // // // // // // // //           <p className="text-muted-foreground mt-1">Your past consultation history</p>
// // // // // // // // // //         </div>

// // // // // // // // // //         <div className="space-y-4">
// // // // // // // // // //           {consultations.map((c, i) => (
// // // // // // // // // //             <motion.div
// // // // // // // // // //               key={c.id}
// // // // // // // // // //               initial={{ opacity: 0, y: 20 }}
// // // // // // // // // //               whileInView={{ opacity: 1, y: 0 }}
// // // // // // // // // //               viewport={{ once: true }}
// // // // // // // // // //               transition={{ delay: i * 0.1 }}
// // // // // // // // // //             >
// // // // // // // // // //               <div className="glass rounded-2xl p-6 shadow-float hover:shadow-float-lg hover:scale-[1.005] transition-all duration-500 group">
// // // // // // // // // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-3">
// // // // // // // // // //                   <div className="flex items-center gap-3">
// // // // // // // // // //                     <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center">
// // // // // // // // // //                       <User size={22} className="text-accent" />
// // // // // // // // // //                     </div>
// // // // // // // // // //                     <div>
// // // // // // // // // //                       <h3 className="font-display font-bold text-foreground">{c.doctor}</h3>
// // // // // // // // // //                       <p className="text-xs text-muted-foreground">{c.specialization}</p>
// // // // // // // // // //                     </div>
// // // // // // // // // //                   </div>
// // // // // // // // // //                   <div className="flex items-center gap-4 text-sm text-muted-foreground">
// // // // // // // // // //                     <span className="flex items-center gap-1"><Calendar size={14} /> {c.date}</span>
// // // // // // // // // //                     <span className="flex items-center gap-1"><Clock size={14} /> {c.time}</span>
// // // // // // // // // //                   </div>
// // // // // // // // // //                 </div>
// // // // // // // // // //                 <p className="text-sm text-muted-foreground leading-relaxed mb-3">{c.notes}</p>
// // // // // // // // // //                 <div className="flex items-center justify-between">
// // // // // // // // // //                   <span className="text-xs px-3 py-1 rounded-full bg-success/10 text-success font-medium">Completed</span>
// // // // // // // // // //                   <button className="flex items-center gap-2 text-sm text-accent font-medium hover:underline opacity-0 group-hover:opacity-100 transition-opacity">
// // // // // // // // // //                     <Download size={14} /> Download PDF
// // // // // // // // // //                   </button>
// // // // // // // // // //                 </div>
// // // // // // // // // //               </div>
// // // // // // // // // //             </motion.div>
// // // // // // // // // //           ))}
// // // // // // // // // //         </div>
// // // // // // // // // //       </div>
// // // // // // // // // //     </DashboardLayout>
// // // // // // // // // //   );
// // // // // // // // // // };

// // // // // // // // // // export default Consultations;
















// // // // // // // // // import { useState, useEffect } from "react";
// // // // // // // // // import { motion } from "framer-motion";
// // // // // // // // // import { Calendar, Download, User, Clock, FileText } from "lucide-react";
// // // // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // // // import api from "@/lib/api";

// // // // // // // // // const Consultations = () => {
// // // // // // // // //   const [history, setHistory] = useState<any[]>([]);

// // // // // // // // //   useEffect(() => {
// // // // // // // // //     const fetchHistory = async () => {
// // // // // // // // //       // You may need to create a specific endpoint for user history in ConsultationController
// // // // // // // // //       const res = await api.get("/api/bookings/patient/my-id"); 
// // // // // // // // //       setHistory(res.data.filter((b: any) => b.status === "COMPLETED"));
// // // // // // // // //     };
// // // // // // // // //     fetchHistory();
// // // // // // // // //   }, []);

// // // // // // // // //   return (
// // // // // // // // //     <DashboardLayout role="patient">
// // // // // // // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // // // // // // //         <h1 className="font-display text-3xl font-bold flex items-center gap-3">
// // // // // // // // //           <FileText size={28} className="text-accent" /> Medical Records
// // // // // // // // //         </h1>
// // // // // // // // //         <div className="space-y-4">
// // // // // // // // //           {history.map((c, i) => (
// // // // // // // // //             <motion.div key={c.bookingId} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
// // // // // // // // //               <div className="glass rounded-2xl p-6 hover:shadow-glow-accent transition-all">
// // // // // // // // //                 <div className="flex justify-between items-start mb-4">
// // // // // // // // //                   <div>
// // // // // // // // //                     <h3 className="font-bold">{c.doctorName}</h3>
// // // // // // // // //                     <p className="text-xs text-muted-foreground">{new Date(c.appointmentTime).toLocaleDateString()}</p>
// // // // // // // // //                   </div>
// // // // // // // // //                   <span className="text-xs px-3 py-1 rounded-full bg-success/10 text-success">Verified</span>
// // // // // // // // //                 </div>
// // // // // // // // //                 <p className="text-sm text-muted-foreground italic">"Notes are securely encrypted in your history."</p>
// // // // // // // // //               </div>
// // // // // // // // //             </motion.div>
// // // // // // // // //           ))}
// // // // // // // // //         </div>
// // // // // // // // //       </div>
// // // // // // // // //     </DashboardLayout>
// // // // // // // // //   );
// // // // // // // // // };

// // // // // // // // // export default Consultations;







// // // // // // // // import { useState, useEffect } from "react";
// // // // // // // // import { motion } from "framer-motion";
// // // // // // // // import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList } from "lucide-react";
// // // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // // import api from "@/lib/api";
// // // // // // // // import { toast } from "sonner";

// // // // // // // // const Consultations = () => {
// // // // // // // //   const [history, setHistory] = useState<any[]>([]);
// // // // // // // //   const [loading, setLoading] = useState(true);

// // // // // // // //   useEffect(() => {
// // // // // // // //     const fetchHistory = async () => {
// // // // // // // //       try {
// // // // // // // //         setLoading(true);
// // // // // // // //         // 1. Get current patient ID from LocalStorage
// // // // // // // //         const userId = localStorage.getItem("userId");
// // // // // // // //         if (!userId) throw new Error("User session not found.");

// // // // // // // //         // 2. Fetch using the specific Consultation history endpoint
// // // // // // // //         // Note: We removed the extra "/api" prefix which caused the 404
// // // // // // // //         const res = await api.get(`/consultations/patient/${userId}`);
        
// // // // // // // //         // Data comes as a list of Consultation entities
// // // // // // // //         setHistory(Array.isArray(res.data) ? res.data : []);
// // // // // // // //       } catch (err) {
// // // // // // // //         console.error("Clinical History Sync Failed:", err);
// // // // // // // //         // toast.error("Failed to sync medical records.");
// // // // // // // //       } finally {
// // // // // // // //         setLoading(false);
// // // // // // // //       }
// // // // // // // //     };
// // // // // // // //     fetchHistory();
// // // // // // // //   }, []);

// // // // // // // //   if (loading) return (
// // // // // // // //     <DashboardLayout role="patient">
// // // // // // // //       <div className="min-h-[60vh] flex items-center justify-center">
// // // // // // // //         <Loader2 className="animate-spin text-accent" size={32} />
// // // // // // // //       </div>
// // // // // // // //     </DashboardLayout>
// // // // // // // //   );

// // // // // // // //   return (
// // // // // // // //     <DashboardLayout role="patient">
// // // // // // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // // // // // //         <div>
// // // // // // // //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // // // // // //             <FileText size={28} className="text-accent" /> Medical Records
// // // // // // // //           </h1>
// // // // // // // //           <p className="text-muted-foreground mt-1">Verified clinical notes and consultation summaries</p>
// // // // // // // //         </div>

// // // // // // // //         <div className="space-y-4">
// // // // // // // //           {history.length > 0 ? history.map((c, i) => (
// // // // // // // //             <motion.div
// // // // // // // //               key={c.id}
// // // // // // // //               initial={{ opacity: 0, y: 10 }}
// // // // // // // //               animate={{ opacity: 1, y: 0 }}
// // // // // // // //               transition={{ delay: i * 0.1 }}
// // // // // // // //             >
// // // // // // // //               <div className="glass rounded-2xl p-6 shadow-float hover:shadow-float-lg transition-all duration-500 group">
// // // // // // // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
// // // // // // // //                   <div className="flex items-center gap-3">
// // // // // // // //                     <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center">
// // // // // // // //                       <User size={22} className="text-accent" />
// // // // // // // //                     </div>
// // // // // // // //                     <div>
// // // // // // // //                       {/* Navigate nested Booking -> Slot -> Doctor -> User for name */}
// // // // // // // //                       <h3 className="font-display font-bold text-foreground text-sm">
// // // // // // // //                         Dr. {c.booking.slot.doctor.user.firstName} {c.booking.slot.doctor.user.lastName}
// // // // // // // //                       </h3>
// // // // // // // //                       <p className="text-xs text-muted-foreground">{c.booking.slot.doctor.specialization}</p>
// // // // // // // //                     </div>
// // // // // // // //                   </div>
// // // // // // // //                   <div className="flex items-center gap-4 text-xs text-muted-foreground font-medium">
// // // // // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-lg">
// // // // // // // //                       <Calendar size={12} /> {new Date(c.startTime).toLocaleDateString()}
// // // // // // // //                     </span>
// // // // // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-lg">
// // // // // // // //                       <Clock size={12} /> {new Date(c.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // // // // // // //                     </span>
// // // // // // // //                   </div>
// // // // // // // //                 </div>

// // // // // // // //                 {/* Real clinical notes from the Consultation entity */}
// // // // // // // //                 <div className="bg-background/40 rounded-xl p-4 mb-4 border border-border/50">
// // // // // // // //                    <div className="flex items-center gap-2 mb-2 text-[10px] uppercase tracking-widest font-bold text-accent">
// // // // // // // //                       <ClipboardList size={10} /> Physician Notes
// // // // // // // //                    </div>
// // // // // // // //                    <p className="text-sm text-foreground/80 leading-relaxed italic">
// // // // // // // //                      {c.doctorNotes || "Detailed clinical summary pending finalization by the physician."}
// // // // // // // //                    </p>
// // // // // // // //                 </div>

// // // // // // // //                 <div className="flex items-center justify-between">
// // // // // // // //                   <span className="text-[10px] font-bold uppercase tracking-widest px-3 py-1 rounded-full bg-success/10 text-success">
// // // // // // // //                     Verified
// // // // // // // //                   </span>
// // // // // // // //                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline opacity-60 group-hover:opacity-100 transition-opacity">
// // // // // // // //                     <Download size={14} /> Export Summary
// // // // // // // //                   </button>
// // // // // // // //                 </div>
// // // // // // // //               </div>
// // // // // // // //             </motion.div>
// // // // // // // //           )) : (
// // // // // // // //             <div className="text-center py-20 glass rounded-3xl border-dashed border-2">
// // // // // // // //                <FileText size={48} className="mx-auto text-muted-foreground/20 mb-4" />
// // // // // // // //                <p className="text-muted-foreground text-sm italic">No verified medical consultations found in your history.</p>
// // // // // // // //             </div>
// // // // // // // //           )}
// // // // // // // //         </div>
// // // // // // // //       </div>
// // // // // // // //     </DashboardLayout>
// // // // // // // //   );
// // // // // // // // };

// // // // // // // // export default Consultations;


// // // // // // // import { useState, useEffect } from "react";
// // // // // // // import { motion } from "framer-motion";
// // // // // // // import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList } from "lucide-react";
// // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // import api from "@/lib/api";

// // // // // // // const Consultations = () => {
// // // // // // //   const [history, setHistory] = useState<any[]>([]);
// // // // // // //   const [loading, setLoading] = useState(true);

// // // // // // //   useEffect(() => {
// // // // // // //     const fetchHistory = async () => {
// // // // // // //       try {
// // // // // // //         setLoading(true);
// // // // // // //         // 1. Get real ID from LocalStorage
// // // // // // //         const userId = localStorage.getItem("userId");
// // // // // // //         if (!userId) throw new Error("User session not found.");

// // // // // // //         // 2. FIX: Removed duplicated "/api" prefix and used the specific Consultation endpoint
// // // // // // //         // This targets: http://localhost:8080/api/consultations/patient/{userId}
// // // // // // //         const res = await api.get(`/consultations/patient/${userId}`);
        
// // // // // // //         // Data comes as a list of Consultation entities
// // // // // // //         setHistory(Array.isArray(res.data) ? res.data : []);
// // // // // // //       } catch (err) {
// // // // // // //         console.error("Clinical History Sync Failed:", err);
// // // // // // //       } finally {
// // // // // // //         setLoading(false);
// // // // // // //       }
// // // // // // //     };
// // // // // // //     fetchHistory();
// // // // // // //   }, []);

// // // // // // //   if (loading) return (
// // // // // // //     <DashboardLayout role="patient">
// // // // // // //       <div className="min-h-[60vh] flex items-center justify-center">
// // // // // // //         <Loader2 className="animate-spin text-accent" size={32} />
// // // // // // //       </div>
// // // // // // //     </DashboardLayout>
// // // // // // //   );

// // // // // // //   return (
// // // // // // //     <DashboardLayout role="patient">
// // // // // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // // // // //         <div>
// // // // // // //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // // // // //             <FileText size={28} className="text-accent" /> Medical Records
// // // // // // //           </h1>
// // // // // // //           <p className="text-muted-foreground mt-1">Verified notes from your past consultations</p>
// // // // // // //         </div>

// // // // // // //         <div className="space-y-4">
// // // // // // //           {history.length > 0 ? history.map((c, i) => (
// // // // // // //             <motion.div
// // // // // // //               key={c.id}
// // // // // // //               initial={{ opacity: 0, y: 10 }}
// // // // // // //               animate={{ opacity: 1, y: 0 }}
// // // // // // //               transition={{ delay: i * 0.1 }}
// // // // // // //             >
// // // // // // //               <div className="glass rounded-2xl p-6 shadow-float hover:shadow-float-lg transition-all duration-500 group">
// // // // // // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
// // // // // // //                   <div className="flex items-center gap-3">
// // // // // // //                     <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center">
// // // // // // //                       <User size={22} className="text-accent" />
// // // // // // //                     </div>
// // // // // // //                     <div>
// // // // // // //                       {/* Navigate nested Consultation -> Booking -> Slot -> Doctor -> User */}
// // // // // // //                       <h3 className="font-display font-bold text-foreground text-sm">
// // // // // // //                         Dr. {c.booking?.slot?.doctor?.user?.firstName} {c.booking?.slot?.doctor?.user?.lastName}
// // // // // // //                       </h3>
// // // // // // //                       <p className="text-xs text-muted-foreground">{c.booking?.slot?.doctor?.specialization}</p>
// // // // // // //                     </div>
// // // // // // //                   </div>
// // // // // // //                   <div className="flex items-center gap-4 text-xs text-muted-foreground font-medium">
// // // // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-lg">
// // // // // // //                       <Calendar size={12} /> {new Date(c.startTime).toLocaleDateString()}
// // // // // // //                     </span>
// // // // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-lg">
// // // // // // //                       <Clock size={12} /> {new Date(c.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // // // // // //                     </span>
// // // // // // //                   </div>
// // // // // // //                 </div>

// // // // // // //                 {/* Display real clinical notes from the doctor entity */}
// // // // // // //                 <div className="bg-background/40 rounded-xl p-4 mb-4 border border-border/50">
// // // // // // //                    <div className="flex items-center gap-2 mb-2 text-[10px] uppercase tracking-widest font-bold text-accent">
// // // // // // //                       <ClipboardList size={10} /> Physician Notes
// // // // // // //                    </div>
// // // // // // //                    <p className="text-sm text-foreground/80 leading-relaxed italic">
// // // // // // //                      {c.doctorNotes || "Detailed clinical summary pending finalization by the physician."}
// // // // // // //                    </p>
// // // // // // //                 </div>

// // // // // // //                 <div className="flex items-center justify-between">
// // // // // // //                   <span className="text-[10px] font-bold uppercase tracking-widest px-3 py-1 rounded-full bg-success/10 text-success">
// // // // // // //                     Verified Record
// // // // // // //                   </span>
// // // // // // //                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline opacity-60 group-hover:opacity-100 transition-opacity">
// // // // // // //                     <Download size={14} /> Download Summary
// // // // // // //                   </button>
// // // // // // //                 </div>
// // // // // // //               </div>
// // // // // // //             </motion.div>
// // // // // // //           )) : (
// // // // // // //             <div className="text-center py-20 glass rounded-3xl border-dashed border-2">
// // // // // // //                <FileText size={48} className="mx-auto text-muted-foreground/20 mb-4" />
// // // // // // //                <p className="text-muted-foreground text-sm italic">No verified consultations found in your history.</p>
// // // // // // //             </div>
// // // // // // //           )}
// // // // // // //         </div>
// // // // // // //       </div>
// // // // // // //     </DashboardLayout>
// // // // // // //   );
// // // // // // // };

// // // // // // // export default Consultations;






// // // // // // import { useState, useEffect } from "react";
// // // // // // import { motion } from "framer-motion";
// // // // // // import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck } from "lucide-react";
// // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // import api from "@/lib/api";

// // // // // // /**
// // // // // //  * Medical Records Library
// // // // // //  * Fetches and displays verified clinical summaries for the patient.
// // // // // //  */
// // // // // // const Consultations = () => {
// // // // // //   const [history, setHistory] = useState<any[]>([]);
// // // // // //   const [loading, setLoading] = useState(true);

// // // // // //   useEffect(() => {
// // // // // //     const fetchHistory = async () => {
// // // // // //       try {
// // // // // //         setLoading(true);
// // // // // //         // 1. Identify the current patient
// // // // // //         const userId = localStorage.getItem("userId");
// // // // // //         if (!userId) throw new Error("Active session not found.");

// // // // // //         // 2. Fetch completed clinical sessions
// // // // // //         // Targets: http://localhost:8080/api/consultations/patient/{userId}
// // // // // //         const res = await api.get(`/consultations/patient/${userId}`);
        
// // // // // //         // Data is an array of Consultation entities
// // // // // //         setHistory(Array.isArray(res.data) ? res.data : []);
// // // // // //       } catch (err) {
// // // // // //         console.error("Clinical History Sync Failure:", err);
// // // // // //       } finally {
// // // // // //         setLoading(false);
// // // // // //       }
// // // // // //     };
// // // // // //     fetchHistory();
// // // // // //   }, []);

// // // // // //   if (loading) return (
// // // // // //     <DashboardLayout role="patient">
// // // // // //       <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
// // // // // //         <Loader2 className="animate-spin text-accent" size={40} />
// // // // // //         <p className="text-muted-foreground animate-pulse font-medium">Decrypting medical records...</p>
// // // // // //       </div>
// // // // // //     </DashboardLayout>
// // // // // //   );

// // // // // //   return (
// // // // // //     <DashboardLayout role="patient">
// // // // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // // // //         <div className="flex justify-between items-end border-b border-white/5 pb-6">
// // // // // //           <div>
// // // // // //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // // // //               <FileText size={28} className="text-accent" /> Medical Records
// // // // // //             </h1>
// // // // // //             <p className="text-muted-foreground mt-1">Access verified notes from your clinical history</p>
// // // // // //           </div>
// // // // // //           <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success uppercase tracking-widest bg-success/5 px-3 py-1.5 rounded-lg border border-success/10">
// // // // // //             <ShieldCheck size={12} /> HIPAA Verified
// // // // // //           </div>
// // // // // //         </div>

// // // // // //         <div className="space-y-4">
// // // // // //           {history.length > 0 ? history.map((c, i) => (
// // // // // //             <motion.div
// // // // // //               key={c.id}
// // // // // //               initial={{ opacity: 0, y: 15 }}
// // // // // //               animate={{ opacity: 1, y: 0 }}
// // // // // //               transition={{ delay: i * 0.1 }}
// // // // // //             >
// // // // // //               <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all duration-500 group border-white/5">
// // // // // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
// // // // // //                   <div className="flex items-center gap-4">
// // // // // //                     <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
// // // // // //                       <User size={26} className="text-accent" />
// // // // // //                     </div>
// // // // // //                     <div>
// // // // // //                       {/* DYNAMIC MAPPING: Consultation -> Booking -> Slot -> Doctor -> User */}
// // // // // //                       <h3 className="font-display font-bold text-foreground text-lg">
// // // // // //                         Dr. {c.booking?.slot?.doctor?.user?.firstName} {c.booking?.slot?.doctor?.user?.lastName}
// // // // // //                       </h3>
// // // // // //                       <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
// // // // // //                         {c.booking?.slot?.doctor?.specialization}
// // // // // //                       </p>
// // // // // //                     </div>
// // // // // //                   </div>
// // // // // //                   <div className="flex items-center gap-3 text-xs text-muted-foreground font-bold">
// // // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-4 py-2 rounded-xl border border-white/5">
// // // // // //                       <Calendar size={14} className="text-accent" /> 
// // // // // //                       {new Date(c.startTime).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
// // // // // //                     </span>
// // // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-4 py-2 rounded-xl border border-white/5">
// // // // // //                       <Clock size={14} className="text-accent" /> 
// // // // // //                       {new Date(c.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // // // // //                     </span>
// // // // // //                   </div>
// // // // // //                 </div>

// // // // // //                 {/* Clinical Findings Segment */}
// // // // // //                 <div className="bg-background/40 rounded-2xl p-5 mb-6 border border-white/5 relative overflow-hidden">
// // // // // //                     <div className="absolute top-0 right-0 p-3 opacity-10">
// // // // // //                         <ClipboardList size={40} />
// // // // // //                     </div>
// // // // // //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
// // // // // //                       <ClipboardList size={12} /> Physician's Notes & Observations
// // // // // //                     </div>
// // // // // //                     <p className="text-sm text-foreground/80 leading-relaxed italic relative z-10">
// // // // // //                       "{c.doctorNotes || "Detailed clinical summary pending finalization by the physician."}"
// // // // // //                     </p>
// // // // // //                 </div>

// // // // // //                 <div className="flex items-center justify-between">
// // // // // //                   <div className="flex items-center gap-2">
// // // // // //                     <span className="text-[10px] font-black uppercase tracking-widest px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
// // // // // //                       Session Complete
// // // // // //                     </span>
// // // // // //                   </div>
// // // // // //                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline group-hover:scale-105 transition-all">
// // // // // //                     <Download size={14} /> Export Medical PDF
// // // // // //                   </button>
// // // // // //                 </div>
// // // // // //               </div>
// // // // // //             </motion.div>
// // // // // //           )) : (
// // // // // //             <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5 bg-white/5">
// // // // // //                 <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
// // // // // //                 <h2 className="text-lg font-bold text-foreground/60 mb-1">Your Medical Vault is Empty</h2>
// // // // // //                 <p className="text-sm text-muted-foreground italic px-8">Records will appear here once your physician finalizes your consultation notes.</p>
// // // // // //             </div>
// // // // // //           )}
// // // // // //         </div>
// // // // // //       </div>
// // // // // //     </DashboardLayout>
// // // // // //   );
// // // // // // };

// // // // // // export default Consultations;






// // // // // import { useState, useEffect } from "react";
// // // // // import { motion } from "framer-motion";
// // // // // import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck } from "lucide-react";
// // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // import api from "@/lib/api";

// // // // // /**
// // // // //  * Medical Records Library
// // // // //  * Fetches and displays verified clinical summaries for the patient.
// // // // //  */
// // // // // const Consultations = () => {
// // // // //   const [history, setHistory] = useState<any[]>([]);
// // // // //   const [loading, setLoading] = useState(true);

// // // // //   useEffect(() => {
// // // // //     const fetchHistory = async () => {
// // // // //       try {
// // // // //         setLoading(true);
// // // // //         // 1. Identify the current patient from LocalStorage
// // // // //         const userId = localStorage.getItem("userId");
// // // // //         if (!userId) throw new Error("Active session not found.");

// // // // //         // 2. Fetch completed clinical sessions from the backend
// // // // //         // Targets: http://localhost:8080/api/consultations/patient/{userId}
// // // // //         const res = await api.get(`/consultations/patient/${userId}`);
        
// // // // //         // Data is an array of Consultation entities
// // // // //         setHistory(Array.isArray(res.data) ? res.data : []);
// // // // //       } catch (err) {
// // // // //         console.error("Clinical History Sync Failure:", err);
// // // // //       } finally {
// // // // //         setLoading(false);
// // // // //       }
// // // // //     };
// // // // //     fetchHistory();
// // // // //   }, []);

// // // // //   if (loading) return (
// // // // //     <DashboardLayout role="patient">
// // // // //       <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
// // // // //         <Loader2 className="animate-spin text-accent" size={40} />
// // // // //         <p className="text-muted-foreground animate-pulse font-medium text-sm">Decrypting medical records...</p>
// // // // //       </div>
// // // // //     </DashboardLayout>
// // // // //   );

// // // // //   return (
// // // // //     <DashboardLayout role="patient">
// // // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // // //         <div className="flex justify-between items-end border-b border-white/5 pb-6">
// // // // //           <div>
// // // // //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // // //               <FileText size={28} className="text-accent" /> Medical Records
// // // // //             </h1>
// // // // //             <p className="text-muted-foreground mt-1">Access verified notes from your clinical history</p>
// // // // //           </div>
// // // // //           <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success uppercase tracking-widest bg-success/5 px-3 py-1.5 rounded-lg border border-success/10">
// // // // //             <ShieldCheck size={12} /> HIPAA Verified
// // // // //           </div>
// // // // //         </div>

// // // // //         <div className="space-y-4">
// // // // //           {history.length > 0 ? history.map((c, i) => (
// // // // //             <motion.div
// // // // //               key={c.id}
// // // // //               initial={{ opacity: 0, y: 15 }}
// // // // //               animate={{ opacity: 1, y: 0 }}
// // // // //               transition={{ delay: i * 0.1 }}
// // // // //             >
// // // // //               <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all duration-500 group border-white/5">
// // // // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
// // // // //                   <div className="flex items-center gap-4">
// // // // //                     <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
// // // // //                       <User size={26} className="text-accent" />
// // // // //                     </div>
// // // // //                     <div>
// // // // //                       {/* DYNAMIC MAPPING: Consultation -> Booking -> Slot -> Doctor -> User */}
// // // // //                       <h3 className="font-display font-bold text-foreground text-lg">
// // // // //                         Dr. {c.booking?.slot?.doctor?.user?.firstName || "Specialist"} {c.booking?.slot?.doctor?.user?.lastName || ""}
// // // // //                       </h3>
// // // // //                       <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
// // // // //                         {c.booking?.slot?.doctor?.specialization || "Clinical Consultation"}
// // // // //                       </p>
// // // // //                     </div>
// // // // //                   </div>
// // // // //                   <div className="flex items-center gap-3 text-xs text-muted-foreground font-bold">
// // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-4 py-2 rounded-xl border border-white/5">
// // // // //                       <Calendar size={14} className="text-accent" /> 
// // // // //                       {new Date(c.startTime).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
// // // // //                     </span>
// // // // //                     <span className="flex items-center gap-1.5 bg-white/5 px-4 py-2 rounded-xl border border-white/5">
// // // // //                       <Clock size={14} className="text-accent" /> 
// // // // //                       {new Date(c.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // // // //                     </span>
// // // // //                   </div>
// // // // //                 </div>

// // // // //                 {/* Clinical Findings Segment */}
// // // // //                 <div className="bg-background/40 rounded-2xl p-5 mb-6 border border-white/5 relative overflow-hidden">
// // // // //                     <div className="absolute top-0 right-0 p-3 opacity-10">
// // // // //                         <ClipboardList size={40} />
// // // // //                     </div>
// // // // //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
// // // // //                       <ClipboardList size={12} /> Physician's Notes & Observations
// // // // //                     </div>
// // // // //                     <p className="text-sm text-foreground/80 leading-relaxed italic relative z-10">
// // // // //                       "{c.doctorNotes || "Detailed clinical summary pending finalization by the physician."}"
// // // // //                     </p>
// // // // //                 </div>

// // // // //                 <div className="flex items-center justify-between">
// // // // //                   <div className="flex items-center gap-2">
// // // // //                     <span className="text-[10px] font-black uppercase tracking-widest px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
// // // // //                       Session Complete
// // // // //                     </span>
// // // // //                   </div>
// // // // //                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline group-hover:scale-105 transition-all">
// // // // //                     <Download size={14} /> Export Medical PDF
// // // // //                   </button>
// // // // //                 </div>
// // // // //               </div>
// // // // //             </motion.div>
// // // // //           )) : (
// // // // //             <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5 bg-white/5">
// // // // //                 <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
// // // // //                 <h2 className="text-lg font-bold text-foreground/60 mb-1">Your Medical Vault is Empty</h2>
// // // // //                 <p className="text-sm text-muted-foreground italic px-8">Records will appear here once your physician finalizes your consultation notes.</p>
// // // // //             </div>
// // // // //           )}
// // // // //         </div>
// // // // //       </div>
// // // // //     </DashboardLayout>
// // // // //   );
// // // // // };

// // // // // export default Consultations;



// // // // import { useState, useEffect } from "react";
// // // // import { motion } from "framer-motion";
// // // // import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck, Pill } from "lucide-react";
// // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // import api from "@/lib/api";

// // // // const Consultations = () => {
// // // //   const [history, setHistory] = useState<any[]>([]);
// // // //   const [loading, setLoading] = useState(true);

// // // //   useEffect(() => {
// // // //     const fetchHistory = async () => {
// // // //       try {
// // // //         setLoading(true);
// // // //         // 1. Get the authenticated Patient's User ID
// // // //         const userId = localStorage.getItem("userId");
// // // //         if (!userId) throw new Error("Session expired.");

// // // //         // 2. Fetch completed clinical records
// // // //         // This targets the service method: getPatientConsultationHistory(userId)
// // // //         const res = await api.get(`/consultations/patient/${userId}`);
        
// // // //         setHistory(Array.isArray(res.data) ? res.data : []);
// // // //       } catch (err) {
// // // //         console.error("Clinical History Sync Failure:", err);
// // // //       } finally {
// // // //         setLoading(false);
// // // //       }
// // // //     };
// // // //     fetchHistory();
// // // //   }, []);

// // // //   if (loading) return (
// // // //     <DashboardLayout role="patient">
// // // //       <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
// // // //         <Loader2 className="animate-spin text-accent" size={40} />
// // // //         <p className="text-muted-foreground animate-pulse font-medium">Retrieving medical vault...</p>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );

// // // //   return (
// // // //     <DashboardLayout role="patient">
// // // //       <div className="max-w-4xl mx-auto space-y-8">
// // // //         <div className="flex justify-between items-end border-b border-white/5 pb-6">
// // // //           <div>
// // // //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // // //               <FileText size={28} className="text-accent" /> Medical Records
// // // //             </h1>
// // // //             <p className="text-muted-foreground mt-1">Verified summaries from your past consultations</p>
// // // //           </div>
// // // //           <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success uppercase tracking-widest bg-success/5 px-3 py-1.5 rounded-lg border border-success/10">
// // // //             <ShieldCheck size={12} /> Encrypted Record
// // // //           </div>
// // // //         </div>

// // // //         <div className="space-y-6">
// // // //           {history.length > 0 ? history.map((c, i) => (
// // // //             <motion.div key={c.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
// // // //               <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all border-white/5 group">
// // // //                 {/* 1. Header: Doctor Info */}
// // // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
// // // //                   <div className="flex items-center gap-4">
// // // //                     <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
// // // //                       <User size={26} className="text-accent" />
// // // //                     </div>
// // // //                     <div>
// // // //                       {/* DTO Mapping verified: Path leads to Doctor's Name */}
// // // //                       <h3 className="font-display font-bold text-foreground text-lg">
// // // //                         Dr. {c.booking?.slot?.doctor?.user?.firstName} {c.booking?.slot?.doctor?.user?.lastName}
// // // //                       </h3>
// // // //                       <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
// // // //                         {c.booking?.slot?.doctor?.specialization}
// // // //                       </p>
// // // //                     </div>
// // // //                   </div>
// // // //                   <div className="text-xs text-muted-foreground font-bold flex gap-3">
// // // //                     <span className="bg-white/5 px-3 py-1.5 rounded-lg border border-white/5 flex items-center gap-2">
// // // //                       <Calendar size={14} className="text-accent" /> 
// // // //                       {new Date(c.startTime).toLocaleDateString()}
// // // //                     </span>
// // // //                   </div>
// // // //                 </div>

// // // //                 {/* 2. Body: Physician Notes */}
// // // //                 <div className="bg-background/40 rounded-2xl p-5 mb-4 border border-white/5">
// // // //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
// // // //                       <ClipboardList size={12} /> Clinical Summary
// // // //                     </div>
// // // //                     <p className="text-sm text-foreground/80 leading-relaxed italic">
// // // //                       "{c.doctorNotes || "General consultation completed. No specific issues noted."}"
// // // //                     </p>
// // // //                 </div>

// // // //                 {/* 3. NEW: Prescribed Medications (DTO placeholder for our next step) */}
// // // //                 {c.prescriptions && c.prescriptions.length > 0 && (
// // // //                   <div className="bg-accent/5 rounded-2xl p-5 mb-6 border border-accent/10">
// // // //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-success">
// // // //                       <Pill size={12} /> Prescribed Medication
// // // //                     </div>
// // // //                     <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
// // // //                       {c.prescriptions.map((p: any) => (
// // // //                         <div key={p.id} className="glass-strong p-3 rounded-xl text-xs flex justify-between">
// // // //                           <span className="font-bold">{p.medicineName}</span>
// // // //                           <span className="text-muted-foreground">{p.dosage} - {p.frequency}</span>
// // // //                         </div>
// // // //                       ))}
// // // //                     </div>
// // // //                   </div>
// // // //                 )}

// // // //                 {/* 4. Footer: Status and Export */}
// // // //                 <div className="flex items-center justify-between">
// // // //                   <span className="text-[10px] font-black uppercase px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
// // // //                     Verified Record
// // // //                   </span>
// // // //                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline">
// // // //                     <Download size={14} /> Download PDF
// // // //                   </button>
// // // //                 </div>
// // // //               </div>
// // // //             </motion.div>
// // // //           )) : (
// // // //             <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5">
// // // //                 <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
// // // //                 <p className="text-sm text-muted-foreground italic">Your verified medical history is currently empty.</p>
// // // //             </div>
// // // //           )}
// // // //         </div>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );
// // // // };

// // // // export default Consultations;




// // // import { useState, useEffect } from "react";
// // // import { motion } from "framer-motion";
// // // import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck, Pill } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import api from "@/lib/api";

// // // const Consultations = () => {
// // //   const [history, setHistory] = useState<any[]>([]);
// // //   const [loading, setLoading] = useState(true);

// // //   useEffect(() => {
// // //     const fetchHistory = async () => {
// // //       try {
// // //         setLoading(true);
// // //         // 1. Get the authenticated Patient's User ID
// // //         const userId = localStorage.getItem("userId");
// // //         if (!userId) throw new Error("Session expired.");

// // //         // 2. Fetch completed clinical records
// // //         // Hits: http://localhost:8080/api/consultations/patient/{userId}
// // //         const res = await api.get(`/consultations/patient/${userId}`);
        
// // //         // Data is an array of Consultation entities
// // //         setHistory(Array.isArray(res.data) ? res.data : []);
// // //       } catch (err) {
// // //         console.error("Clinical History Sync Failure:", err);
// // //       } finally {
// // //         setLoading(false);
// // //       }
// // //     };
// // //     fetchHistory();
// // //   }, []);

// // //   if (loading) return (
// // //     <DashboardLayout role="patient">
// // //       <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
// // //         <Loader2 className="animate-spin text-accent" size={40} />
// // //         <p className="text-muted-foreground animate-pulse font-medium">Retrieving medical vault...</p>
// // //       </div>
// // //     </DashboardLayout>
// // //   );

// // //   return (
// // //     <DashboardLayout role="patient">
// // //       <div className="max-w-4xl mx-auto space-y-8">
// // //         <div className="flex justify-between items-end border-b border-white/5 pb-6">
// // //           <div>
// // //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // //               <FileText size={28} className="text-accent" /> Medical Records
// // //             </h1>
// // //             <p className="text-muted-foreground mt-1">Verified summaries from your past consultations</p>
// // //           </div>
// // //           <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success uppercase tracking-widest bg-success/5 px-3 py-1.5 rounded-lg border border-success/10">
// // //             <ShieldCheck size={12} /> Encrypted Record
// // //           </div>
// // //         </div>

// // //         <div className="space-y-6">
// // //           {history.length > 0 ? history.map((c, i) => (
// // //             <motion.div key={c.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
// // //               <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all border-white/5 group">
                
// // //                 {/* 1. Header: Doctor Identity (Traversing DTO) */}
// // //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
// // //                   <div className="flex items-center gap-4">
// // //                     <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
// // //                       <User size={26} className="text-accent" />
// // //                     </div>
// // //                     <div>
// // //                       <h3 className="font-display font-bold text-foreground text-lg">
// // //                         Dr. {c.booking?.slot?.doctor?.user?.firstName || "Specialist"} {c.booking?.slot?.doctor?.user?.lastName || ""}
// // //                       </h3>
// // //                       <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
// // //                         {c.booking?.slot?.doctor?.specialization || "Clinical Consultation"}
// // //                       </p>
// // //                     </div>
// // //                   </div>
// // //                   <div className="text-xs text-muted-foreground font-bold flex gap-3">
// // //                     <span className="bg-white/5 px-3 py-1.5 rounded-lg border border-white/5 flex items-center gap-2">
// // //                       <Calendar size={14} className="text-accent" /> 
// // //                       {new Date(c.startTime).toLocaleDateString()}
// // //                     </span>
// // //                   </div>
// // //                 </div>

// // //                 {/* 2. Body: Physician Notes */}
// // //                 <div className="bg-background/40 rounded-2xl p-5 mb-4 border border-white/5">
// // //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
// // //                       <ClipboardList size={12} /> Clinical Summary
// // //                     </div>
// // //                     <p className="text-sm text-foreground/80 leading-relaxed italic">
// // //                       "{c.doctorNotes || "General consultation completed. Summary pending."}"
// // //                     </p>
// // //                 </div>

// // //                 {/* 3. Prescribed Medications (DTO Integrated) */}
// // //                 {c.prescriptions && c.prescriptions.length > 0 && (
// // //                   <div className="bg-accent/5 rounded-2xl p-5 mb-6 border border-accent/10">
// // //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-success">
// // //                       <Pill size={12} /> Prescribed Medication
// // //                     </div>
// // //                     <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
// // //                       {c.prescriptions.map((p: any) => (
// // //                         <div key={p.id} className="glass-strong p-3 rounded-xl text-xs flex justify-between">
// // //                           <span className="font-bold text-foreground">{p.medicineName}</span>
// // //                           <span className="text-muted-foreground">{p.dosage} - {p.frequency}</span>
// // //                         </div>
// // //                       ))}
// // //                     </div>
// // //                   </div>
// // //                 )}

// // //                 <div className="flex items-center justify-between">
// // //                   <span className="text-[10px] font-black uppercase px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
// // //                     Verified Session
// // //                   </span>
// // //                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline">
// // //                     <Download size={14} /> Download PDF
// // //                   </button>
// // //                 </div>
// // //               </div>
// // //             </motion.div>
// // //           )) : (
// // //             <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5">
// // //                 <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
// // //                 <p className="text-sm text-muted-foreground italic">Your verified medical history is currently empty.</p>
// // //             </div>
// // //           )}
// // //         </div>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default Consultations;





// // import { useState, useEffect } from "react";
// // import { motion } from "framer-motion";
// // import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck, Pill } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import api from "@/lib/api";

// // const Consultations = () => {
// //   const [history, setHistory] = useState<any[]>([]);
// //   const [loading, setLoading] = useState(true);

// //   useEffect(() => {
// //     const fetchHistory = async () => {
// //       try {
// //         setLoading(true);
// //         // 1. Get the authenticated Patient's User ID from local session
// //         const userId = localStorage.getItem("userId");
// //         if (!userId) throw new Error("Active session not found.");

// //         // 2. Fetch completed clinical records
// //         // Targets: http://localhost:8080/api/consultations/patient/{userId}
// //         const res = await api.get(`/consultations/patient/${userId}`);
        
// //         // Data is an array of Consultation entities
// //         setHistory(Array.isArray(res.data) ? res.data : []);
// //       } catch (err) {
// //         console.error("Clinical History Sync Failure:", err);
// //       } finally {
// //         setLoading(false);
// //       }
// //     };
// //     fetchHistory();
// //   }, []);

// //   if (loading) return (
// //     <DashboardLayout role="patient">
// //       <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
// //         <Loader2 className="animate-spin text-accent" size={40} />
// //         <p className="text-muted-foreground animate-pulse font-medium">Retrieving medical vault...</p>
// //       </div>
// //     </DashboardLayout>
// //   );

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-4xl mx-auto space-y-8">
// //         <div className="flex justify-between items-end border-b border-white/5 pb-6">
// //           <div>
// //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// //               <FileText size={28} className="text-accent" /> Medical Records
// //             </h1>
// //             <p className="text-muted-foreground mt-1">Verified summaries from your past consultations</p>
// //           </div>
// //           <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success uppercase tracking-widest bg-success/5 px-3 py-1.5 rounded-lg border border-success/10">
// //             <ShieldCheck size={12} /> HIPAA Verified
// //           </div>
// //         </div>

// //         <div className="space-y-6">
// //           {history.length > 0 ? history.map((c, i) => (
// //             <motion.div key={c.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
// //               <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all border-white/5 group">
                
// //                 {/* 1. Header: Doctor Identity (Traversing Nested DTO) */}
// //                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
// //                   <div className="flex items-center gap-4">
// //                     <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
// //                       <User size={26} className="text-accent" />
// //                     </div>
// //                     <div>
// //                       {/* PATH: Consultation -> Booking -> Slot -> Doctor -> User */}
// //                       <h3 className="font-display font-bold text-foreground text-lg">
// //                         Dr. {c.booking?.slot?.doctor?.user?.firstName || "Specialist"} {c.booking?.slot?.doctor?.user?.lastName || ""}
// //                       </h3>
// //                       <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
// //                         {c.booking?.slot?.doctor?.specialization || "Clinical Consultation"}
// //                       </p>
// //                     </div>
// //                   </div>
// //                   <div className="text-xs text-muted-foreground font-bold flex gap-3">
// //                     <span className="bg-white/5 px-3 py-1.5 rounded-lg border border-white/5 flex items-center gap-2">
// //                       <Calendar size={14} className="text-accent" /> 
// //                       {new Date(c.startTime).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
// //                     </span>
// //                   </div>
// //                 </div>

// //                 {/* 2. Body: Physician Notes */}
// //                 <div className="bg-background/40 rounded-2xl p-5 mb-4 border border-white/5">
// //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
// //                       <ClipboardList size={12} /> Physician's Notes
// //                     </div>
// //                     <p className="text-sm text-foreground/80 leading-relaxed italic">
// //                       "{c.doctorNotes || "General consultation completed. Summary pending finalization."}"
// //                     </p>
// //                 </div>

// //                 {/* 3. Prescribed Medications Loop */}
// //                 {c.prescriptions && c.prescriptions.length > 0 && (
// //                   <div className="bg-accent/5 rounded-2xl p-5 mb-6 border border-accent/10">
// //                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-success">
// //                       <Pill size={12} /> Prescribed Medication
// //                     </div>
// //                     <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
// //                       {c.prescriptions.map((p: any) => (
// //                         <div key={p.id} className="glass-strong p-3 rounded-xl text-xs flex justify-between border border-white/5">
// //                           <span className="font-bold text-foreground">{p.medicineName}</span>
// //                           <span className="text-muted-foreground">{p.dosage} - {p.frequency}</span>
// //                         </div>
// //                       ))}
// //                     </div>
// //                   </div>
// //                 )}

// //                 {/* 4. Footer: Status and Export */}
// //                 <div className="flex items-center justify-between">
// //                   <span className="text-[10px] font-black uppercase px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
// //                     Verified Session
// //                   </span>
// //                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline group-hover:scale-105 transition-all">
// //                     <Download size={14} /> Download PDF
// //                   </button>
// //                 </div>
// //               </div>
// //             </motion.div>
// //           )) : (
// //             <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5 bg-white/5">
// //                 <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
// //                 <h2 className="text-lg font-bold text-foreground/60 mb-1">Your Medical Vault is Empty</h2>
// //                 <p className="text-sm text-muted-foreground italic px-8">Verified notes will appear here once your physician finalizes the consultation summary.</p>
// //             </div>
// //           )}
// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default Consultations;




// import { useState, useEffect } from "react";
// import { motion } from "framer-motion";
// import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck, Pill } from "lucide-react";
// import DashboardLayout from "@/components/DashboardLayout";
// import api from "@/lib/api";

// const Consultations = () => {
//   const [history, setHistory] = useState<any[]>([]);
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     const fetchHistory = async () => {
//       try {
//         setLoading(true);
//         // 1. Get the authenticated Patient's User ID
//         const userId = localStorage.getItem("userId");
//         if (!userId) throw new Error("Session expired.");

//         // 2. Fetch completed clinical records from backend
//         const res = await api.get(`/consultations/patient/${userId}`);
        
//         setHistory(Array.isArray(res.data) ? res.data : []);
//       } catch (err) {
//         console.error("Clinical History Sync Failure:", err);
//       } finally {
//         setLoading(false);
//       }
//     };
//     fetchHistory();
//   }, []);

//   if (loading) return (
//     <DashboardLayout role="patient">
//       <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
//         <Loader2 className="animate-spin text-accent" size={40} />
//         <p className="text-muted-foreground animate-pulse font-medium">Retrieving medical vault...</p>
//       </div>
//     </DashboardLayout>
//   );

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-4xl mx-auto space-y-8">
//         <div className="flex justify-between items-end border-b border-white/5 pb-6">
//           <div>
//             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
//               <FileText size={28} className="text-accent" /> Medical Records
//             </h1>
//             <p className="text-muted-foreground mt-1">Verified summaries from your past consultations</p>
//           </div>
//           <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success uppercase tracking-widest bg-success/5 px-3 py-1.5 rounded-lg border border-success/10">
//             <ShieldCheck size={12} /> Encrypted Record
//           </div>
//         </div>

//         <div className="space-y-6">
//           {history.length > 0 ? history.map((c, i) => (
//             <motion.div key={c.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
//               <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all border-white/5 group">
                
//                 {/* 1. Header: Doctor Identity (Mapping: Consultation -> Booking -> Slot -> Doctor -> User) */}
//                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
//                   <div className="flex items-center gap-4">
//                     <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
//                       <User size={26} className="text-accent" />
//                     </div>
//                     <div>
//                       <h3 className="font-display font-bold text-foreground text-lg">
//                         Dr. {c.booking?.slot?.doctor?.user?.firstName || "Specialist"} {c.booking?.slot?.doctor?.user?.lastName || ""}
//                       </h3>
//                       <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
//                         {c.booking?.slot?.doctor?.specialization || "General Consultation"}
//                       </p>
//                     </div>
//                   </div>
//                   <div className="text-xs text-muted-foreground font-bold flex gap-3">
//                     <span className="bg-white/5 px-3 py-1.5 rounded-lg border border-white/5 flex items-center gap-2">
//                       <Calendar size={14} className="text-accent" /> 
//                       {new Date(c.startTime).toLocaleDateString()}
//                     </span>
//                   </div>
//                 </div>

//                 {/* 2. Body: Physician Notes */}
//                 <div className="bg-background/40 rounded-2xl p-5 mb-4 border border-white/5">
//                     <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
//                       <ClipboardList size={12} /> Clinical Summary
//                     </div>
//                     <p className="text-sm text-foreground/80 leading-relaxed italic">
//                       "{c.doctorNotes || "Detailed clinical summary pending finalization by the physician."}"
//                     </p>
//                 </div>

//                 {/* 3. Footer: Status and Export */}
//                 <div className="flex items-center justify-between">
//                   <span className="text-[10px] font-black uppercase px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
//                     Verified Session
//                   </span>
//                   <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline">
//                     <Download size={14} /> Download PDF
//                   </button>
//                 </div>
//               </div>
//             </motion.div>
//           )) : (
//             <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5">
//                 <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
//                 <p className="text-sm text-muted-foreground italic">Your verified medical history is currently empty.</p>
//             </div>
//           )}
//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default Consultations;



import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck, Pill } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";

const Consultations = () => {
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        const userId = localStorage.getItem("userId");
        if (!userId) throw new Error("Session expired.");

        const res = await api.get(`/consultations/patient/${userId}`);
        setHistory(Array.isArray(res.data) ? res.data : []);
      } catch (err) {
        console.error("Clinical History Sync Failure:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  if (loading) return (
    <DashboardLayout role="patient">
      <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
        <Loader2 className="animate-spin text-accent" size={40} />
        <p className="text-muted-foreground animate-pulse font-medium">Decrypting medical vault...</p>
      </div>
    </DashboardLayout>
  );

  return (
    <DashboardLayout role="patient">
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="flex justify-between items-end border-b border-white/5 pb-6">
          <div>
            <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
              <FileText size={28} className="text-accent" /> Medical Records
            </h1>
            <p className="text-muted-foreground mt-1 text-sm font-medium">Verified summaries and prescriptions</p>
          </div>
          <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success bg-success/5 px-3 py-1.5 rounded-lg border border-success/10 uppercase tracking-widest">
            <ShieldCheck size={12} /> HIPAA Encrypted
          </div>
        </div>

        <div className="space-y-6">
          {history.length > 0 ? history.map((c, i) => (
            <motion.div key={c.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
              <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all border-white/5 group">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                  <div className="flex items-center gap-4">
                    <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
                      <User size={26} className="text-accent" />
                    </div>
                    <div>
                      <h3 className="font-display font-bold text-foreground text-lg">
                        Dr. {c.booking?.slot?.doctor?.user?.firstName} {c.booking?.slot?.doctor?.user?.lastName}
                      </h3>
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                        {c.booking?.slot?.doctor?.specialization}
                      </p>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground font-bold flex gap-3">
                    <span className="bg-white/5 px-3 py-1.5 rounded-lg border border-white/5 flex items-center gap-2">
                      <Calendar size={14} className="text-accent" /> {new Date(c.startTime).toLocaleDateString()}
                    </span>
                  </div>
                </div>

                <div className="bg-background/40 rounded-2xl p-5 mb-4 border border-white/5">
                    <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
                      <ClipboardList size={12} /> Physician's Summary
                    </div>
                    <p className="text-sm text-foreground/80 leading-relaxed italic">
                      "{c.doctorNotes || "General consultation completed. Summary pending finalization."}"
                    </p>
                </div>

                {/* PRESCRIPTION SECTION */}
                {c.prescriptions && c.prescriptions.length > 0 && (
                  <div className="bg-accent/5 rounded-2xl p-5 mb-6 border border-accent/10">
                    <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-success">
                      <Pill size={12} /> Prescribed Medications
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {c.prescriptions.map((p: any) => (
                        <div key={p.id} className="glass-strong p-3 rounded-xl text-xs flex justify-between items-center border border-white/5">
                          <div>
                            <span className="font-bold text-foreground block">{p.medicineName}</span>
                            <span className="text-[10px] text-muted-foreground italic">{p.instructions || "No instructions provided"}</span>
                          </div>
                          <span className="bg-accent/10 text-accent px-2 py-1 rounded-md font-bold">{p.dosage}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between mt-4">
                  <span className="text-[10px] font-black uppercase px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
                    Verified Session
                  </span>
                  <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline">
                    <Download size={14} /> Download PDF
                  </button>
                </div>
              </div>
            </motion.div>
          )) : (
            <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5">
                <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
                <p className="text-sm text-muted-foreground italic">Your medical history is empty.</p>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Consultations;