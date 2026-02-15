// // import { motion } from "framer-motion";
// // import { Clock, MessageSquare, FileText, Calendar, ChevronDown } from "lucide-react";
// // import { useState } from "react";
// // import DashboardLayout from "@/components/DashboardLayout";

// // const timelineItems = [
// //   { id: 1, type: "triage", title: "AI Triage: Persistent Headache", date: "Feb 10, 2026", summary: "Identified tension headache with 82% confidence. Recommended rest and hydration.", icon: MessageSquare },
// //   { id: 2, type: "report", title: "Blood Test Report", date: "Feb 8, 2026", summary: "CBC results within normal range. Vitamin D slightly below optimal.", icon: FileText },
// //   { id: 3, type: "consultation", title: "Dr. Sarah Chen - Cardiology", date: "Feb 5, 2026", summary: "Routine heart checkup. All vitals normal. Follow-up in 6 months.", icon: Calendar },
// //   { id: 4, type: "triage", title: "AI Triage: Chest Discomfort", date: "Jan 28, 2026", summary: "Likely muscle strain. Confidence: 71%. Referred for cardiology consultation.", icon: MessageSquare },
// //   { id: 5, type: "report", title: "X-Ray Results", date: "Jan 20, 2026", summary: "Chest X-ray clear. No abnormalities detected.", icon: FileText },
// //   { id: 6, type: "consultation", title: "Dr. James Wilson - General", date: "Jan 15, 2026", summary: "Annual physical examination completed. Overall health status: Good.", icon: Calendar },
// // ];

// // const Timeline = () => {
// //   const [expanded, setExpanded] = useState<number | null>(null);

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-3xl mx-auto">
// //         <div className="mb-8">
// //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// //             <Clock size={28} className="text-accent" />
// //             Timeline & Recalls
// //           </h1>
// //           <p className="text-muted-foreground mt-1">Your complete health history</p>
// //         </div>

// //         <div className="relative">
// //           {/* Vertical line */}
// //           <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-accent via-primary to-transparent" />

// //           <div className="space-y-6">
// //             {timelineItems.map((item, i) => (
// //               <motion.div
// //                 key={item.id}
// //                 initial={{ opacity: 0, x: -20 }}
// //                 whileInView={{ opacity: 1, x: 0 }}
// //                 viewport={{ once: true }}
// //                 transition={{ duration: 0.5, delay: i * 0.1 }}
// //                 className="relative pl-16"
// //               >
// //                 {/* Node */}
// //                 <motion.div
// //                   whileHover={{ scale: 1.3 }}
// //                   className={`absolute left-4 top-4 w-5 h-5 rounded-full border-2 border-background z-10 ${
// //                     item.type === "triage" ? "bg-accent" :
// //                     item.type === "report" ? "bg-warning" : "bg-success"
// //                   }`}
// //                 />
// //                 <div className={`absolute left-3 top-3 w-7 h-7 rounded-full animate-pulse-soft ${
// //                   item.type === "triage" ? "bg-accent/20" :
// //                   item.type === "report" ? "bg-warning/20" : "bg-success/20"
// //                 }`} />

// //                 {/* Card */}
// //                 <div
// //                   className="glass rounded-2xl p-5 shadow-float hover:shadow-float-lg transition-all duration-500 cursor-pointer"
// //                   onClick={() => setExpanded(expanded === item.id ? null : item.id)}
// //                 >
// //                   <div className="flex items-start justify-between">
// //                     <div className="flex items-center gap-3">
// //                       <item.icon size={18} className="text-accent" />
// //                       <div>
// //                         <h3 className="font-display font-bold text-foreground text-sm">{item.title}</h3>
// //                         <p className="text-xs text-muted-foreground">{item.date}</p>
// //                       </div>
// //                     </div>
// //                     <motion.div animate={{ rotate: expanded === item.id ? 180 : 0 }} transition={{ duration: 0.2 }}>
// //                       <ChevronDown size={16} className="text-muted-foreground" />
// //                     </motion.div>
// //                   </div>

// //                   {expanded === item.id && (
// //                     <motion.div
// //                       initial={{ opacity: 0, height: 0 }}
// //                       animate={{ opacity: 1, height: "auto" }}
// //                       exit={{ opacity: 0, height: 0 }}
// //                       className="mt-3 pt-3 border-t border-border/50"
// //                     >
// //                       <p className="text-sm text-muted-foreground leading-relaxed">{item.summary}</p>
// //                     </motion.div>
// //                   )}
// //                 </div>
// //               </motion.div>
// //             ))}
// //           </div>
// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default Timeline;


// import { motion, AnimatePresence } from "framer-motion";
// import { Clock, MessageSquare, FileText, Calendar, ChevronDown, Sparkles, User, AlertCircle, Loader2 } from "lucide-react";
// import { useState, useEffect } from "react";
// import DashboardLayout from "@/components/DashboardLayout";
// import axios from "axios";

// // Interface to handle the combined data structure
// interface TimelineEvent {
//   id: string;
//   type: "triage" | "consultation";
//   title: string;
//   date: string;
//   summary: string;
//   details?: string;
//   icon: any;
//   color: string;
// }

// const Timeline = () => {
//   const [expanded, setExpanded] = useState<string | null>(null);
//   const [events, setEvents] = useState<TimelineEvent[]>([]);
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     const fetchHealthJourney = async () => {
//       try {
//         const token = localStorage.getItem("token");
//         const storedUser = localStorage.getItem("user");
//         const parsedUser = storedUser ? JSON.parse(storedUser) : null;
//         const patientId = localStorage.getItem("userId") || parsedUser?.id;

//         if (!patientId) {
//           console.error("No Patient ID found");
//           setLoading(false);
//           return;
//         }

//         const headers = { Authorization: `Bearer ${token}` };

//         // Simultaneous fetch from the two distinct backend modules
//         const [triageRes, recordRes] = await Promise.all([
//           axios.get(`http://localhost:8080/api/triage/history/patient/${patientId}`, { headers }),
//           axios.get(`http://localhost:8080/api/records/patient/${patientId}`, { headers })
//         ]);

//         // 1. Map AI Triage Records
//         const triageEvents: TimelineEvent[] = triageRes.data.map((t: any) => ({
//           id: t.id,
//           type: "triage",
//           title: `AI Triage: ${t.predictedDisease}`,
//           date: t.createdAt,
//           summary: `Symptoms: ${t.symptomsInput}`,
//           details: t.aiAdvice,
//           icon: Sparkles,
//           color: "bg-accent"
//         }));

//         // 2. Map Doctor Consultations (excluding standalone file uploads)
//         const consultationEvents: TimelineEvent[] = recordRes.data
//           .filter((r: any) => !r.fileUrl) // Filter out pure report uploads
//           .map((r: any) => ({
//             id: r.id,
//             type: "consultation",
//             title: `Consultation: Dr. ${r.doctorName}`,
//             date: r.date,
//             summary: r.diagnosis,
//             details: r.symptoms ? `Patient reported: ${r.symptoms}` : undefined,
//             icon: User,
//             color: "bg-primary"
//           }));

//         // 3. Combine and Sort by Date (Newest first)
//         const combined = [...triageEvents, ...consultationEvents].sort(
//           (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
//         );

//         setEvents(combined);
//       } catch (error) {
//         console.error("Failed to load timeline:", error);
//       } finally {
//         setLoading(false);
//       }
//     };

//     fetchHealthJourney();
//   }, []);

//   const formatDate = (dateString: string) => {
//     return new Date(dateString).toLocaleDateString('en-US', { 
//       day: 'numeric', 
//       month: 'short', 
//       year: 'numeric',
//       hour: '2-digit',
//       minute: '2-digit'
//     });
//   };

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-3xl mx-auto">
//         <div className="mb-8">
//           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
//             <Clock size={28} className="text-accent" />
//             Health Timeline
//           </h1>
//           <p className="text-muted-foreground mt-1">Your complete journey: AI analysis & clinical visits</p>
//         </div>

//         <div className="relative">
//           {/* Vertical Timeline Thread */}
//           <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-accent via-primary/50 to-transparent" />

//           <div className="space-y-6">
//             {loading ? (
//               <div className="flex flex-col items-center py-20 text-muted-foreground gap-3">
//                 <Loader2 className="animate-spin text-accent" size={32} />
//                 <p className="italic">Syncing your health history...</p>
//               </div>
//             ) : events.length === 0 ? (
//               <div className="pl-16 py-10">
//                 <div className="glass rounded-2xl p-8 text-center border-dashed border-2">
//                   <AlertCircle className="mx-auto mb-2 opacity-20" size={40} />
//                   <p className="text-muted-foreground font-medium">Your timeline is empty.</p>
//                   <p className="text-xs text-muted-foreground/60">AI Triage chats and Doctor visits will appear here.</p>
//                 </div>
//               </div>
//             ) : (
//               events.map((item, i) => (
//                 <motion.div
//                   key={item.id}
//                   initial={{ opacity: 0, x: -20 }}
//                   whileInView={{ opacity: 1, x: 0 }}
//                   viewport={{ once: true }}
//                   transition={{ duration: 0.5, delay: i * 0.05 }}
//                   className="relative pl-16"
//                 >
//                   {/* Timeline Node */}
//                   <div className={`absolute left-4 top-4 w-5 h-5 rounded-full border-4 border-background z-10 ${item.color} shadow-lg`} />
                  
//                   {/* Timeline Card */}
//                   <div
//                     className="glass rounded-2xl p-5 shadow-float hover:shadow-float-lg transition-all duration-300 cursor-pointer group"
//                     onClick={() => setExpanded(expanded === item.id ? null : item.id)}
//                   >
//                     <div className="flex items-start justify-between">
//                       <div className="flex items-center gap-4">
//                         <div className={`p-2.5 rounded-xl ${item.type === 'triage' ? 'bg-accent/10 text-accent' : 'bg-primary/10 text-primary'}`}>
//                           <item.icon size={20} />
//                         </div>
//                         <div>
//                           <h3 className="font-display font-bold text-foreground text-sm group-hover:text-accent transition-colors">
//                             {item.title}
//                           </h3>
//                           <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-widest">
//                             {formatDate(item.date)}
//                           </p>
//                         </div>
//                       </div>
//                       <motion.div animate={{ rotate: expanded === item.id ? 180 : 0 }}>
//                         <ChevronDown size={18} className="text-muted-foreground" />
//                       </motion.div>
//                     </div>

//                     <div className="mt-2 pl-14">
//                        <p className="text-xs text-muted-foreground line-clamp-1 italic">
//                         {item.summary}
//                       </p>
//                     </div>

//                     <AnimatePresence>
//                       {expanded === item.id && (
//                         <motion.div
//                           initial={{ opacity: 0, height: 0 }}
//                           animate={{ opacity: 1, height: "auto" }}
//                           exit={{ opacity: 0, height: 0 }}
//                           className="mt-4 pt-4 border-t border-border/50 overflow-hidden"
//                         >
//                           <div className="space-y-3">
//                             <div className="bg-foreground/5 rounded-xl p-3">
//                                <p className="text-[10px] font-bold text-accent uppercase mb-1">
//                                  {item.type === 'triage' ? 'AI Recommendations' : 'Doctor Diagnosis'}
//                                </p>
//                                <p className="text-sm text-foreground leading-relaxed whitespace-pre-wrap">
//                                  {item.details || item.summary}
//                                </p>
//                             </div>
//                             {item.type === 'triage' && (
//                               <p className="text-[10px] text-muted-foreground italic">
//                                 * This analysis was performed by Medibot AI and is for informational purposes.
//                               </p>
//                             )}
//                           </div>
//                         </motion.div>
//                       )}
//                     </AnimatePresence>
//                   </div>
//                 </motion.div>
//               ))
//             )}
//           </div>
//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default Timeline;




import { motion, AnimatePresence } from "framer-motion";
import { Clock, MessageSquare, FileText, Calendar, ChevronDown, Sparkles, User, AlertCircle, Loader2 } from "lucide-react";
import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api"; // FIX: Use centralized api instance for interceptors

// Interface to handle the combined data structure
interface TimelineEvent {
  id: string;
  type: "triage" | "consultation";
  title: string;
  date: string;
  summary: string;
  details?: string;
  icon: any;
  color: string;
}

const Timeline = () => {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHealthJourney = async () => {
      try {
        setLoading(true);
        // FIX: Consistent ID retrieval matching AuthService.ts
        const patientId = localStorage.getItem("userId");

        if (!patientId || patientId === "undefined") {
          console.warn("No valid Patient ID found in storage. Redirecting or showing empty state.");
          setLoading(false);
          return;
        }

        // Simpler simultaneous fetch using the authenticated 'api' instance
        // FIX: Interceptors handle the Bearer token automatically now
        const [triageRes, recordRes] = await Promise.all([
          api.get(`/triage/history/patient/${patientId}`),
          api.get(`/records/patient/${patientId}`)
        ]);

        // 1. Map AI Triage Records (from TriageHistoryController)
        const triageEvents: TimelineEvent[] = triageRes.data.map((t: any) => ({
          id: t.id,
          type: "triage",
          title: `AI Triage: ${t.predictedDisease}`,
          date: t.createdAt, // Standard timestamp from backend
          summary: `Symptoms: ${t.symptomsInput}`,
          details: t.aiAdvice,
          icon: Sparkles,
          color: "bg-accent"
        }));

        // 2. Map Doctor Consultations (from MedicalRecordController)
        const consultationEvents: TimelineEvent[] = recordRes.data
          .filter((r: any) => !r.fileUrl) // Filter out pure file reports for a cleaner timeline
          .map((r: any) => ({
            id: r.id,
            type: "consultation",
            title: `Consultation: Dr. ${r.doctorName || 'Specialist'}`,
            date: r.date || r.createdAt,
            summary: r.diagnosis || 'General Checkup',
            details: r.symptoms ? `Patient reported: ${r.symptoms}` : undefined,
            icon: User,
            color: "bg-primary"
          }));

        // 3. Combine and Sort by Date (Newest first)
        const combined = [...triageEvents, ...consultationEvents].sort(
          (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
        );

        setEvents(combined);
      } catch (error: any) {
        console.error("Failed to load timeline history:", error);
        // If 403, we know the session is invalid
        if (error.response?.status === 403) {
          console.error("Auth mismatch. Session might be stale.");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchHealthJourney();
  }, []);

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', { 
        day: 'numeric', 
        month: 'short', 
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (e) {
      return dateString;
    }
  };

  return (
    <DashboardLayout role="patient">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
            <Clock size={28} className="text-accent" />
            Health Timeline
          </h1>
          <p className="text-muted-foreground mt-1">Your complete journey: AI analysis & clinical visits</p>
        </div>

        <div className="relative">
          {/* Vertical Timeline Thread */}
          <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-accent via-primary/50 to-transparent" />

          <div className="space-y-6">
            {loading ? (
              <div className="flex flex-col items-center py-20 text-muted-foreground gap-3">
                <Loader2 className="animate-spin text-accent" size={32} />
                <p className="italic">Syncing your health history...</p>
              </div>
            ) : events.length === 0 ? (
              <div className="pl-16 py-10">
                <div className="glass rounded-2xl p-8 text-center border-dashed border-2">
                  <AlertCircle className="mx-auto mb-2 opacity-20" size={40} />
                  <p className="text-muted-foreground font-medium">Your timeline is empty.</p>
                  <p className="text-xs text-muted-foreground/60">AI Triage chats and Doctor visits will appear here.</p>
                </div>
              </div>
            ) : (
              events.map((item, i) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, x: -20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: i * 0.05 }}
                  className="relative pl-16"
                >
                  {/* Timeline Node */}
                  <div className={`absolute left-4 top-4 w-5 h-5 rounded-full border-4 border-background z-10 ${item.color} shadow-lg`} />
                  
                  {/* Timeline Card */}
                  <div
                    className="glass rounded-2xl p-5 shadow-float hover:shadow-float-lg transition-all duration-300 cursor-pointer group"
                    onClick={() => setExpanded(expanded === item.id ? null : item.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-4">
                        <div className={`p-2.5 rounded-xl ${item.type === 'triage' ? 'bg-accent/10 text-accent' : 'bg-primary/10 text-primary'}`}>
                          <item.icon size={20} />
                        </div>
                        <div>
                          <h3 className="font-display font-bold text-foreground text-sm group-hover:text-accent transition-colors">
                            {item.title}
                          </h3>
                          <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-widest">
                            {formatDate(item.date)}
                          </p>
                        </div>
                      </div>
                      <motion.div animate={{ rotate: expanded === item.id ? 180 : 0 }}>
                        <ChevronDown size={18} className="text-muted-foreground" />
                      </motion.div>
                    </div>

                    <div className="mt-2 pl-14">
                       <p className="text-xs text-muted-foreground line-clamp-1 italic">
                        {item.summary}
                      </p>
                    </div>

                    <AnimatePresence>
                      {expanded === item.id && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          className="mt-4 pt-4 border-t border-border/50 overflow-hidden"
                        >
                          <div className="space-y-3">
                            <div className="bg-foreground/5 rounded-xl p-3">
                               <p className="text-[10px] font-bold text-accent uppercase mb-1">
                                 {item.type === 'triage' ? 'AI Recommendations' : 'Doctor Diagnosis'}
                               </p>
                               <p className="text-sm text-foreground leading-relaxed whitespace-pre-wrap">
                                 {item.details || item.summary}
                               </p>
                            </div>
                            {item.type === 'triage' && (
                              <p className="text-[10px] text-muted-foreground italic">
                                * This analysis was performed by Medibot AI and is for informational purposes.
                              </p>
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </motion.div>
              ))
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Timeline;