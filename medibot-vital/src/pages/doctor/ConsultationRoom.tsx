// // // // // // // // // // // // // import { useState } from "react";
// // // // // // // // // // // // // import { motion } from "framer-motion";
// // // // // // // // // // // // // import { Mic, MicOff, Video as VideoIcon, VideoOff, Phone, FileText, MessageSquare, Clock, User, Upload } from "lucide-react";
// // // // // // // // // // // // // import DashboardLayout from "@/components/DashboardLayout";

// // // // // // // // // // // // // const DoctorConsultationRoom = () => {
// // // // // // // // // // // // //   const [micOn, setMicOn] = useState(true);
// // // // // // // // // // // // //   const [camOn, setCamOn] = useState(true);
// // // // // // // // // // // // //   const [activeTab, setActiveTab] = useState<"transcript" | "documents" | "history">("transcript");

// // // // // // // // // // // // //   return (
// // // // // // // // // // // // //     <DashboardLayout role="doctor">
// // // // // // // // // // // // //       <div className="max-w-7xl mx-auto">
// // // // // // // // // // // // //         <h1 className="font-display text-2xl font-bold text-foreground mb-4">Consultation Room</h1>
// // // // // // // // // // // // //         <p className="text-sm text-muted-foreground mb-6">Patient: Alex Thompson</p>

// // // // // // // // // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 h-[calc(100vh-14rem)]">
// // // // // // // // // // // // //           {/* Video */}
// // // // // // // // // // // // //           <div className="glass rounded-2xl overflow-hidden flex flex-col">
// // // // // // // // // // // // //             <div className="flex-1 bg-gradient-to-br from-foreground/5 to-foreground/10 flex items-center justify-center relative">
// // // // // // // // // // // // //               <div className="text-center">
// // // // // // // // // // // // //                 <div className="w-24 h-24 rounded-full bg-gradient-to-br from-primary/30 to-accent/30 flex items-center justify-center mx-auto mb-4">
// // // // // // // // // // // // //                   <User size={40} className="text-accent" />
// // // // // // // // // // // // //                 </div>
// // // // // // // // // // // // //                 <p className="text-muted-foreground">Alex Thompson</p>
// // // // // // // // // // // // //                 <p className="text-xs text-muted-foreground/60">Connected</p>
// // // // // // // // // // // // //               </div>
// // // // // // // // // // // // //               <div className="absolute bottom-4 right-4 w-36 h-28 glass rounded-xl flex items-center justify-center">
// // // // // // // // // // // // //                 <User size={24} className="text-muted-foreground" />
// // // // // // // // // // // // //               </div>
// // // // // // // // // // // // //             </div>

// // // // // // // // // // // // //             <div className="p-4 flex items-center justify-center gap-3">
// // // // // // // // // // // // //               <motion.button whileTap={{ scale: 0.9 }} onClick={() => setMicOn(!micOn)}
// // // // // // // // // // // // //                 className={`w-12 h-12 rounded-full flex items-center justify-center transition-all ${micOn ? "glass hover:bg-secondary" : "bg-destructive text-destructive-foreground"}`}>
// // // // // // // // // // // // //                 {micOn ? <Mic size={20} /> : <MicOff size={20} />}
// // // // // // // // // // // // //               </motion.button>
// // // // // // // // // // // // //               <motion.button whileTap={{ scale: 0.9 }} onClick={() => setCamOn(!camOn)}
// // // // // // // // // // // // //                 className={`w-12 h-12 rounded-full flex items-center justify-center transition-all ${camOn ? "glass hover:bg-secondary" : "bg-destructive text-destructive-foreground"}`}>
// // // // // // // // // // // // //                 {camOn ? <VideoIcon size={20} /> : <VideoOff size={20} />}
// // // // // // // // // // // // //               </motion.button>
// // // // // // // // // // // // //               <motion.button whileTap={{ scale: 0.9 }}
// // // // // // // // // // // // //                 className="w-14 h-14 rounded-full bg-destructive text-destructive-foreground flex items-center justify-center hover:scale-105 transition-all">
// // // // // // // // // // // // //                 <Phone size={22} className="rotate-[135deg]" />
// // // // // // // // // // // // //               </motion.button>
// // // // // // // // // // // // //             </div>
// // // // // // // // // // // // //           </div>

// // // // // // // // // // // // //           {/* Side Panel */}
// // // // // // // // // // // // //           <div className="glass rounded-2xl flex flex-col overflow-hidden">
// // // // // // // // // // // // //             <div className="flex border-b border-border/30">
// // // // // // // // // // // // //               {([
// // // // // // // // // // // // //                 { key: "transcript" as const, label: "Transcript", icon: MessageSquare },
// // // // // // // // // // // // //                 { key: "documents" as const, label: "Reports", icon: FileText },
// // // // // // // // // // // // //                 { key: "history" as const, label: "History", icon: Clock },
// // // // // // // // // // // // //               ]).map((tab) => (
// // // // // // // // // // // // //                 <button key={tab.key} onClick={() => setActiveTab(tab.key)}
// // // // // // // // // // // // //                   className={`flex-1 flex items-center justify-center gap-1.5 py-3 text-xs font-medium transition-all ${
// // // // // // // // // // // // //                     activeTab === tab.key ? "text-accent border-b-2 border-accent" : "text-muted-foreground hover:text-foreground"
// // // // // // // // // // // // //                   }`}>
// // // // // // // // // // // // //                   <tab.icon size={14} />
// // // // // // // // // // // // //                   {tab.label}
// // // // // // // // // // // // //                 </button>
// // // // // // // // // // // // //               ))}
// // // // // // // // // // // // //             </div>

// // // // // // // // // // // // //             <div className="flex-1 overflow-y-auto p-4">
// // // // // // // // // // // // //               {activeTab === "transcript" && (
// // // // // // // // // // // // //                 <div className="space-y-3">
// // // // // // // // // // // // //                   {["Patient reports persistent headaches for a week.", "Onset is typically in the afternoon.", "No visual disturbances or nausea reported."].map((line, i) => (
// // // // // // // // // // // // //                     <motion.div key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.2 }}
// // // // // // // // // // // // //                       className="glass-strong rounded-xl p-3 text-xs text-muted-foreground">{line}</motion.div>
// // // // // // // // // // // // //                   ))}
// // // // // // // // // // // // //                 </div>
// // // // // // // // // // // // //               )}
// // // // // // // // // // // // //               {activeTab === "documents" && (
// // // // // // // // // // // // //                 <div className="space-y-2">
// // // // // // // // // // // // //                   {["Blood Test - Feb 2026.pdf", "Previous Prescription.pdf", "MRI Report.pdf"].map((d, i) => (
// // // // // // // // // // // // //                     <div key={i} className="glass rounded-xl p-3 flex items-center gap-2 text-xs cursor-pointer hover:shadow-glow-accent transition-all">
// // // // // // // // // // // // //                       <FileText size={14} className="text-accent" /> <span className="text-foreground">{d}</span>
// // // // // // // // // // // // //                     </div>
// // // // // // // // // // // // //                   ))}
// // // // // // // // // // // // //                   <button className="w-full glass rounded-xl p-3 flex items-center justify-center gap-2 text-xs text-accent hover:shadow-glow-accent transition-all mt-2">
// // // // // // // // // // // // //                     <Upload size={14} /> Upload Report
// // // // // // // // // // // // //                   </button>
// // // // // // // // // // // // //                 </div>
// // // // // // // // // // // // //               )}
// // // // // // // // // // // // //               {activeTab === "history" && (
// // // // // // // // // // // // //                 <div className="space-y-2 text-xs">
// // // // // // // // // // // // //                   <div className="glass rounded-xl p-3"><span className="font-semibold text-foreground">Conditions:</span> <span className="text-muted-foreground">Hypertension, Migraine</span></div>
// // // // // // // // // // // // //                   <div className="glass rounded-xl p-3"><span className="font-semibold text-foreground">Allergies:</span> <span className="text-muted-foreground">Penicillin</span></div>
// // // // // // // // // // // // //                   <div className="glass rounded-xl p-3"><span className="font-semibold text-foreground">Last Visit:</span> <span className="text-muted-foreground">Jan 15, 2026 - General Checkup</span></div>
// // // // // // // // // // // // //                   <div className="glass rounded-xl p-3"><span className="font-semibold text-foreground">Medications:</span> <span className="text-muted-foreground">Amlodipine 5mg, Sumatriptan PRN</span></div>
// // // // // // // // // // // // //                 </div>
// // // // // // // // // // // // //               )}
// // // // // // // // // // // // //             </div>
// // // // // // // // // // // // //           </div>
// // // // // // // // // // // // //         </div>
// // // // // // // // // // // // //       </div>
// // // // // // // // // // // // //     </DashboardLayout>
// // // // // // // // // // // // //   );
// // // // // // // // // // // // // };

// // // // // // // // // // // // // export default DoctorConsultationRoom;




// // // // // // // // // // // // import { useState, useEffect } from "react";
// // // // // // // // // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // // // // // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // // // // // // // // import { Mic, MicOff, Video as VideoIcon, VideoOff, Phone, FileText, ClipboardCheck, Loader2, User } from "lucide-react";
// // // // // // // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // // // // // // import api from "@/lib/api";
// // // // // // // // // // // // import { toast } from "sonner";

// // // // // // // // // // // // const DoctorConsultationRoom = () => {
// // // // // // // // // // // //   const { bookingId } = useParams();
// // // // // // // // // // // //   const navigate = useNavigate();
  
// // // // // // // // // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // // // // // // // // //   const [loading, setLoading] = useState(true);
// // // // // // // // // // // //   const [notes, setNotes] = useState("");
// // // // // // // // // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // // // // // // // // //   // 1. Handshake with backend to record session start
// // // // // // // // // // // //   useEffect(() => {
// // // // // // // // // // // //     const initSession = async () => {
// // // // // // // // // // // //       try {
// // // // // // // // // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // // // // // // // // //         setConsultation(res.data);
// // // // // // // // // // // //       } catch (err) {
// // // // // // // // // // // //         toast.error("Session initialization failed.");
// // // // // // // // // // // //         navigate("/doctor/appointments");
// // // // // // // // // // // //       } finally {
// // // // // // // // // // // //         setLoading(false);
// // // // // // // // // // // //       }
// // // // // // // // // // // //     };
// // // // // // // // // // // //     initSession();
// // // // // // // // // // // //   }, [bookingId]);

// // // // // // // // // // // //   // 2. End Call Handler: Saves notes to the patient's record
// // // // // // // // // // // //   const handleEndCall = async () => {
// // // // // // // // // // // //     if (!consultation?.id) return;
// // // // // // // // // // // //     try {
// // // // // // // // // // // //       setIsEnding(true);
// // // // // // // // // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
// // // // // // // // // // // //       toast.success("Consultation finalized successfully.");
// // // // // // // // // // // //       navigate("/doctor/appointments");
// // // // // // // // // // // //     } catch (err) {
// // // // // // // // // // // //       toast.error("Failed to save clinical notes.");
// // // // // // // // // // // //     } finally {
// // // // // // // // // // // //       setIsEnding(false);
// // // // // // // // // // // //     }
// // // // // // // // // // // //   };

// // // // // // // // // // // //   if (loading) return <div className="flex items-center justify-center min-h-screen"><Loader2 className="animate-spin text-accent" /></div>;

// // // // // // // // // // // //   return (
// // // // // // // // // // // //     <DashboardLayout role="doctor">
// // // // // // // // // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
// // // // // // // // // // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10">
// // // // // // // // // // // //           <div>
// // // // // // // // // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2">
// // // // // // // // // // // //               <div className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
// // // // // // // // // // // //               Live Clinical Session
// // // // // // // // // // // //             </h1>
// // // // // // // // // // // //             <p className="text-[10px] text-muted-foreground uppercase tracking-widest mt-1">Ref ID: {consultation?.id.substring(0,8)}</p>
// // // // // // // // // // // //           </div>
// // // // // // // // // // // //           <button 
// // // // // // // // // // // //             onClick={handleEndCall} 
// // // // // // // // // // // //             disabled={isEnding}
// // // // // // // // // // // //             className="bg-destructive text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95"
// // // // // // // // // // // //           >
// // // // // // // // // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // // // // // // // // //             Finish & Save Notes
// // // // // // // // // // // //           </button>
// // // // // // // // // // // //         </div>

// // // // // // // // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
// // // // // // // // // // // //           {/* Jitsi Live Video */}
// // // // // // // // // // // //           <div className="glass rounded-3xl overflow-hidden border-white/5 bg-black/40">
// // // // // // // // // // // //             <JitsiMeeting
// // // // // // // // // // // //               domain="meet.jit.si"
// // // // // // // // // // // //               roomName={`Medibot-Room-${bookingId}`}
// // // // // // // // // // // //               configOverwrite={{ startWithAudioMuted: false, prejoinPageEnabled: false }}
// // // // // // // // // // // //               getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; }}
// // // // // // // // // // // //             />
// // // // // // // // // // // //           </div>

// // // // // // // // // // // //           {/* Clinical Workspace */}
// // // // // // // // // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5">
// // // // // // // // // // // //             <div className="p-5 border-b border-white/5 bg-white/5">
// // // // // // // // // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // // // // // // // // //                 <FileText size={16} /> Physician's Notes
// // // // // // // // // // // //               </h3>
// // // // // // // // // // // //             </div>
// // // // // // // // // // // //             <div className="flex-1 p-4">
// // // // // // // // // // // //               <textarea 
// // // // // // // // // // // //                 value={notes} 
// // // // // // // // // // // //                 onChange={(e) => setNotes(e.target.value)}
// // // // // // // // // // // //                 placeholder="Document diagnosis, symptoms, and advice..."
// // // // // // // // // // // //                 className="w-full h-full bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30"
// // // // // // // // // // // //               />
// // // // // // // // // // // //             </div>
// // // // // // // // // // // //             <div className="p-4 bg-accent/5 flex items-center justify-center text-[10px] text-muted-foreground gap-2 font-medium">
// // // // // // // // // // // //                <ClipboardCheck size={12} /> Auto-saving to Patient Medical History
// // // // // // // // // // // //             </div>
// // // // // // // // // // // //           </div>
// // // // // // // // // // // //         </div>
// // // // // // // // // // // //       </div>
// // // // // // // // // // // //     </DashboardLayout>
// // // // // // // // // // // //   );
// // // // // // // // // // // // };

// // // // // // // // // // // // export default DoctorConsultationRoom;








// // // // // // // // // // // import { useState, useEffect } from "react";
// // // // // // // // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // // // // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // // // // // // // import { Phone, FileText, ClipboardCheck, Loader2, ShieldCheck, Save } from "lucide-react";
// // // // // // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // // // // // import api from "@/lib/api";
// // // // // // // // // // // import { toast } from "sonner";

// // // // // // // // // // // const DoctorConsultationRoom = () => {
// // // // // // // // // // //   const { bookingId } = useParams();
// // // // // // // // // // //   const navigate = useNavigate();
  
// // // // // // // // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // // // // // // // //   const [loading, setLoading] = useState(true);
// // // // // // // // // // //   const [notes, setNotes] = useState("");
// // // // // // // // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // // // // // // // //   // 1. Backend Handshake: Open the medical session record
// // // // // // // // // // //   useEffect(() => {
// // // // // // // // // // //     const initSession = async () => {
// // // // // // // // // // //       try {
// // // // // // // // // // //         setLoading(true);
// // // // // // // // // // //         // Hits @PostMapping("/start/{bookingId}")
// // // // // // // // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // // // // // // // //         setConsultation(res.data);
// // // // // // // // // // //       } catch (err) {
// // // // // // // // // // //         toast.error("Handshake failed. Ensure session isn't already closed.");
// // // // // // // // // // //         navigate("/doctor/appointments");
// // // // // // // // // // //       } finally {
// // // // // // // // // // //         setLoading(false);
// // // // // // // // // // //       }
// // // // // // // // // // //     };
// // // // // // // // // // //     initSession();
// // // // // // // // // // //   }, [bookingId, navigate]);

// // // // // // // // // // //   // 2. Wrap-up: Close session and save clinical documentation
// // // // // // // // // // //   const handleEndCall = async () => {
// // // // // // // // // // //     if (!consultation?.id) return;
// // // // // // // // // // //     try {
// // // // // // // // // // //       setIsEnding(true);
// // // // // // // // // // //       // Hits @PatchMapping("/end/{id}")
// // // // // // // // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
// // // // // // // // // // //       toast.success("Medical record saved successfully.");
// // // // // // // // // // //       navigate("/doctor/appointments");
// // // // // // // // // // //     } catch (err) {
// // // // // // // // // // //       toast.error("Sync failed. Copy your notes before leaving.");
// // // // // // // // // // //     } finally {
// // // // // // // // // // //       setIsEnding(false);
// // // // // // // // // // //     }
// // // // // // // // // // //   };

// // // // // // // // // // //   if (loading) return (
// // // // // // // // // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // // // // // // // // //       <Loader2 className="animate-spin text-accent mb-4" size={48} />
// // // // // // // // // // //       <p className="text-muted-foreground animate-pulse">Initializing clinical encryption...</p>
// // // // // // // // // // //     </div>
// // // // // // // // // // //   );

// // // // // // // // // // //   return (
// // // // // // // // // // //     <DashboardLayout role="doctor">
// // // // // // // // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // // // // // // // // //         {/* Active Session Bar */}
// // // // // // // // // // //         <div className="flex justify-between items-center bg-white/5 p-5 rounded-3xl border border-white/10 shadow-float">
// // // // // // // // // // //           <div>
// // // // // // // // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2">
// // // // // // // // // // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // // // // // // // // // //               Active Medical Session
// // // // // // // // // // //             </h1>
// // // // // // // // // // //             <p className="text-[10px] text-muted-foreground uppercase tracking-widest mt-1 flex items-center gap-2">
// // // // // // // // // // //                <ShieldCheck size={12} className="text-success" /> HIPAA COMPLIANT TUNNEL
// // // // // // // // // // //             </p>
// // // // // // // // // // //           </div>
          
// // // // // // // // // // //           <button 
// // // // // // // // // // //             onClick={handleEndCall} 
// // // // // // // // // // //             disabled={isEnding}
// // // // // // // // // // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3.5 rounded-2xl flex items-center gap-3 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // // // // // // // // // //           >
// // // // // // // // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // // // // // // // //             Finalize & Save Record
// // // // // // // // // // //           </button>
// // // // // // // // // // //         </div>

// // // // // // // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // // // // // // // // // //           {/* Live Video Feed */}
// // // // // // // // // // //           <div className="glass rounded-3xl overflow-hidden border-white/5 bg-black/50">
// // // // // // // // // // //             <JitsiMeeting
// // // // // // // // // // //               domain="meet.jit.si"
// // // // // // // // // // //               roomName={`Medibot-Room-${bookingId}`}
// // // // // // // // // // //               configOverwrite={{ 
// // // // // // // // // // //                 startWithAudioMuted: false, 
// // // // // // // // // // //                 prejoinPageEnabled: false,
// // // // // // // // // // //                 enableWelcomePage: false
// // // // // // // // // // //               }}
// // // // // // // // // // //               getIFrameRef={(iframeRef) => { 
// // // // // // // // // // //                 iframeRef.style.height = '100%'; 
// // // // // // // // // // //                 iframeRef.style.width = '100%'; 
// // // // // // // // // // //               }}
// // // // // // // // // // //             />
// // // // // // // // // // //           </div>

// // // // // // // // // // //           {/* Physician workspace synced to Medical Record database */}
// // // // // // // // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // // // // // // // // // //             <div className="p-5 border-b border-white/5 flex items-center justify-between">
// // // // // // // // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // // // // // // // //                 <FileText size={16} /> Clinical Findings
// // // // // // // // // // //               </h3>
// // // // // // // // // // //               <Save size={14} className="text-muted-foreground opacity-30" />
// // // // // // // // // // //             </div>
            
// // // // // // // // // // //             <div className="flex-1 p-5">
// // // // // // // // // // //               <textarea 
// // // // // // // // // // //                 value={notes} 
// // // // // // // // // // //                 onChange={(e) => setNotes(e.target.value)}
// // // // // // // // // // //                 placeholder="Document diagnosis, symptoms, and advice here. These will be added to the patient's permanent record..."
// // // // // // // // // // //                 className="w-full h-full bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/90 placeholder:text-muted-foreground/20 font-medium"
// // // // // // // // // // //               />
// // // // // // // // // // //             </div>
            
// // // // // // // // // // //             <div className="p-5 bg-black/20 border-t border-white/5 flex items-center gap-3 text-[10px] text-muted-foreground">
// // // // // // // // // // //                <ClipboardCheck size={14} className="text-success" />
// // // // // // // // // // //                <span>AUTO-SYNC ENABLED FOR MEDIBOT ID: {consultation?.id.substring(0,8)}</span>
// // // // // // // // // // //             </div>
// // // // // // // // // // //           </div>

// // // // // // // // // // //         </div>
// // // // // // // // // // //       </div>
// // // // // // // // // // //     </DashboardLayout>
// // // // // // // // // // //   );
// // // // // // // // // // // };

// // // // // // // // // // // export default DoctorConsultationRoom;







// // // // // // // // // // import { useState, useEffect } from "react"; // FIXED: useState only declared once here
// // // // // // // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // // // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // // // // // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // // // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // // // // import api from "@/lib/api";
// // // // // // // // // // import { toast } from "sonner";

// // // // // // // // // // const DoctorConsultationRoom = () => {
// // // // // // // // // //   const { bookingId } = useParams();
// // // // // // // // // //   const navigate = useNavigate();
  
// // // // // // // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // // // // // // //   const [loading, setLoading] = useState(true);
// // // // // // // // // //   const [notes, setNotes] = useState("");
// // // // // // // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // // // // // // //   // 1. Handshake: Hits @PostMapping("/start/{bookingId}")
// // // // // // // // // //   useEffect(() => {
// // // // // // // // // //     const initSession = async () => {
// // // // // // // // // //       try {
// // // // // // // // // //         setLoading(true);
// // // // // // // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // // // // // // //         setConsultation(res.data);
// // // // // // // // // //       } catch (err) {
// // // // // // // // // //         toast.error("Handshake failed. Ensure session isn't already closed.");
// // // // // // // // // //         navigate("/doctor/appointments");
// // // // // // // // // //       } finally {
// // // // // // // // // //         setLoading(false);
// // // // // // // // // //       }
// // // // // // // // // //     };
// // // // // // // // // //     initSession();
// // // // // // // // // //   }, [bookingId, navigate]);

// // // // // // // // // //   // 2. Wrap-up: Hits @PatchMapping("/end/{id}")
// // // // // // // // // //   const handleEndCall = async () => {
// // // // // // // // // //     if (!consultation?.id) return;
// // // // // // // // // //     try {
// // // // // // // // // //       setIsEnding(true);
// // // // // // // // // //       // Backend expects raw string notes
// // // // // // // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
// // // // // // // // // //       toast.success("Record saved to history.");
// // // // // // // // // //       navigate("/doctor/appointments");
// // // // // // // // // //     } catch (err) {
// // // // // // // // // //       toast.error("Sync failed. Check connection.");
// // // // // // // // // //     } finally {
// // // // // // // // // //       setIsEnding(false);
// // // // // // // // // //     }
// // // // // // // // // //   };

// // // // // // // // // //   if (loading) return (
// // // // // // // // // //     <div className="min-h-screen flex items-center justify-center">
// // // // // // // // // //       <Loader2 className="animate-spin text-accent" size={40} />
// // // // // // // // // //     </div>
// // // // // // // // // //   );

// // // // // // // // // //   return (
// // // // // // // // // //     <DashboardLayout role="doctor">
// // // // // // // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // // // // // // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10">
// // // // // // // // // //           <div>
// // // // // // // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2">
// // // // // // // // // //               <div className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
// // // // // // // // // //               Live Consultation
// // // // // // // // // //             </h1>
// // // // // // // // // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1">
// // // // // // // // // //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT TUNNEL
// // // // // // // // // //             </p>
// // // // // // // // // //           </div>
// // // // // // // // // //           <button 
// // // // // // // // // //             onClick={handleEndCall} 
// // // // // // // // // //             disabled={isEnding}
// // // // // // // // // //             className="bg-destructive text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold transition-all active:scale-95 disabled:opacity-50"
// // // // // // // // // //           >
// // // // // // // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // // // // // // //             End & Save Record
// // // // // // // // // //           </button>
// // // // // // // // // //         </div>

// // // // // // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
// // // // // // // // // //           {/* Jitsi Meeting Integration */}
// // // // // // // // // //           <div className="glass rounded-3xl overflow-hidden bg-black/40">
// // // // // // // // // //             <JitsiMeeting
// // // // // // // // // //               domain="meet.jit.si"
// // // // // // // // // //               roomName={`Medibot-Room-${bookingId}`} // Matches patient side room name
// // // // // // // // // //               configOverwrite={{ startWithAudioMuted: false, prejoinPageEnabled: false }}
// // // // // // // // // //               getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; }}
// // // // // // // // // //             />
// // // // // // // // // //           </div>

// // // // // // // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden bg-white/5">
// // // // // // // // // //             <div className="p-5 border-b border-white/5">
// // // // // // // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // // // // // // //                 <FileText size={16} /> Physician's Notes
// // // // // // // // // //               </h3>
// // // // // // // // // //             </div>
// // // // // // // // // //             <textarea 
// // // // // // // // // //               value={notes} 
// // // // // // // // // //               onChange={(e) => setNotes(e.target.value)}
// // // // // // // // // //               placeholder="Start documenting diagnosis..."
// // // // // // // // // //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80"
// // // // // // // // // //             />
// // // // // // // // // //             <div className="p-4 bg-accent/5 flex items-center justify-center text-[10px] text-muted-foreground gap-2">
// // // // // // // // // //                <ClipboardCheck size={12} /> Syncing with Medical ID: {consultation?.id.substring(0,8)}
// // // // // // // // // //             </div>
// // // // // // // // // //           </div>
// // // // // // // // // //         </div>
// // // // // // // // // //       </div>
// // // // // // // // // //     </DashboardLayout>
// // // // // // // // // //   );
// // // // // // // // // // };

// // // // // // // // // // export default DoctorConsultationRoom;






// // // // // // // // // import { useState, useEffect } from "react"; 
// // // // // // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // // // // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // // // import api from "@/lib/api";
// // // // // // // // // import { toast } from "sonner";

// // // // // // // // // const DoctorConsultationRoom = () => {
// // // // // // // // //   const { bookingId } = useParams(); // Retrieves the specific appointment ID from the route
// // // // // // // // //   const navigate = useNavigate();
  
// // // // // // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // // // // // //   const [loading, setLoading] = useState(true);
// // // // // // // // //   const [notes, setNotes] = useState("");
// // // // // // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // // // // // //   // 1. Session Handshake: Hits @PostMapping("/start/{bookingId}") to record session start
// // // // // // // // //   useEffect(() => {
// // // // // // // // //     const initSession = async () => {
// // // // // // // // //       if (!bookingId) {
// // // // // // // // //         toast.error("Invalid booking reference.");
// // // // // // // // //         navigate("/doctor/appointments");
// // // // // // // // //         return;
// // // // // // // // //       }

// // // // // // // // //       try {
// // // // // // // // //         setLoading(true);
// // // // // // // // //         // This ensures a Consultation entity is created and linked to the Booking
// // // // // // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // // // // // //         setConsultation(res.data);
// // // // // // // // //       } catch (err) {
// // // // // // // // //         console.error("Clinical Handshake Failed:", err);
// // // // // // // // //         toast.error("Could not initialize the clinical room. Verify appointment status.");
// // // // // // // // //         navigate("/doctor/appointments");
// // // // // // // // //       } finally {
// // // // // // // // //         setLoading(false);
// // // // // // // // //       }
// // // // // // // // //     };
// // // // // // // // //     initSession();
// // // // // // // // //   }, [bookingId, navigate]);

// // // // // // // // //   // 2. Wrap-up logic: Hits @PatchMapping("/end/{id}") to finalize medical record
// // // // // // // // //   const handleEndCall = async () => {
// // // // // // // // //     if (!consultation?.id) return;
    
// // // // // // // // //     try {
// // // // // // // // //       setIsEnding(true);
// // // // // // // // //       // Sends the physician's notes to be saved in the database
// // // // // // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
      
// // // // // // // // //       toast.success("Consultation complete. Notes finalized in medical records.");
// // // // // // // // //       navigate("/doctor/appointments"); // Redirect back to schedule
// // // // // // // // //     } catch (err) {
// // // // // // // // //       toast.error("Sync failed. Please copy your notes before exiting.");
// // // // // // // // //     } finally {
// // // // // // // // //       setIsEnding(false);
// // // // // // // // //     }
// // // // // // // // //   };

// // // // // // // // //   if (loading) return (
// // // // // // // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // // // // // // //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// // // // // // // // //       <p className="text-muted-foreground animate-pulse font-medium">Entering clinical room...</p>
// // // // // // // // //     </div>
// // // // // // // // //   );

// // // // // // // // //   return (
// // // // // // // // //     <DashboardLayout role="doctor">
// // // // // // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // // // // // // //         {/* Active Call Management Bar */}
// // // // // // // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// // // // // // // // //           <div>
// // // // // // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2">
// // // // // // // // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // // // // // // // //               Live Consultation
// // // // // // // // //             </h1>
// // // // // // // // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-bold">
// // // // // // // // //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT TUNNEL
// // // // // // // // //             </p>
// // // // // // // // //           </div>
          
// // // // // // // // //           <button 
// // // // // // // // //             onClick={handleEndCall} 
// // // // // // // // //             disabled={isEnding}
// // // // // // // // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // // // // // // // //           >
// // // // // // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // // // // // //             Finish & Save Record
// // // // // // // // //           </button>
// // // // // // // // //         </div>

// // // // // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // // // // // // // //           {/* Jitsi Meeting Viewport (WebRTC Integration) */}
// // // // // // // // //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
// // // // // // // // //             <JitsiMeeting
// // // // // // // // //               domain="meet.jit.si"
// // // // // // // // //               roomName={`Medibot-Room-${bookingId}`} // Standardized to match the Patient side
// // // // // // // // //               configOverwrite={{ 
// // // // // // // // //                 startWithAudioMuted: false, 
// // // // // // // // //                 prejoinPageEnabled: false,
// // // // // // // // //                 enableWelcomePage: false
// // // // // // // // //               }}
// // // // // // // // //               getIFrameRef={(iframeRef) => { 
// // // // // // // // //                 iframeRef.style.height = '100%'; 
// // // // // // // // //                 iframeRef.style.width = '100%'; 
// // // // // // // // //               }}
// // // // // // // // //             />
// // // // // // // // //           </div>

// // // // // // // // //           {/* Physician's Workspace synced with Consultation Entity */}
// // // // // // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // // // // // // // //             <div className="p-5 border-b border-white/5 bg-white/5">
// // // // // // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // // // // // //                 <FileText size={16} /> Physician's Notes
// // // // // // // // //               </h3>
// // // // // // // // //             </div>
            
// // // // // // // // //             <textarea 
// // // // // // // // //               value={notes} 
// // // // // // // // //               onChange={(e) => setNotes(e.target.value)}
// // // // // // // // //               placeholder="Document diagnosis, symptoms, and medical advice here..."
// // // // // // // // //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30 font-medium"
// // // // // // // // //             />
            
// // // // // // // // //             <div className="p-4 bg-accent/5 flex items-center justify-center text-[10px] text-muted-foreground gap-2 font-bold uppercase tracking-tight">
// // // // // // // // //                <ClipboardCheck size={12} className="text-success" /> 
// // // // // // // // //                Cloud Sync: ID-{consultation?.id.substring(0,8)}
// // // // // // // // //             </div>
// // // // // // // // //           </div>

// // // // // // // // //         </div>
// // // // // // // // //       </div>
// // // // // // // // //     </DashboardLayout>
// // // // // // // // //   );
// // // // // // // // // };

// // // // // // // // // export default DoctorConsultationRoom;









// // // // // // // // import { useState, useEffect } from "react"; 
// // // // // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // // // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // // import api from "@/lib/api";
// // // // // // // // import { toast } from "sonner";

// // // // // // // // const DoctorConsultationRoom = () => {
// // // // // // // //   const { bookingId } = useParams(); // Retrieves UUID from /doctor/consultation/:bookingId
// // // // // // // //   const navigate = useNavigate();
  
// // // // // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // // // // //   const [loading, setLoading] = useState(true);
// // // // // // // //   const [notes, setNotes] = useState("");
// // // // // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // // // // //   // 1. SESSION HANDSHAKE: Hits @PostMapping("/start/{bookingId}")
// // // // // // // //   useEffect(() => {
// // // // // // // //     const initSession = async () => {
// // // // // // // //       if (!bookingId) {
// // // // // // // //         toast.error("Invalid booking reference.");
// // // // // // // //         navigate("/doctor/appointments");
// // // // // // // //         return;
// // // // // // // //       }

// // // // // // // //       try {
// // // // // // // //         setLoading(true);
// // // // // // // //         // This initializes the session. If Dr. Elena or Kartik refreshes, 
// // // // // // // //         // the backend now returns the EXISTING record.
// // // // // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // // // // //         setConsultation(res.data);
        
// // // // // // // //         // DEBUG: Ensure room name sync
// // // // // // // //         console.log("JOINING SHARED JITSI ROOM:", `Medibot-Room-${bookingId}`);
// // // // // // // //       } catch (err) {
// // // // // // // //         console.error("Clinical Handshake Failed:", err);
// // // // // // // //         toast.error("Could not secure the clinical room. Verify appointment status.");
// // // // // // // //         navigate("/doctor/appointments");
// // // // // // // //       } finally {
// // // // // // // //         setLoading(false);
// // // // // // // //       }
// // // // // // // //     };
// // // // // // // //     initSession();
// // // // // // // //   }, [bookingId, navigate]);

// // // // // // // //   // 2. WRAP-UP: Hits @PatchMapping("/end/{id}") to finalize clinical records
// // // // // // // //   const handleEndCall = async () => {
// // // // // // // //     if (!consultation?.id) return;
    
// // // // // // // //     try {
// // // // // // // //       setIsEnding(true);
// // // // // // // //       // Finalizes session and saves the notes to the Patient's timeline
// // // // // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
      
// // // // // // // //       toast.success("Consultation complete. Notes archived successfully.");
// // // // // // // //       navigate("/doctor/appointments"); 
// // // // // // // //     } catch (err) {
// // // // // // // //       toast.error("Sync failed. Copy your notes before exiting.");
// // // // // // // //     } finally {
// // // // // // // //       setIsEnding(false);
// // // // // // // //     }
// // // // // // // //   };

// // // // // // // //   if (loading) return (
// // // // // // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // // // // // //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// // // // // // // //       <p className="text-muted-foreground animate-pulse font-medium">Synchronizing medical session...</p>
// // // // // // // //     </div>
// // // // // // // //   );

// // // // // // // //   return (
// // // // // // // //     <DashboardLayout role="doctor">
// // // // // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // // // // // //         {/* Physician's Control Bar */}
// // // // // // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// // // // // // // //           <div>
// // // // // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2">
// // // // // // // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // // // // // // //               Live Consultation: {consultation?.booking?.patient?.firstName} {consultation?.booking?.patient?.lastName}
// // // // // // // //             </h1>
// // // // // // // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
// // // // // // // //               <ShieldCheck size={10} className="text-success" /> Encrypted Physician-Patient Tunnel
// // // // // // // //             </p>
// // // // // // // //           </div>
          
// // // // // // // //           <button 
// // // // // // // //             onClick={handleEndCall} 
// // // // // // // //             disabled={isEnding}
// // // // // // // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // // // // // // //           >
// // // // // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // // // // //             Finish & Save Record
// // // // // // // //           </button>
// // // // // // // //         </div>

// // // // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // // // // // // //           {/* WEBRTC VIEWPORT (JITSI INTEGRATION) */}
// // // // // // // //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
// // // // // // // //             <JitsiMeeting
// // // // // // // //               domain="meet.jit.si"
// // // // // // // //               // MUST MATCH PATIENT EXACTLY
// // // // // // // //               roomName={`Medibot-Room-${bookingId}`} 
// // // // // // // //               configOverwrite={{ 
// // // // // // // //                 startWithAudioMuted: false, 
// // // // // // // //                 prejoinPageEnabled: false, // Bypasses name entry for speed
// // // // // // // //                 enableWelcomePage: false,
// // // // // // // //                 disableDeepLinking: true // Keeps session within your app
// // // // // // // //               }}
// // // // // // // //               getIFrameRef={(iframeRef) => { 
// // // // // // // //                 iframeRef.style.height = '100%'; 
// // // // // // // //                 iframeRef.style.width = '100%'; 
// // // // // // // //               }}
// // // // // // // //             />
// // // // // // // //           </div>

// // // // // // // //           {/* CLINICAL FINDINGS (Notes Sidebar) */}
// // // // // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // // // // // // //             <div className="p-5 border-b border-white/5 bg-white/5">
// // // // // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // // // // //                 <FileText size={16} /> Physician's Findings
// // // // // // // //               </h3>
// // // // // // // //               <p className="text-[9px] text-muted-foreground mt-1 uppercase font-bold tracking-tight">Auto-Syncing to Medical Vault</p>
// // // // // // // //             </div>
            
// // // // // // // //             <textarea 
// // // // // // // //               value={notes} 
// // // // // // // //               onChange={(e) => setNotes(e.target.value)}
// // // // // // // //               placeholder="Document diagnosis, vitals, and medical advice. These will be added to the patient's permanent medical record..."
// // // // // // // //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30 font-medium"
// // // // // // // //             />
            
// // // // // // // //             <div className="p-4 bg-black/20 border-t border-white/5">
// // // // // // // //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// // // // // // // //                   <ClipboardCheck size={14} className="text-success" /> 
// // // // // // // //                   <span>Verified Session ID: {consultation?.id.substring(0,8)}</span>
// // // // // // // //                </div>
// // // // // // // //             </div>
// // // // // // // //           </div>

// // // // // // // //         </div>
// // // // // // // //       </div>
// // // // // // // //     </DashboardLayout>
// // // // // // // //   );
// // // // // // // // };

// // // // // // // // export default DoctorConsultationRoom;





// // // // // // // import { useState, useEffect } from "react"; 
// // // // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // // import api from "@/lib/api";
// // // // // // // import { toast } from "sonner";

// // // // // // // const DoctorConsultationRoom = () => {
// // // // // // //   // Retrieves the specific appointment UUID from the URL
// // // // // // //   const { bookingId } = useParams(); 
// // // // // // //   const navigate = useNavigate();
  
// // // // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // // // //   const [loading, setLoading] = useState(true);
// // // // // // //   const [notes, setNotes] = useState("");
// // // // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // // // //   // 1. SESSION HANDSHAKE: Hits @PostMapping("/start/{bookingId}")
// // // // // // //   useEffect(() => {
// // // // // // //     const initSession = async () => {
// // // // // // //       if (!bookingId) {
// // // // // // //         toast.error("Invalid booking reference.");
// // // // // // //         navigate("/doctor/appointments");
// // // // // // //         return;
// // // // // // //       }

// // // // // // //       try {
// // // // // // //         setLoading(true);
// // // // // // //         // This initializes the session. Thanks to our backend update, 
// // // // // // //         // this is now idempotent and won't throw 500 errors on refresh.
// // // // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // // // //         setConsultation(res.data);
        
// // // // // // //         // DEBUG: Verify room name matches the patient side
// // // // // // //         console.log("JOINING SHARED JITSI ROOM:", `Medibot-Room-${bookingId}`);
// // // // // // //       } catch (err) {
// // // // // // //         console.error("Clinical Handshake Failed:", err);
// // // // // // //         toast.error("Could not secure the clinical room. Verify appointment status.");
// // // // // // //         navigate("/doctor/appointments");
// // // // // // //       } finally {
// // // // // // //         setLoading(false);
// // // // // // //       }
// // // // // // //     };
// // // // // // //     initSession();
// // // // // // //   }, [bookingId, navigate]);

// // // // // // //   // 2. SESSION WRAP-UP: Hits @PatchMapping("/end/{id}")
// // // // // // //   const handleEndCall = async () => {
// // // // // // //     if (!consultation?.id) return;
    
// // // // // // //     try {
// // // // // // //       setIsEnding(true);
// // // // // // //       // Finalizes session and saves the notes to the Patient's medical timeline
// // // // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
      
// // // // // // //       toast.success("Consultation complete. Notes archived in patient history.");
// // // // // // //       navigate("/doctor/appointments"); 
// // // // // // //     } catch (err) {
// // // // // // //       toast.error("Cloud sync failed. Please copy your notes before exiting.");
// // // // // // //     } finally {
// // // // // // //       setIsEnding(false);
// // // // // // //     }
// // // // // // //   };

// // // // // // //   if (loading) return (
// // // // // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // // // // //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// // // // // // //       <p className="text-muted-foreground animate-pulse font-medium">Synchronizing medical session...</p>
// // // // // // //     </div>
// // // // // // //   );

// // // // // // //   return (
// // // // // // //     <DashboardLayout role="doctor">
// // // // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // // // // //         {/* Physician's Control Header */}
// // // // // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// // // // // // //           <div>
// // // // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2">
// // // // // // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // // // // // //               {/* DYNAMIC: Shows actual patient name from the booking data */}
// // // // // // //               Live Consultation: {consultation?.booking?.patient?.firstName} {consultation?.booking?.patient?.lastName}
// // // // // // //             </h1>
// // // // // // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
// // // // // // //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT VIDEO TUNNEL
// // // // // // //             </p>
// // // // // // //           </div>
          
// // // // // // //           <button 
// // // // // // //             onClick={handleEndCall} 
// // // // // // //             disabled={isEnding}
// // // // // // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // // // // // //           >
// // // // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // // // //             Finish & Save Record
// // // // // // //           </button>
// // // // // // //         </div>

// // // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // // // // // //           {/* WEBRTC VIEWPORT (JITSI INTEGRATION) */}
// // // // // // //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
// // // // // // //             <JitsiMeeting
// // // // // // //               domain="meet.jit.si"
// // // // // // //               // CRITICAL: roomName prefix must match patient side exactly!
// // // // // // //               roomName={`Medibot-Room-${bookingId}`} 
// // // // // // //               configOverwrite={{ 
// // // // // // //                 startWithAudioMuted: false, 
// // // // // // //                 prejoinPageEnabled: false, // Skips Jitsi moderator entry
// // // // // // //                 enableWelcomePage: false,
// // // // // // //                 disableDeepLinking: true 
// // // // // // //               }}
// // // // // // //               interfaceConfigOverwrite={{
// // // // // // //                 SHOW_JITSI_WATERMARK: false,
// // // // // // //                 TOOLBAR_BUTTONS: ['microphone', 'camera', 'desktop', 'chat', 'raisehand', 'tileview'],
// // // // // // //               }}
// // // // // // //               getIFrameRef={(iframeRef) => { 
// // // // // // //                 iframeRef.style.height = '100%'; 
// // // // // // //                 iframeRef.style.width = '100%'; 
// // // // // // //               }}
// // // // // // //             />
// // // // // // //           </div>

// // // // // // //           {/* PHYSICIAN'S WORKSPACE (Clinical Notes) */}
// // // // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // // // // // //             <div className="p-5 border-b border-white/5 bg-white/5">
// // // // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // // // //                 <FileText size={16} /> Clinical Findings
// // // // // // //               </h3>
// // // // // // //               <p className="text-[9px] text-muted-foreground mt-1 uppercase font-bold tracking-tight">Writing to Patient Vault</p>
// // // // // // //             </div>
            
// // // // // // //             <textarea 
// // // // // // //               value={notes} 
// // // // // // //               onChange={(e) => setNotes(e.target.value)}
// // // // // // //               placeholder="Document diagnosis, symptoms, and medical advice here. These will be added to the patient's permanent record..."
// // // // // // //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30 font-medium"
// // // // // // //             />
            
// // // // // // //             <div className="p-4 bg-black/20 border-t border-white/5">
// // // // // // //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// // // // // // //                   <ClipboardCheck size={14} className="text-success" /> 
// // // // // // //                   <span>Synced Medical ID: {consultation?.id.substring(0,8)}</span>
// // // // // // //                </div>
// // // // // // //             </div>
// // // // // // //           </div>

// // // // // // //         </div>
// // // // // // //       </div>
// // // // // // //     </DashboardLayout>
// // // // // // //   );
// // // // // // // };

// // // // // // // export default DoctorConsultationRoom;





// // // // // // import { useState, useEffect } from "react"; 
// // // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // import api from "@/lib/api";
// // // // // // import { toast } from "sonner";

// // // // // // const DoctorConsultationRoom = () => {
// // // // // //   // Retrieves the specific appointment UUID from the URL path
// // // // // //   const { bookingId } = useParams(); 
// // // // // //   const navigate = useNavigate();
  
// // // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // // //   const [loading, setLoading] = useState(true);
// // // // // //   const [notes, setNotes] = useState("");
// // // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // // //   // 1. SESSION HANDSHAKE: Hits @PostMapping("/start/{bookingId}")
// // // // // //   // This logic is now idempotent on your backend to prevent 500 errors.
// // // // // //   useEffect(() => {
// // // // // //     const initSession = async () => {
// // // // // //       if (!bookingId) {
// // // // // //         toast.error("Invalid booking reference.");
// // // // // //         navigate("/doctor/appointments");
// // // // // //         return;
// // // // // //       }

// // // // // //       try {
// // // // // //         setLoading(true);
// // // // // //         // We call the start endpoint. If Dr. Elena or Kartik refreshes, 
// // // // // //         // the backend now safely returns the EXISTING record.
// // // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // // //         setConsultation(res.data);
        
// // // // // //         // DEBUG: Verify synchronization string in console
// // // // // //         console.log("JOINING SHARED JITSI ROOM:", `Medibot-Room-${bookingId}`);
// // // // // //       } catch (err) {
// // // // // //         console.error("Clinical Handshake Failed:", err);
// // // // // //         toast.error("Could not secure the clinical room. Verify appointment status.");
// // // // // //         navigate("/doctor/appointments");
// // // // // //       } finally {
// // // // // //         setLoading(false);
// // // // // //       }
// // // // // //     };
// // // // // //     initSession();
// // // // // //   }, [bookingId, navigate]);

// // // // // //   // 2. SESSION WRAP-UP: Hits @PatchMapping("/end/{id}")
// // // // // //   const handleEndCall = async () => {
// // // // // //     if (!consultation?.id) return;
    
// // // // // //     try {
// // // // // //       setIsEnding(true);
// // // // // //       // Finalizes session and saves the notes to the Patient's medical history
// // // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
      
// // // // // //       toast.success("Consultation complete. Notes archived in patient record.");
// // // // // //       navigate("/doctor/appointments"); 
// // // // // //     } catch (err) {
// // // // // //       toast.error("Cloud sync failed. Please copy your notes before exiting.");
// // // // // //     } finally {
// // // // // //       setIsEnding(false);
// // // // // //     }
// // // // // //   };

// // // // // //   if (loading) return (
// // // // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // // // //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// // // // // //       <p className="text-muted-foreground animate-pulse font-medium">Synchronizing medical session...</p>
// // // // // //     </div>
// // // // // //   );

// // // // // //   return (
// // // // // //     <DashboardLayout role="doctor">
// // // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // // // //         {/* Physician's Session Header */}
// // // // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// // // // // //           <div>
// // // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2 text-foreground">
// // // // // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // // // // //               {/* DYNAMIC: Traverses nested Consultation -> Booking -> Patient to show Kartik's real name */}
// // // // // //               Live Consultation: {consultation?.booking?.patient?.firstName} {consultation?.booking?.patient?.lastName}
// // // // // //             </h1>
// // // // // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
// // // // // //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT VIDEO TUNNEL
// // // // // //             </p>
// // // // // //           </div>
          
// // // // // //           <button 
// // // // // //             onClick={handleEndCall} 
// // // // // //             disabled={isEnding}
// // // // // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // // // // //           >
// // // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // // //             Finish & Save Record
// // // // // //           </button>
// // // // // //         </div>

// // // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // // // // //           {/* WEBRTC VIEWPORT (JITSI INTEGRATION) */}
// // // // // //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
// // // // // //             <JitsiMeeting
// // // // // //               domain="meet.jit.si"
// // // // // //               // CRITICAL: This roomName must be identical on both doctor and patient sides
// // // // // //               roomName={`Medibot-Room-${bookingId}`} 
// // // // // //               configOverwrite={{ 
// // // // // //                 startWithAudioMuted: false, 
// // // // // //                 prejoinPageEnabled: false, // Skips the name/login entry screen
// // // // // //                 enableWelcomePage: false,
// // // // // //                 disableDeepLinking: true 
// // // // // //               }}
// // // // // //               interfaceConfigOverwrite={{
// // // // // //                 SHOW_JITSI_WATERMARK: false,
// // // // // //                 TOOLBAR_BUTTONS: ['microphone', 'camera', 'desktop', 'chat', 'raisehand', 'tileview'],
// // // // // //               }}
// // // // // //               getIFrameRef={(iframeRef) => { 
// // // // // //                 iframeRef.style.height = '100%'; 
// // // // // //                 iframeRef.style.width = '100%'; 
// // // // // //               }}
// // // // // //             />
// // // // // //           </div>

// // // // // //           {/* PHYSICIAN'S WORKSPACE (Clinical Notes) */}
// // // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // // // // //             <div className="p-5 border-b border-white/5 bg-white/5">
// // // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // // //                 <FileText size={16} /> Clinical Findings
// // // // // //               </h3>
// // // // // //               <p className="text-[9px] text-muted-foreground mt-1 uppercase font-bold tracking-tight">Syncing to Patient Vault</p>
// // // // // //             </div>
            
// // // // // //             <textarea 
// // // // // //               value={notes} 
// // // // // //               onChange={(e) => setNotes(e.target.value)}
// // // // // //               placeholder="Document diagnosis, symptoms, and medical advice here..."
// // // // // //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30 font-medium"
// // // // // //             />
            
// // // // // //             <div className="p-4 bg-black/20 border-t border-white/5">
// // // // // //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// // // // // //                   <ClipboardCheck size={14} className="text-success" /> 
// // // // // //                   <span>Active Session ID: {consultation?.id.substring(0,8)}</span>
// // // // // //                </div>
// // // // // //             </div>
// // // // // //           </div>

// // // // // //         </div>
// // // // // //       </div>
// // // // // //     </DashboardLayout>
// // // // // //   );
// // // // // // };

// // // // // // export default DoctorConsultationRoom;


// // // // // import { useState, useEffect } from "react"; 
// // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // import api from "@/lib/api";
// // // // // import { toast } from "sonner";

// // // // // const DoctorConsultationRoom = () => {
// // // // //   // 1. Extract the bookingId from the URL (e.g., /doctor/consultation/700daee0...)
// // // // //   const { bookingId } = useParams(); 
// // // // //   const navigate = useNavigate();
  
// // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // //   const [loading, setLoading] = useState(true);
// // // // //   const [notes, setNotes] = useState("");
// // // // //   const [isEnding, setIsEnding] = useState(false);

// // // // //   // 2. SESSION HANDSHAKE: Hits @PostMapping("/start/{bookingId}")
// // // // //   useEffect(() => {
// // // // //     const initSession = async () => {
// // // // //       if (!bookingId) {
// // // // //         toast.error("Invalid booking reference.");
// // // // //         navigate("/doctor/appointments");
// // // // //         return;
// // // // //       }

// // // // //       try {
// // // // //         setLoading(true);
// // // // //         // This initializes the session. 
// // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // //         setConsultation(res.data);
// // // // //         console.log("CLINICAL_SYNC_SUCCESS: Joined shared session", res.data.id);
// // // // //       } catch (err: any) {
// // // // //         // SAFETY FALLBACK: If backend returns 500 (Duplicate Key), it means the session 
// // // // //         // is already active. We can proceed using the bookingId from the URL.
// // // // //         if (err.response?.status === 500) {
// // // // //           console.warn("CLINICAL_SYNC_WARNING: Session already exists. Proceeding with URL ID.");
// // // // //           setLoading(false);
// // // // //         } else {
// // // // //           console.error("Clinical Handshake Failed:", err);
// // // // //           toast.error("Could not verify the clinical room status.");
// // // // //           navigate("/doctor/appointments");
// // // // //         }
// // // // //       } finally {
// // // // //         setLoading(false);
// // // // //       }
// // // // //     };
// // // // //     initSession();
// // // // //   }, [bookingId, navigate]);

// // // // //   // 3. SESSION WRAP-UP: Hits @PatchMapping("/end/{id}")
// // // // //   const handleEndCall = async () => {
// // // // //     // Uses either the returned consultation ID or the bookingId as a fallback
// // // // //     const idToClose = consultation?.id || bookingId;
// // // // //     if (!idToClose) return;
    
// // // // //     try {
// // // // //       setIsEnding(true);
// // // // //       await api.patch(`/consultations/end/${idToClose}`, notes);
// // // // //       toast.success("Consultation complete. Notes archived.");
// // // // //       navigate("/doctor/appointments"); 
// // // // //     } catch (err) {
// // // // //       toast.error("Cloud sync failed. Save your notes manually before leaving.");
// // // // //     } finally {
// // // // //       setIsEnding(false);
// // // // //     }
// // // // //   };

// // // // //   if (loading) return (
// // // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // // //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// // // // //       <p className="text-muted-foreground animate-pulse font-medium">Connecting to secure medical tunnel...</p>
// // // // //     </div>
// // // // //   );

// // // // //   return (
// // // // //     <DashboardLayout role="doctor">
// // // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // // //         {/* Physician's Control Header */}
// // // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// // // // //           <div>
// // // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2 text-foreground">
// // // // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // // // //               Live Consultation: {consultation?.booking?.patient?.firstName || "Verified Patient"}
// // // // //             </h1>
// // // // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
// // // // //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT VIDEO TUNNEL
// // // // //             </p>
// // // // //           </div>
          
// // // // //           <button 
// // // // //             onClick={handleEndCall} 
// // // // //             disabled={isEnding}
// // // // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // // // //           >
// // // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // // //             Finish & Save Record
// // // // //           </button>
// // // // //         </div>

// // // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // // // //           {/* WEBRTC VIEWPORT (JITSI INTEGRATION) */}
// // // // //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
// // // // //             <JitsiMeeting
// // // // //               domain="meet.jit.si"
// // // // //               // CRITICAL SYNC: Both doctor and patient MUST use this exact roomName string
// // // // //               roomName={`Medibot-Room-${bookingId}`} 
// // // // //               configOverwrite={{ 
// // // // //                 startWithAudioMuted: false, 
// // // // //                 prejoinPageEnabled: false, 
// // // // //                 enableWelcomePage: false,
// // // // //                 disableDeepLinking: true 
// // // // //               }}
// // // // //               interfaceConfigOverwrite={{
// // // // //                 SHOW_JITSI_WATERMARK: false,
// // // // //                 TOOLBAR_BUTTONS: ['microphone', 'camera', 'desktop', 'chat', 'raisehand', 'tileview'],
// // // // //               }}
// // // // //               getIFrameRef={(iframeRef) => { 
// // // // //                 iframeRef.style.height = '100%'; 
// // // // //                 iframeRef.style.width = '100%'; 
// // // // //               }}
// // // // //             />
// // // // //           </div>

// // // // //           {/* PHYSICIAN'S WORKSPACE */}
// // // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // // // //             <div className="p-5 border-b border-white/5 bg-white/5">
// // // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // // // //                 <FileText size={16} /> Physician's Notes
// // // // //               </h3>
// // // // //             </div>
            
// // // // //             <textarea 
// // // // //               value={notes} 
// // // // //               onChange={(e) => setNotes(e.target.value)}
// // // // //               placeholder="Document diagnosis and medical advice here..."
// // // // //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30 font-medium"
// // // // //             />
            
// // // // //             <div className="p-4 bg-black/20 border-t border-white/5">
// // // // //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// // // // //                   <ClipboardCheck size={14} className="text-success" /> 
// // // // //                   <span>Verified Session ID: {String(bookingId).substring(0,8)}</span>
// // // // //                </div>
// // // // //             </div>
// // // // //           </div>

// // // // //         </div>
// // // // //       </div>
// // // // //     </DashboardLayout>
// // // // //   );
// // // // // };

// // // // // export default DoctorConsultationRoom;









// // // // import { useState, useEffect } from "react"; 
// // // // import { useParams, useNavigate } from "react-router-dom";
// // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // import api from "@/lib/api";
// // // // import { toast } from "sonner";

// // // // const DoctorConsultationRoom = () => {
// // // //   // 1. Get the UUID from the URL path
// // // //   const { bookingId } = useParams(); 
// // // //   const navigate = useNavigate();
  
// // // //   const [consultation, setConsultation] = useState<any>(null);
// // // //   const [loading, setLoading] = useState(true);
// // // //   const [notes, setNotes] = useState("");
// // // //   const [isEnding, setIsEnding] = useState(false);

// // // //   // 2. SESSION HANDSHAKE: Hits @PostMapping("/start/{bookingId}")
// // // //   useEffect(() => {
// // // //     const initSession = async () => {
// // // //       if (!bookingId) {
// // // //         toast.error("Invalid booking reference.");
// // // //         navigate("/doctor/appointments");
// // // //         return;
// // // //       }

// // // //       try {
// // // //         setLoading(true);
// // // //         // Handshake with backend
// // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // //         setConsultation(res.data);
// // // //         console.log("CLINICAL_SYNC: Established session", res.data.id);
// // // //       } catch (err: any) {
// // // //         // ERROR BYPASS: If 500 occurs, the session already exists. 
// // // //         // We continue so the Jitsi frame loads anyway using the URL ID.
// // // //         if (err.response?.status === 500) {
// // // //           console.warn("SYNC_WARNING: Session active. Joining via URL context.");
// // // //           setLoading(false);
// // // //         } else {
// // // //           toast.error("Handshake failed. Check connection.");
// // // //           navigate("/doctor/appointments");
// // // //         }
// // // //       } finally {
// // // //         setLoading(false);
// // // //       }
// // // //     };
// // // //     initSession();
// // // //   }, [bookingId, navigate]);

// // // //   // 3. WRAP-UP: Hits @PatchMapping("/end/{id}")
// // // //   const handleEndCall = async () => {
// // // //     const activeId = consultation?.id || bookingId;
// // // //     if (!activeId) return;
    
// // // //     try {
// // // //       setIsEnding(true);
// // // //       await api.patch(`/consultations/end/${activeId}`, notes);
// // // //       toast.success("Consultation complete. Record saved.");
// // // //       navigate("/doctor/appointments"); 
// // // //     } catch (err) {
// // // //       toast.error("Save failed. Copy notes before leaving.");
// // // //     } finally {
// // // //       setIsEnding(false);
// // // //     }
// // // //   };

// // // //   if (loading) return (
// // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// // // //       <p className="text-muted-foreground animate-pulse font-medium">Securing clinical room...</p>
// // // //     </div>
// // // //   );

// // // //   return (
// // // //     <DashboardLayout role="doctor">
// // // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // // //         {/* Header Bar */}
// // // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// // // //           <div>
// // // //             <h1 className="font-display text-xl font-bold flex items-center gap-2">
// // // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // // //               Live Consultation: {consultation?.booking?.patient?.firstName || "Kartik"}
// // // //             </h1>
// // // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
// // // //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT TUNNEL
// // // //             </p>
// // // //           </div>
          
// // // //           <button onClick={handleEndCall} disabled={isEnding} className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold transition-all active:scale-95 disabled:opacity-50">
// // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // //             Finish & Save Record
// // // //           </button>
// // // //         </div>

// // // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // // //           {/* Jitsi Meeting Viewport */}
// // // //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
// // // //             <JitsiMeeting
// // // //               domain="meet.jit.si"
// // // //               roomName={`Medibot-Room-${bookingId}`} // Standardized sync ID
// // // //               configOverwrite={{ 
// // // //                 // CRITICAL FOR SINGLE PC TESTING: Release hardware locks
// // // //                 startWithAudioMuted: true, 
// // // //                 startWithVideoMuted: true,
// // // //                 prejoinPageEnabled: false,
// // // //                 disableDeepLinking: true 
// // // //               }}
// // // //               getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; iframeRef.style.width = '100%'; }}
// // // //             />
// // // //           </div>

// // // //           {/* Clinical Workspace */}
// // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // // //             <div className="p-5 border-b border-white/5">
// // // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent"><FileText size={16} /> Clinical Notes</h3>
// // // //             </div>
// // // //             <textarea value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Document diagnosis here..." className="flex-1 p-5 bg-transparent border-none outline-none text-sm text-foreground/80 font-medium resize-none" />
// // // //             <div className="p-4 bg-black/20 border-t border-white/5">
// // // //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// // // //                   <ClipboardCheck size={14} className="text-success" /> 
// // // //                   <span>Synced Medical ID: {String(bookingId).substring(0,8)}</span>
// // // //                </div>
// // // //             </div>
// // // //           </div>

// // // //         </div>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );
// // // // };

// // // // export default DoctorConsultationRoom;









// // // import { useState, useEffect } from "react"; 
// // // import { useParams, useNavigate } from "react-router-dom";
// // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import api from "@/lib/api";
// // // import { toast } from "sonner";

// // // const DoctorConsultationRoom = () => {
// // //   const { bookingId } = useParams(); 
// // //   const navigate = useNavigate();
  
// // //   const [consultation, setConsultation] = useState<any>(null);
// // //   const [roomId, setRoomId] = useState<string>(""); // The authoritative room name
// // //   const [loading, setLoading] = useState(true);
// // //   const [notes, setNotes] = useState("");
// // //   const [isEnding, setIsEnding] = useState(false);

// // //   useEffect(() => {
// // //     const initSession = async () => {
// // //       if (!bookingId) {
// // //         toast.error("Invalid booking reference.");
// // //         navigate("/doctor/appointments");
// // //         return;
// // //       }

// // //       try {
// // //         setLoading(true);
        
// // //         // 1. Handshake: Start the session record
// // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // //         const consultationData = res.data;
// // //         setConsultation(consultationData);

// // //         // 2. Room Generation: Create a unique authoritative string
// // //         const generatedRoomName = `Medibot-Secure-Room-${bookingId}`;
        
// // //         // 3. Broadcast: Save this Room ID to the database and trigger patient notification
// // //         await api.patch(`/consultations/${consultationData.id}/room`, generatedRoomName);
        
// // //         // 4. Update Local State to load Jitsi
// // //         setRoomId(generatedRoomName);
// // //         console.log("CLINICAL_HANDSHAKE_COMPLETE: Room broadcasted to patient.");

// // //       } catch (err: any) {
// // //         // Fallback: If 500 error occurs (session exists), Kartik might have joined first.
// // //         if (err.response?.status === 500) {
// // //           console.warn("Session already active. Joining existing context.");
// // //           setRoomId(`Medibot-Secure-Room-${bookingId}`);
// // //         } else {
// // //           console.error("Clinical Handshake Failed:", err);
// // //           toast.error("Could not secure the clinical room.");
// // //           navigate("/doctor/appointments");
// // //         }
// // //       } finally {
// // //         setLoading(false);
// // //       }
// // //     };
// // //     initSession();
// // //   }, [bookingId, navigate]);

// // //   const handleEndCall = async () => {
// // //     if (!consultation?.id) return;
// // //     try {
// // //       setIsEnding(true);
// // //       // Hits @PatchMapping("/end/{id}") to save notes and release slot
// // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
// // //       toast.success("Consultation complete. Notes archived.");
// // //       navigate("/doctor/appointments"); 
// // //     } catch (err) {
// // //       toast.error("Cloud sync failed. Copy notes before leaving.");
// // //     } finally {
// // //       setIsEnding(false);
// // //     }
// // //   };

// // //   if (loading) return (
// // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// // //       <p className="text-muted-foreground animate-pulse font-medium">Initializing secure video tunnel...</p>
// // //     </div>
// // //   );

// // //   return (
// // //     <DashboardLayout role="doctor">
// // //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// // //         {/* Physician's Control Header */}
// // //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// // //           <div>
// // //             <h1 className="font-display text-xl font-bold flex items-center gap-2 text-foreground">
// // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // //               Patient: {consultation?.booking?.patient?.firstName || "Verified User"} {consultation?.booking?.patient?.lastName || ""}
// // //             </h1>
// // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
// // //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT VIDEO STREAM
// // //             </p>
// // //           </div>
          
// // //           <button 
// // //             onClick={handleEndCall} 
// // //             disabled={isEnding}
// // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold transition-all active:scale-95 disabled:opacity-50 shadow-lg shadow-destructive/20"
// // //           >
// // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // //             Finish & Save Notes
// // //           </button>
// // //         </div>

// // //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// // //           {/* WEBRTC VIEWPORT (JITSI INTEGRATION) */}
// // //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
// // //             {roomId && (
// // //               <JitsiMeeting
// // //                 domain="meet.jit.si"
// // //                 roomName={roomId} 
// // //                 configOverwrite={{ 
// // //                   startWithAudioMuted: true, // Prevents feedback loop on one PC
// // //                   startWithVideoMuted: true, // Releases camera for the other browser
// // //                   prejoinPageEnabled: false, 
// // //                   disableDeepLinking: true 
// // //                 }}
// // //                 interfaceConfigOverwrite={{
// // //                   SHOW_JITSI_WATERMARK: false,
// // //                   TOOLBAR_BUTTONS: ['microphone', 'camera', 'desktop', 'chat', 'raisehand', 'tileview'],
// // //                 }}
// // //                 getIFrameRef={(iframeRef) => { 
// // //                   iframeRef.style.height = '100%'; 
// // //                   iframeRef.style.width = '100%'; 
// // //                 }}
// // //               />
// // //             )}
// // //           </div>

// // //           {/* PHYSICIAN'S WORKSPACE (Clinical Notes) */}
// // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // //             <div className="p-5 border-b border-white/5 bg-white/5 flex items-center justify-between">
// // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // //                 <FileText size={16} /> Clinical Findings
// // //               </h3>
// // //             </div>
            
// // //             <textarea 
// // //               value={notes} 
// // //               onChange={(e) => setNotes(e.target.value)}
// // //               placeholder="Start documenting diagnosis, symptoms, and advice..."
// // //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30 font-medium"
// // //             />
            
// // //             <div className="p-4 bg-black/20 border-t border-white/5">
// // //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// // //                   <ClipboardCheck size={14} className="text-success" /> 
// // //                   <span>Active Session ID: {consultation?.id?.substring(0,8)}</span>
// // //                </div>
// // //             </div>
// // //           </div>

// // //         </div>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default DoctorConsultationRoom;


// // import { useState, useEffect } from "react"; 
// // import { useParams, useNavigate } from "react-router-dom";
// // import { JitsiMeeting } from "@jitsi/react-sdk";
// // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import api from "@/lib/api";
// // import { toast } from "sonner";

// // const DoctorConsultationRoom = () => {
// //   // 1. Extract the bookingId from the URL path
// //   const { bookingId } = useParams(); 
// //   const navigate = useNavigate();
  
// //   const [consultation, setConsultation] = useState<any>(null);
// //   const [roomId, setRoomId] = useState<string>(""); 
// //   const [loading, setLoading] = useState(true);
// //   const [notes, setNotes] = useState("");
// //   const [isEnding, setIsEnding] = useState(false);

// //   // 2. THE CLINICAL HANDSHAKE
// //   useEffect(() => {
// //     const initSession = async () => {
// //       if (!bookingId) {
// //         toast.error("Invalid booking reference.");
// //         navigate("/doctor/appointments");
// //         return;
// //       }

// //       try {
// //         setLoading(true);
        
// //         // STEP A: Create or retrieve the database record
// //         const res = await api.post(`/consultations/start/${bookingId}`);
// //         const consultationData = res.data;
// //         setConsultation(consultationData);

// //         // STEP B: Generate the authoritative Room Name
// //         const generatedRoomName = `Medibot-Secure-Room-${bookingId}`;
        
// //         // STEP C: Broadcast the ID to the backend (Fixes the 400 Bad Request)
// //         // We explicitly tell Axios to send this as a plain string
// //         await api.patch(`/consultations/${consultationData.id}/room`, generatedRoomName, {
// //           headers: { 'Content-Type': 'text/plain' } 
// //         });
        
// //         setRoomId(generatedRoomName);
// //         console.log("HANDSHAKE_SUCCESS: Clinical room identity broadcasted.");

// //       } catch (err: any) {
// //         // FALLBACK: If Elena already joined or session is active
// //         if (err.response?.status === 500 || err.response?.status === 400) {
// //           console.warn("SYNC_FALLBACK: Session context active. Loading room via URL context.");
// //           setRoomId(`Medibot-Secure-Room-${bookingId}`);
// //           setLoading(false);
// //         } else {
// //           console.error("Clinical Handshake Failed:", err);
// //           toast.error("Could not secure the clinical room.");
// //           navigate("/doctor/appointments");
// //         }
// //       } finally {
// //         setLoading(false);
// //       }
// //     };
// //     initSession();
// //   }, [bookingId, navigate]);

// //   // 3. THE CLINICAL WRAP-UP
// //   const handleEndCall = async () => {
// //     if (!consultation?.id && !bookingId) return;
// //     try {
// //       setIsEnding(true);
// //       // Sends the doctor's findings to be archived in Kartik's medical timeline
// //       const activeId = consultation?.id || bookingId;
// //       await api.patch(`/consultations/end/${activeId}`, notes);
      
// //       toast.success("Consultation complete. Notes archived successfully.");
// //       navigate("/doctor/appointments"); 
// //     } catch (err) {
// //       toast.error("Sync failed. Copy your notes manually before leaving.");
// //     } finally {
// //       setIsEnding(false);
// //     }
// //   };

// //   if (loading) return (
// //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// //       <Loader2 className="animate-spin text-accent mb-4" size={44} />
// //       <p className="text-muted-foreground animate-pulse font-medium text-sm">Securing clinical tunnel...</p>
// //     </div>
// //   );

// //   return (
// //     <DashboardLayout role="doctor">
// //       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
// //         {/* Physician's Session Control Bar */}
// //         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
// //           <div>
// //             <h1 className="font-display text-xl font-bold flex items-center gap-2 text-foreground">
// //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// //               Patient: {consultation?.booking?.patient?.firstName || "Verified"} {consultation?.booking?.patient?.lastName || "User"}
// //             </h1>
// //             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
// //               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT VIDEO STREAM
// //             </p>
// //           </div>
          
// //           <button 
// //             onClick={handleEndCall} 
// //             disabled={isEnding}
// //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold transition-all active:scale-95 disabled:opacity-50 shadow-lg shadow-destructive/20"
// //           >
// //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// //             Finish & Save Notes
// //           </button>
// //         </div>

// //         <div className="grid lg:grid-cols-[1fr_380px] gap-4 flex-1 min-h-0">
          
// //           {/* WEBRTC VIEWPORT (JITSI SDK INTEGRATION) */}
// //           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5 relative">
// //             {roomId ? (
// //               <JitsiMeeting
// //                 domain="meet.jit.si"
// //                 roomName={roomId} 
// //                 configOverwrite={{ 
// //                   startWithAudioMuted: true, // Prevents feedback loop on one PC
// //                   startWithVideoMuted: true, // Releases camera hardware lock
// //                   prejoinPageEnabled: false, 
// //                   disableDeepLinking: true 
// //                 }}
// //                 interfaceConfigOverwrite={{
// //                   SHOW_JITSI_WATERMARK: false,
// //                   TOOLBAR_BUTTONS: ['microphone', 'camera', 'desktop', 'chat', 'raisehand', 'tileview'],
// //                 }}
// //                 getIFrameRef={(iframeRef) => { 
// //                   iframeRef.style.height = '100%'; 
// //                   iframeRef.style.width = '100%'; 
// //                 }}
// //               />
// //             ) : (
// //               <div className="flex items-center justify-center h-full text-muted-foreground italic">
// //                 Initializing shared room...
// //               </div>
// //             )}
// //           </div>

// //           {/* PHYSICIAN'S WORKSPACE (Clinical Documentation) */}
// //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// //             <div className="p-5 border-b border-white/5 bg-white/5">
// //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent uppercase tracking-wider">
// //                 <FileText size={16} /> Physician's Findings
// //               </h3>
// //             </div>
            
// //             <textarea 
// //               value={notes} 
// //               onChange={(e) => setNotes(e.target.value)}
// //               placeholder="Document diagnosis, symptoms, and advice here..."
// //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30 font-medium"
// //             />
            
// //             <div className="p-4 bg-black/20 border-t border-white/5">
// //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// //                   <ClipboardCheck size={14} className="text-success" /> 
// //                   <span>Active Session ID: {consultation?.id?.substring(0,8) || bookingId?.substring(0,8)}</span>
// //                </div>
// //             </div>
// //           </div>

// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default DoctorConsultationRoom;





// import { useState, useEffect } from "react"; 
// import { useParams, useNavigate } from "react-router-dom";
// import { JitsiMeeting } from "@jitsi/react-sdk";
// import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck, Pill, Plus, Trash2, Save } from "lucide-react";
// import DashboardLayout from "@/components/DashboardLayout";
// import api from "@/lib/api";
// import { toast } from "sonner";
// import { motion, AnimatePresence } from "framer-motion";

// const DoctorConsultationRoom = () => {
//   const { bookingId } = useParams(); 
//   const navigate = useNavigate();
  
//   const [consultation, setConsultation] = useState<any>(null);
//   const [roomId, setRoomId] = useState<string>(""); 
//   const [loading, setLoading] = useState(true);
//   const [notes, setNotes] = useState("");
//   const [isEnding, setIsEnding] = useState(false);
  
//   // Tabs & Prescriptions State
//   const [activeTab, setActiveTab] = useState<"notes" | "prescriptions">("notes");
//   const [prescriptions, setPrescriptions] = useState([{
//     medicineName: '', dosage: '', frequency: '', duration: '', instructions: ''
//   }]);

//   // 1. HANDSHAKE: Authoritative Room ID Creation
//   useEffect(() => {
//     const initSession = async () => {
//       if (!bookingId) {
//         toast.error("Invalid booking reference.");
//         navigate("/doctor/appointments");
//         return;
//       }

//       try {
//         setLoading(true);
//         const res = await api.post(`/consultations/start/${bookingId}`);
//         const consultationData = res.data;
//         setConsultation(consultationData);

//         const generatedRoomName = `Medibot-Secure-Room-${bookingId}`;
        
//         // Broadcast the Room ID to sync with Patient side
//         await api.patch(`/consultations/${consultationData.id}/room`, generatedRoomName, {
//           headers: { 'Content-Type': 'text/plain' } 
//         });
        
//         setRoomId(generatedRoomName);
//         console.log("HANDSHAKE_SUCCESS: Room broadcasted.");

//       } catch (err: any) {
//         if (err.response?.status === 500 || err.response?.status === 400) {
//           setRoomId(`Medibot-Secure-Room-${bookingId}`);
//           setLoading(false);
//         } else {
//           toast.error("Handshake failed. Check connection.");
//           navigate("/doctor/appointments");
//         }
//       } finally {
//         setLoading(false);
//       }
//     };
//     initSession();
//   }, [bookingId, navigate]);

//   // 2. PRESCRIPTION LOGIC
//   const addMedication = () => {
//     setPrescriptions([...prescriptions, { medicineName: '', dosage: '', frequency: '', duration: '', instructions: '' }]);
//   };

//   const removeMedication = (index: number) => {
//     setPrescriptions(prescriptions.filter((_, i) => i !== index));
//   };

//   const handleSavePrescriptions = async () => {
//     if (!consultation?.id) return;
//     try {
//       await api.post(`/consultations/${consultation.id}/prescriptions`, prescriptions);
//       toast.success("Prescription synchronized with Patient Vault");
//     } catch (err) {
//       toast.error("Failed to save prescriptions.");
//     }
//   };

//   // 3. WRAP-UP
//   const handleEndCall = async () => {
//     const activeId = consultation?.id || bookingId;
//     if (!activeId) return;
//     try {
//       setIsEnding(true);
//       await api.patch(`/consultations/end/${activeId}`, notes);
//       toast.success("Consultation complete. Records archived.");
//       navigate("/doctor/appointments"); 
//     } catch (err) {
//       toast.error("Final sync failed. Save notes manually.");
//     } finally {
//       setIsEnding(false);
//     }
//   };

//   if (loading) return (
//     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
//       <Loader2 className="animate-spin text-accent mb-4" size={44} />
//       <p className="text-muted-foreground animate-pulse font-medium">Securing clinical room...</p>
//     </div>
//   );

//   return (
//     <DashboardLayout role="doctor">
//       <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
//         {/* Header Bar */}
//         <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
//           <div>
//             <h1 className="font-display text-xl font-bold flex items-center gap-2">
//               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
//               Patient: {consultation?.booking?.patient?.firstName || "Verified"} {consultation?.booking?.patient?.lastName || "User"}
//             </h1>
//             <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
//               <ShieldCheck size={10} className="text-success" /> HIPAA COMPLIANT VIDEO STREAM
//             </p>
//           </div>
          
//           <button onClick={handleEndCall} disabled={isEnding} className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50">
//             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
//             Finish & Save Notes
//           </button>
//         </div>

//         <div className="grid lg:grid-cols-[1fr_400px] gap-4 flex-1 min-h-0">
          
//           {/* Jitsi Meeting Viewport */}
//           <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5 relative">
//             {roomId && (
//               <JitsiMeeting
//                 domain="meet.jit.si"
//                 roomName={roomId} 
//                 configOverwrite={{ 
//                   startWithAudioMuted: true, startWithVideoMuted: true,
//                   prejoinPageEnabled: false, disableDeepLinking: true 
//                 }}
//                 getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; iframeRef.style.width = '100%'; }}
//               />
//             )}
//           </div>

//           {/* Clinical Workspace Sidebar */}
//           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
//             <div className="flex border-b border-white/10">
//               <button onClick={() => setActiveTab("notes")} className={`flex-1 py-4 text-xs font-bold uppercase tracking-widest flex items-center justify-center gap-2 transition-all ${activeTab === 'notes' ? 'text-accent bg-white/5' : 'text-muted-foreground opacity-50'}`}>
//                 <FileText size={14} /> Notes
//               </button>
//               <button onClick={() => setActiveTab("prescriptions")} className={`flex-1 py-4 text-xs font-bold uppercase tracking-widest flex items-center justify-center gap-2 transition-all ${activeTab === 'prescriptions' ? 'text-accent bg-white/5' : 'text-muted-foreground opacity-50'}`}>
//                 <Pill size={14} /> Prescriptions
//               </button>
//             </div>
            
//             <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
//               {activeTab === "notes" ? (
//                 <textarea 
//                   value={notes} 
//                   onChange={(e) => setNotes(e.target.value)}
//                   placeholder="Document diagnosis and advice..."
//                   className="w-full h-full bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 font-medium"
//                 />
//               ) : (
//                 <div className="space-y-4">
//                   {prescriptions.map((p, i) => (
//                     <motion.div initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} key={i} className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-3 relative group">
//                       <input 
//                         placeholder="Medicine Name" 
//                         value={p.medicineName}
//                         onChange={(e) => {
//                           const newP = [...prescriptions];
//                           newP[i].medicineName = e.target.value;
//                           setPrescriptions(newP);
//                         }}
//                         className="w-full bg-transparent border-b border-white/10 outline-none text-sm font-bold text-accent placeholder:text-muted-foreground/30 pb-1" 
//                       />
//                       <div className="grid grid-cols-2 gap-2">
//                         <input placeholder="Dosage (e.g. 500mg)" value={p.dosage} onChange={(e) => { const newP = [...prescriptions]; newP[i].dosage = e.target.value; setPrescriptions(newP); }} className="bg-transparent border-b border-white/10 outline-none text-[10px] text-foreground/70" />
//                         <input placeholder="Freq (e.g. 1-0-1)" value={p.frequency} onChange={(e) => { const newP = [...prescriptions]; newP[i].frequency = e.target.value; setPrescriptions(newP); }} className="bg-transparent border-b border-white/10 outline-none text-[10px] text-foreground/70" />
//                       </div>
//                       <button onClick={() => removeMedication(i)} className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-destructive/20 text-destructive flex items-center justify-center opacity-0 group-hover:opacity-100 transition-all"><Trash2 size={12}/></button>
//                     </motion.div>
//                   ))}
//                   <button onClick={addMedication} className="w-full py-3 rounded-xl border border-dashed border-white/20 text-muted-foreground hover:text-accent hover:border-accent/50 transition-all text-[10px] uppercase font-bold flex items-center justify-center gap-2">
//                     <Plus size={14} /> Add Medicine
//                   </button>
//                   <button onClick={handleSavePrescriptions} className="w-full py-3 rounded-xl bg-accent/20 text-accent font-bold text-xs flex items-center justify-center gap-2 hover:bg-accent/30 transition-all mt-4">
//                     <Save size={14} /> Sync Prescription
//                   </button>
//                 </div>
//               )}
//             </div>
            
//             <div className="p-4 bg-black/20 border-t border-white/5 text-[10px] text-muted-foreground font-bold uppercase flex items-center gap-2">
//               <ClipboardCheck size={14} className="text-success" /> Synced Medical ID: {consultation?.id?.substring(0,8)}
//             </div>
//           </div>

//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default DoctorConsultationRoom;



import { useState, useEffect } from "react"; 
import { useParams, useNavigate } from "react-router-dom";
import { JitsiMeeting } from "@jitsi/react-sdk";
import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck, Pill, Plus, Trash2, Save } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";

const DoctorConsultationRoom = () => {
  const { bookingId } = useParams(); 
  const navigate = useNavigate();
  
  const [consultation, setConsultation] = useState<any>(null);
  const [roomId, setRoomId] = useState<string>(""); 
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState("");
  const [isEnding, setIsEnding] = useState(false);
  
  const [activeTab, setActiveTab] = useState<"notes" | "prescriptions">("notes");
  const [prescriptions, setPrescriptions] = useState([{
    medicineName: '', dosage: '', frequency: '', duration: '', instructions: ''
  }]);

  // 1. HANDSHAKE: Authoritative Room ID Creation
  useEffect(() => {
    const initSession = async () => {
      if (!bookingId) {
        toast.error("No clinical context found. Returning to queue.");
        navigate("/doctor/dashboard");
        return;
      }

      try {
        setLoading(true);
        // Start the session context
        const res = await api.post(`/consultations/start/${bookingId}`);
        const consultationData = res.data;
        setConsultation(consultationData);

        const generatedRoomName = `Medibot-Secure-Room-${bookingId}`;
        
        // Broadcast the Room ID to the database so Kartik can find you
        await api.patch(`/consultations/${consultationData.id}/room`, generatedRoomName, {
          headers: { 'Content-Type': 'text/plain' } 
        });
        
        setRoomId(generatedRoomName);
      } catch (err: any) {
        // Fallback for page refreshes
        if (err.response?.status === 500 || err.response?.status === 400) {
          setRoomId(`Medibot-Secure-Room-${bookingId}`);
        } else {
          toast.error("Clinical handshake failed.");
          navigate("/doctor/dashboard");
        }
      } finally {
        setLoading(false);
      }
    };
    initSession();
  }, [bookingId, navigate]);

  // 2. PRESCRIPTION HANDLER
  const handleSavePrescriptions = async () => {
    if (!consultation?.id) return;
    try {
      // POST the array of medicines to the new endpoint
      await api.post(`/consultations/${consultation.id}/prescriptions`, prescriptions);
      toast.success("Prescriptions synced to Patient Vault");
    } catch (err) {
      toast.error("Failed to sync prescriptions.");
    }
  };

  // 3. WRAP-UP HANDLER (FIXED: Payload matches ConsultationEndRequest DTO)
  const handleEndCall = async () => {
    const activeId = consultation?.id || bookingId;
    if (!activeId) return;

    try {
      setIsEnding(true);
      // FIX: Wrap 'notes' in an object to match the backend @RequestBody DTO 
      await api.patch(`/consultations/end/${activeId}`, { notes: notes }); 
      
      toast.success("Consultation finalized and archived.");
      navigate("/doctor/dashboard"); 
    } catch (err) {
      console.error("End call error:", err);
      toast.error("Sync failed. Copy your notes manually before leaving.");
    } finally {
      setIsEnding(false);
    }
  };

  if (loading) return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background">
      <Loader2 className="animate-spin text-accent mb-4" size={44} />
      <p className="text-muted-foreground animate-pulse font-medium">Securing clinical tunnel...</p>
    </div>
  );

  return (
    <DashboardLayout role="doctor">
      <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
        {/* Physician Header */}
        <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
          <div>
            <h1 className="font-display text-xl font-bold flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
              Patient: {consultation?.booking?.patientName || "Verified User"}
            </h1>
            <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
              <ShieldCheck size={10} className="text-success" /> HIPAA SECURE CHANNEL
            </p>
          </div>
          
          <button 
            onClick={handleEndCall} 
            disabled={isEnding} 
            className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold transition-all active:scale-95 disabled:opacity-50 shadow-lg"
          >
            {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
            Finish & Save
          </button>
        </div>

        <div className="grid lg:grid-cols-[1fr_400px] gap-4 flex-1 min-h-0">
          
          {/* JITSI VIEWPORT */}
          <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5 relative">
            {roomId && (
              <JitsiMeeting
                domain="meet.jit.si"
                roomName={roomId} 
                configOverwrite={{ 
                  startWithAudioMuted: true, startWithVideoMuted: true,
                  prejoinPageEnabled: false, disableDeepLinking: true 
                }}
                getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; iframeRef.style.width = '100%'; }}
              />
            )}
          </div>

          {/* Clinical Workspace Sidebar */}
          <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
            <div className="flex border-b border-white/10">
              <button onClick={() => setActiveTab("notes")} className={`flex-1 py-4 text-xs font-bold uppercase flex items-center justify-center gap-2 transition-all ${activeTab === 'notes' ? 'text-accent bg-white/5 border-b-2 border-accent' : 'text-muted-foreground opacity-50'}`}>
                <FileText size={14} /> Notes
              </button>
              <button onClick={() => setActiveTab("prescriptions")} className={`flex-1 py-4 text-xs font-bold uppercase flex items-center justify-center gap-2 transition-all ${activeTab === 'prescriptions' ? 'text-accent bg-white/5 border-b-2 border-accent' : 'text-muted-foreground opacity-50'}`}>
                <Pill size={14} /> Prescribe
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
              {activeTab === "notes" ? (
                <textarea 
                  value={notes} 
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Document findings and advice here..."
                  className="w-full h-full bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 font-medium"
                />
              ) : (
                <div className="space-y-4">
                  {prescriptions.map((p, i) => (
                    <div key={i} className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-3 relative group">
                      <input 
                        placeholder="Medicine Name" 
                        value={p.medicineName}
                        onChange={(e) => {
                          const newP = [...prescriptions];
                          newP[i].medicineName = e.target.value;
                          setPrescriptions(newP);
                        }}
                        className="w-full bg-transparent border-b border-white/10 outline-none text-sm font-bold text-accent pb-1" 
                      />
                      <div className="grid grid-cols-2 gap-2">
                        <input placeholder="Dosage" value={p.dosage} onChange={(e) => { const newP = [...prescriptions]; newP[i].dosage = e.target.value; setPrescriptions(newP); }} className="bg-transparent border-b border-white/10 outline-none text-[10px] text-foreground/70" />
                        <input placeholder="Frequency" value={p.frequency} onChange={(e) => { const newP = [...prescriptions]; newP[i].frequency = e.target.value; setPrescriptions(newP); }} className="bg-transparent border-b border-white/10 outline-none text-[10px] text-foreground/70" />
                      </div>
                      <button onClick={() => setPrescriptions(prescriptions.filter((_, idx) => idx !== i))} className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-destructive/20 text-destructive flex items-center justify-center opacity-0 group-hover:opacity-100 transition-all"><Trash2 size={12}/></button>
                    </div>
                  ))}
                  <button onClick={() => setPrescriptions([...prescriptions, { medicineName: '', dosage: '', frequency: '', duration: '', instructions: '' }])} className="w-full py-3 rounded-xl border border-dashed border-white/20 text-muted-foreground hover:text-accent transition-all text-[10px] uppercase font-bold flex items-center justify-center gap-2">
                    <Plus size={14} /> Add Medicine
                  </button>
                  <button onClick={handleSavePrescriptions} className="w-full py-3 rounded-xl bg-accent/20 text-accent font-bold text-xs flex items-center justify-center gap-2 hover:bg-accent/30 transition-all">
                    <Save size={14} /> Sync to Vault
                  </button>
                </div>
              )}
            </div>
            
            <div className="p-4 bg-black/20 border-t border-white/5 text-[10px] text-muted-foreground font-bold uppercase flex items-center gap-2">
              <ClipboardCheck size={14} className="text-success" /> Synced ID: {String(bookingId).substring(0,8)}
            </div>
          </div>

        </div>
      </div>
    </DashboardLayout>
  );
};

export default DoctorConsultationRoom;