// // // // // // import { useState } from "react";
// // // // // // import { motion } from "framer-motion";
// // // // // // import { Mic, MicOff, Video, VideoOff, Phone, FileText, MessageSquare, Clock, User } from "lucide-react";
// // // // // // import DashboardLayout from "@/components/DashboardLayout";

// // // // // // const VideoConsultation = () => {
// // // // // //   const [micOn, setMicOn] = useState(true);
// // // // // //   const [camOn, setCamOn] = useState(true);
// // // // // //   const [activeTab, setActiveTab] = useState<"transcript" | "documents" | "history">("transcript");

// // // // // //   const tabs = [
// // // // // //     { key: "transcript" as const, label: "Transcript", icon: MessageSquare },
// // // // // //     { key: "documents" as const, label: "Documents", icon: FileText },
// // // // // //     { key: "history" as const, label: "History", icon: Clock },
// // // // // //   ];

// // // // // //   return (
// // // // // //     <DashboardLayout role="patient">
// // // // // //       <div className="max-w-7xl mx-auto">
// // // // // //         <h1 className="font-display text-2xl font-bold text-foreground mb-6">Video Consultation</h1>

// // // // // //         <div className="grid lg:grid-cols-[1fr_350px] gap-4 h-[calc(100vh-12rem)]">
// // // // // //           {/* Video Panel (70%) */}
// // // // // //           <div className="glass rounded-2xl overflow-hidden relative flex flex-col">
// // // // // //             {/* Video Area */}
// // // // // //             <div className="flex-1 bg-gradient-to-br from-foreground/5 to-foreground/10 flex items-center justify-center relative">
// // // // // //               <div className="text-center">
// // // // // //                 <div className="w-24 h-24 rounded-full bg-gradient-to-br from-primary/30 to-accent/30 flex items-center justify-center mx-auto mb-4">
// // // // // //                   <User size={40} className="text-accent" />
// // // // // //                 </div>
// // // // // //                 <p className="text-muted-foreground text-sm">Dr. Sarah Chen</p>
// // // // // //                 <p className="text-xs text-muted-foreground/60">Connecting...</p>
// // // // // //               </div>

// // // // // //               {/* Self View */}
// // // // // //               <div className="absolute bottom-4 right-4 w-32 h-24 md:w-40 md:h-28 glass rounded-xl overflow-hidden flex items-center justify-center">
// // // // // //                 <User size={24} className="text-muted-foreground" />
// // // // // //               </div>
// // // // // //             </div>

// // // // // //             {/* Controls */}
// // // // // //             <div className="p-4 flex items-center justify-center gap-3">
// // // // // //               <motion.button
// // // // // //                 whileTap={{ scale: 0.9 }}
// // // // // //                 onClick={() => setMicOn(!micOn)}
// // // // // //                 className={`w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300 ${
// // // // // //                   micOn ? "glass text-foreground hover:bg-secondary" : "bg-destructive text-destructive-foreground"
// // // // // //                 }`}
// // // // // //               >
// // // // // //                 {micOn ? <Mic size={20} /> : <MicOff size={20} />}
// // // // // //               </motion.button>
// // // // // //               <motion.button
// // // // // //                 whileTap={{ scale: 0.9 }}
// // // // // //                 onClick={() => setCamOn(!camOn)}
// // // // // //                 className={`w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300 ${
// // // // // //                   camOn ? "glass text-foreground hover:bg-secondary" : "bg-destructive text-destructive-foreground"
// // // // // //                 }`}
// // // // // //               >
// // // // // //                 {camOn ? <Video size={20} /> : <VideoOff size={20} />}
// // // // // //               </motion.button>
// // // // // //               <motion.button
// // // // // //                 whileTap={{ scale: 0.9 }}
// // // // // //                 className="w-14 h-14 rounded-full bg-destructive text-destructive-foreground flex items-center justify-center hover:scale-105 transition-all"
// // // // // //               >
// // // // // //                 <Phone size={22} className="rotate-[135deg]" />
// // // // // //               </motion.button>
// // // // // //             </div>
// // // // // //           </div>

// // // // // //           {/* Side Panel (30%) */}
// // // // // //           <div className="glass rounded-2xl flex flex-col overflow-hidden">
// // // // // //             {/* Tabs */}
// // // // // //             <div className="flex border-b border-border/30">
// // // // // //               {tabs.map((tab) => (
// // // // // //                 <button
// // // // // //                   key={tab.key}
// // // // // //                   onClick={() => setActiveTab(tab.key)}
// // // // // //                   className={`flex-1 flex items-center justify-center gap-1.5 py-3 text-xs font-medium transition-all duration-300 ${
// // // // // //                     activeTab === tab.key ? "text-accent border-b-2 border-accent" : "text-muted-foreground hover:text-foreground"
// // // // // //                   }`}
// // // // // //                 >
// // // // // //                   <tab.icon size={14} />
// // // // // //                   <span className="hidden sm:inline">{tab.label}</span>
// // // // // //                 </button>
// // // // // //               ))}
// // // // // //             </div>

// // // // // //             {/* Tab Content */}
// // // // // //             <div className="flex-1 overflow-y-auto p-4">
// // // // // //               {activeTab === "transcript" && (
// // // // // //                 <div className="space-y-3">
// // // // // //                   <p className="text-xs text-muted-foreground text-center">Live transcript will appear here</p>
// // // // // //                   {["Hello, how are you feeling today?", "I've been having headaches for the past week.", "Let me check your recent reports..."].map((msg, i) => (
// // // // // //                     <motion.div
// // // // // //                       key={i}
// // // // // //                       initial={{ opacity: 0, y: 10 }}
// // // // // //                       animate={{ opacity: 1, y: 0 }}
// // // // // //                       transition={{ delay: i * 0.3 }}
// // // // // //                       className={`p-3 rounded-xl text-xs ${i % 2 === 0 ? "glass-strong" : "bg-accent/10"}`}
// // // // // //                     >
// // // // // //                       <span className="font-semibold text-foreground">{i % 2 === 0 ? "Dr. Chen: " : "You: "}</span>
// // // // // //                       <span className="text-muted-foreground">{msg}</span>
// // // // // //                     </motion.div>
// // // // // //                   ))}
// // // // // //                 </div>
// // // // // //               )}
// // // // // //               {activeTab === "documents" && (
// // // // // //                 <div className="space-y-2">
// // // // // //                   {["Blood Test Report.pdf", "Chest X-Ray.pdf"].map((doc, i) => (
// // // // // //                     <div key={i} className="glass rounded-xl p-3 flex items-center gap-2 text-xs hover:shadow-glow-accent transition-all cursor-pointer">
// // // // // //                       <FileText size={14} className="text-accent" />
// // // // // //                       <span className="text-foreground">{doc}</span>
// // // // // //                     </div>
// // // // // //                   ))}
// // // // // //                   <div className="border-2 border-dashed border-border/50 rounded-xl p-4 text-center text-xs text-muted-foreground mt-4">
// // // // // //                     Drop files here to share
// // // // // //                   </div>
// // // // // //                 </div>
// // // // // //               )}
// // // // // //               {activeTab === "history" && (
// // // // // //                 <div className="space-y-2 text-xs">
// // // // // //                   {[
// // // // // //                     { date: "Jan 15", note: "General checkup - All clear" },
// // // // // //                     { date: "Dec 20", note: "Skin allergy treatment" },
// // // // // //                     { date: "Dec 5", note: "Migraine assessment" },
// // // // // //                   ].map((item, i) => (
// // // // // //                     <div key={i} className="glass rounded-xl p-3">
// // // // // //                       <div className="font-semibold text-foreground">{item.date}</div>
// // // // // //                       <div className="text-muted-foreground">{item.note}</div>
// // // // // //                     </div>
// // // // // //                   ))}
// // // // // //                 </div>
// // // // // //               )}
// // // // // //             </div>
// // // // // //           </div>
// // // // // //         </div>
// // // // // //       </div>
// // // // // //     </DashboardLayout>
// // // // // //   );
// // // // // // };

// // // // // // export default VideoConsultation;














// // // // // import { useState, useEffect } from "react";
// // // // // import { useParams, useNavigate } from "react-router-dom";
// // // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // // import { Phone, FileText, MessageSquare, Clock, Loader2 } from "lucide-react";
// // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // import api from "@/lib/api";
// // // // // import { toast } from "sonner";

// // // // // const VideoConsultation = () => {
// // // // //   const { bookingId } = useParams(); // Get ID from URL
// // // // //   const navigate = useNavigate();
// // // // //   const [consultation, setConsultation] = useState<any>(null);
// // // // //   const [loading, setLoading] = useState(true);
// // // // //   const [notes, setNotes] = useState("");

// // // // //   // 1. Initialize Consultation on Backend
// // // // //   useEffect(() => {
// // // // //     const startSession = async () => {
// // // // //       try {
// // // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // // //         setConsultation(res.data);
// // // // //       } catch (err) {
// // // // //         toast.error("Failed to initialize video room.");
// // // // //       } finally {
// // // // //         setLoading(false);
// // // // //       }
// // // // //     };
// // // // //     startSession();
// // // // //   }, [bookingId]);

// // // // //   // 2. End Call Handler
// // // // //   const handleEndCall = async () => {
// // // // //     try {
// // // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
// // // // //       toast.success("Session saved to medical history.");
// // // // //       navigate("/patient/dashboard");
// // // // //     } catch (err) {
// // // // //       toast.error("Failed to save session notes.");
// // // // //     }
// // // // //   };

// // // // //   if (loading) return <div className="flex items-center justify-center min-h-screen"><Loader2 className="animate-spin" /></div>;

// // // // //   return (
// // // // //     <DashboardLayout role="patient">
// // // // //       <div className="max-w-7xl mx-auto space-y-4">
// // // // //         <div className="flex justify-between items-center">
// // // // //           <h1 className="font-display text-2xl font-bold">Live Consultation</h1>
// // // // //           <button onClick={handleEndCall} className="bg-destructive text-white px-6 py-2 rounded-xl flex items-center gap-2 font-bold">
// // // // //             <Phone size={18} className="rotate-[135deg]" /> End & Save
// // // // //           </button>
// // // // //         </div>

// // // // //         <div className="grid lg:grid-cols-[1fr_350px] gap-4 h-[calc(100vh-15rem)]">
// // // // //           {/* Jitsi Video Integration */}
// // // // //           <div className="glass rounded-2xl overflow-hidden relative">
// // // // //             <JitsiMeeting
// // // // //               domain="meet.jit.si"
// // // // //               roomName={`Medibot-Room-${bookingId}`}
// // // // //               configOverwrite={{
// // // // //                 startWithAudioMuted: false,
// // // // //                 disableModeratorIndicator: true,
// // // // //                 enableEmailInStats: false,
// // // // //               }}
// // // // //               interfaceConfigOverwrite={{
// // // // //                 TOOLBAR_BUTTONS: ['microphone', 'camera', 'desktop', 'chat', 'raisehand'],
// // // // //               }}
// // // // //               getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; }}
// // // // //             />
// // // // //           </div>

// // // // //           {/* Sidebar for Notes & History */}
// // // // //           <div className="glass rounded-2xl flex flex-col overflow-hidden p-4">
// // // // //              <h3 className="font-bold text-sm mb-2 flex items-center gap-2"><FileText size={14}/> Clinical Notes</h3>
// // // // //              <textarea 
// // // // //                value={notes} 
// // // // //                onChange={(e) => setNotes(e.target.value)}
// // // // //                placeholder="Write summary here..."
// // // // //                className="flex-1 w-full bg-transparent border border-white/10 rounded-lg p-3 text-xs outline-none focus:ring-1 focus:ring-accent"
// // // // //              />
// // // // //           </div>
// // // // //         </div>
// // // // //       </div>
// // // // //     </DashboardLayout>
// // // // //   );
// // // // // };

// // // // // export default VideoConsultation;




// // // // import { useState, useEffect } from "react";
// // // // import { useParams, useNavigate } from "react-router-dom";
// // // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // // import { Phone, FileText, Mic, MicOff, Video, VideoOff, Loader2, ShieldCheck } from "lucide-react";
// // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // import api from "@/lib/api";
// // // // import { toast } from "sonner";

// // // // const VideoConsultation = () => {
// // // //   const { bookingId } = useParams(); // Retrieves the specific appointment ID from the URL
// // // //   const navigate = useNavigate();
  
// // // //   const [consultation, setConsultation] = useState<any>(null);
// // // //   const [loading, setLoading] = useState(true);
// // // //   const [notes, setNotes] = useState("");
// // // //   const [isEnding, setIsEnding] = useState(false);

// // // //   // 1. Handshake with Backend to start the clinical session
// // // //   useEffect(() => {
// // // //     const initSession = async () => {
// // // //       if (!bookingId) {
// // // //         toast.error("Invalid booking reference.");
// // // //         navigate("/patient/dashboard");
// // // //         return;
// // // //       }

// // // //       try {
// // // //         setLoading(true);
// // // //         // Calls your @PostMapping("/start/{bookingId}")
// // // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // // //         setConsultation(res.data);
// // // //       } catch (err) {
// // // //         console.error("Session Init Error:", err);
// // // //         toast.error("Could not start medical session. Verify appointment status.");
// // // //         navigate("/patient/dashboard");
// // // //       } finally {
// // // //         setLoading(false);
// // // //       }
// // // //     };
// // // //     initSession();
// // // //   }, [bookingId, navigate]);

// // // //   // 2. Finalize Session: End call and save clinical notes
// // // //   const handleEndAndSave = async () => {
// // // //     if (!consultation?.id) return;
    
// // // //     try {
// // // //       setIsEnding(true);
// // // //       // Calls your @PatchMapping("/end/{id}")
// // // //       // Important: Send notes as a plain string if your backend uses @RequestBody String notes
// // // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
      
// // // //       toast.success("Consultation complete. Notes saved to your history.");
// // // //       navigate("/patient/consultations"); // Redirect to the History Library
// // // //     } catch (err) {
// // // //       toast.error("Error saving notes. Please copy them before leaving.");
// // // //     } finally {
// // // //       setIsEnding(false);
// // // //     }
// // // //   };

// // // //   if (loading) return (
// // // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // // //       <Loader2 className="animate-spin text-accent mb-4" size={40} />
// // // //       <p className="text-muted-foreground animate-pulse font-medium">Securing clinical room...</p>
// // // //     </div>
// // // //   );

// // // //   return (
// // // //     <DashboardLayout role="patient">
// // // //       <div className="max-w-7xl mx-auto space-y-6 h-[calc(100vh-8rem)] flex flex-col">
        
// // // //         {/* Header Section */}
// // // //         <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
// // // //           <div>
// // // //             <h1 className="font-display text-2xl font-bold flex items-center gap-2">
// // // //               <div className="w-2 h-2 rounded-full bg-destructive animate-ping" />
// // // //               Live Consultation
// // // //             </h1>
// // // //             <p className="text-xs text-muted-foreground flex items-center gap-1 mt-1">
// // // //               <ShieldCheck size={12} className="text-success" /> End-to-end encrypted medical session
// // // //             </p>
// // // //           </div>
          
// // // //           <button 
// // // //             onClick={handleEndAndSave} 
// // // //             disabled={isEnding}
// // // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // // //           >
// // // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // // //             End & Save Record
// // // //           </button>
// // // //         </div>

// // // //         <div className="grid lg:grid-cols-[1fr_350px] gap-6 flex-1 min-h-0">
          
// // // //           {/* LEFT: Live Video Feed (WebRTC) */}
// // // //           <div className="glass rounded-3xl overflow-hidden relative border-white/5 bg-black/20">
// // // //             <JitsiMeeting
// // // //               domain="meet.jit.si"
// // // //               roomName={`Medibot-Room-${bookingId}`}
// // // //               configOverwrite={{
// // // //                 startWithAudioMuted: false,
// // // //                 disableModeratorIndicator: true,
// // // //                 enableEmailInStats: false,
// // // //                 prejoinPageEnabled: false,
// // // //               }}
// // // //               interfaceConfigOverwrite={{
// // // //                 TOOLBAR_BUTTONS: ['microphone', 'camera', 'desktop', 'chat', 'raisehand', 'tileview'],
// // // //               }}
// // // //               getIFrameRef={(iframeRef) => {
// // // //                 iframeRef.style.height = '100%';
// // // //                 iframeRef.style.width = '100%';
// // // //               }}
// // // //             />
// // // //           </div>

// // // //           {/* RIGHT: Live Physician Notes Panel */}
// // // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5">
// // // //             <div className="p-5 border-b border-white/5 bg-white/5">
// // // //               <h3 className="font-bold text-sm flex items-center gap-2">
// // // //                 <FileText size={16} className="text-accent" /> 
// // // //                 Live Clinical Notes
// // // //               </h3>
// // // //               <p className="text-[10px] text-muted-foreground mt-1">Summarize vitals and diagnosis here.</p>
// // // //             </div>
            
// // // //             <div className="flex-1 p-4">
// // // //               <textarea 
// // // //                 value={notes} 
// // // //                 onChange={(e) => setNotes(e.target.value)}
// // // //                 placeholder="Start typing physician notes..."
// // // //                 className="w-full h-full bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/30"
// // // //               />
// // // //             </div>
            
// // // //             <div className="p-4 bg-accent/5">
// // // //                <div className="text-[9px] uppercase tracking-widest text-accent font-bold mb-2">Patient Security Context</div>
// // // //                <div className="glass-strong rounded-xl p-3 text-[10px] text-muted-foreground">
// // // //                   Reference ID: {consultation?.id.substring(0, 13)}...
// // // //                </div>
// // // //             </div>
// // // //           </div>

// // // //         </div>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );
// // // // };

// // // // export default VideoConsultation;












// // // import { useState, useEffect } from "react";
// // // import { useParams, useNavigate } from "react-router-dom";
// // // import { JitsiMeeting } from "@jitsi/react-sdk";
// // // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import api from "@/lib/api";
// // // import { toast } from "sonner";

// // // const VideoConsultation = () => {
// // //   // Retrieves the specific appointment ID from the URL (mapped in App.tsx)
// // //   const { bookingId } = useParams(); 
// // //   const navigate = useNavigate();
  
// // //   const [consultation, setConsultation] = useState<any>(null);
// // //   const [loading, setLoading] = useState(true);
// // //   const [notes, setNotes] = useState("");
// // //   const [isEnding, setIsEnding] = useState(false);

// // //   // 1. Session Handshake: Sync with backend session or create one
// // //   useEffect(() => {
// // //     const initSession = async () => {
// // //       if (!bookingId) {
// // //         toast.error("Invalid booking reference.");
// // //         navigate("/patient/dashboard");
// // //         return;
// // //       }

// // //       try {
// // //         setLoading(true);
// // //         // Hits @PostMapping("/start/{bookingId}") - Now idempotent to avoid 500 errors
// // //         const res = await api.post(`/consultations/start/${bookingId}`);
// // //         setConsultation(res.data);
// // //         console.log("CLINICAL_SYNC: Established session ID", res.data.id);
// // //       } catch (err) {
// // //         console.error("Clinical Handshake Failed:", err);
// // //         toast.error("Could not secure the clinical room. Verify appointment status.");
// // //         navigate("/patient/dashboard");
// // //       } finally {
// // //         setLoading(false);
// // //       }
// // //     };
// // //     initSession();
// // //   }, [bookingId, navigate]);

// // //   // 2. Finalize Session: Patient can end call and save their perspective/notes
// // //   const handleEndAndSave = async () => {
// // //     if (!consultation?.id) return;
    
// // //     try {
// // //       setIsEnding(true);
// // //       // Hits @PatchMapping("/end/{id}") on backend
// // //       await api.patch(`/consultations/end/${consultation.id}`, notes);
      
// // //       toast.success("Consultation ended. Notes saved to your history.");
// // //       navigate("/patient/consultations"); // Redirect to history records
// // //     } catch (err) {
// // //       toast.error("Error saving session data. Check your connection.");
// // //     } finally {
// // //       setIsEnding(false);
// // //     }
// // //   };

// // //   if (loading) return (
// // //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// // //       <Loader2 className="animate-spin text-accent mb-4" size={40} />
// // //       <p className="text-muted-foreground animate-pulse font-medium">Securing encrypted clinical room...</p>
// // //     </div>
// // //   );

// // //   return (
// // //     <DashboardLayout role="patient">
// // //       <div className="max-w-7xl mx-auto space-y-6 h-[calc(100vh-8rem)] flex flex-col">
        
// // //         {/* Connection Header */}
// // //         <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
// // //           <div>
// // //             <h1 className="font-display text-2xl font-bold flex items-center gap-2 text-foreground">
// // //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// // //               Live Consultation
// // //             </h1>
// // //             <p className="text-[10px] text-muted-foreground flex items-center gap-1.5 mt-1 uppercase tracking-widest font-black">
// // //               <ShieldCheck size={12} className="text-success" /> HIPAA-Compliant Video Tunnel
// // //             </p>
// // //           </div>
          
// // //           <button 
// // //             onClick={handleEndAndSave} 
// // //             disabled={isEnding}
// // //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3.5 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// // //           >
// // //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// // //             End & Save Record
// // //           </button>
// // //         </div>

// // //         <div className="grid lg:grid-cols-[1fr_350px] gap-6 flex-1 min-h-0">
          
// // //           {/* Jitsi Meeting Viewport (The exact same logic as Doctor side) */}
// // //           <div className="glass rounded-3xl overflow-hidden relative border-white/5 bg-black/20">
// // //             <JitsiMeeting
// // //               domain="meet.jit.si"
// // //               // CRITICAL SYNC: This string must match the Doctor's exactly
// // //               roomName={`Medibot-Room-${bookingId}`} 
// // //               configOverwrite={{
// // //                 startWithAudioMuted: false,
// // //                 disableModeratorIndicator: true,
// // //                 enableEmailInStats: false,
// // //                 prejoinPageEnabled: false, // Bypasses the name/login entry screen
// // //               }}
// // //               interfaceConfigOverwrite={{
// // //                 TOOLBAR_BUTTONS: ['microphone', 'camera', 'chat', 'tileview', 'raisehand'],
// // //                 SHOW_JITSI_WATERMARK: false,
// // //               }}
// // //               getIFrameRef={(iframeRef) => {
// // //                 iframeRef.style.height = '100%';
// // //                 iframeRef.style.width = '100%';
// // //               }}
// // //             />
// // //           </div>

// // //           {/* Clinical Context Sidebar */}
// // //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// // //             <div className="p-5 border-b border-white/10 bg-white/5">
// // //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent">
// // //                 <FileText size={16} /> 
// // //                 Clinical Summary
// // //               </h3>
// // //               <p className="text-[9px] text-muted-foreground mt-1 uppercase font-bold tracking-tight">Your personal session notes</p>
// // //             </div>
            
// // //             <div className="flex-1 p-4">
// // //               <textarea 
// // //                 value={notes} 
// // //                 onChange={(e) => setNotes(e.target.value)}
// // //                 placeholder="Type your own notes or questions for the doctor here. They will be saved to your dashboard record..."
// // //                 className="w-full h-full bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/20 font-medium"
// // //               />
// // //             </div>
            
// // //             <div className="p-5 bg-black/20 border-t border-white/5">
// // //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// // //                   <ClipboardCheck size={14} className="text-success" /> 
// // //                   <span>Auto-Archive ID: {consultation?.id.substring(0,8)}</span>
// // //                </div>
// // //             </div>
// // //           </div>

// // //         </div>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default VideoConsultation;




// // import { useState, useEffect } from "react";
// // import { useParams, useNavigate } from "react-router-dom";
// // import { JitsiMeeting } from "@jitsi/react-sdk";
// // import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck, User } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import api from "@/lib/api";
// // import { toast } from "sonner";

// // const VideoConsultation = () => {
// //   const { bookingId } = useParams(); 
// //   const navigate = useNavigate();
  
// //   const [consultation, setConsultation] = useState<any>(null);
// //   const [activeRoomId, setActiveRoomId] = useState<string>(""); // Discovered from Doctor
// //   const [loading, setLoading] = useState(true);
// //   const [notes, setNotes] = useState("");
// //   const [isEnding, setIsEnding] = useState(false);

// //   // 1. HANDSHAKE & DISCOVERY
// //   useEffect(() => {
// //     let pollInterval: NodeJS.Timeout;

// //     const initHandshake = async () => {
// //       try {
// //         setLoading(true);
// //         // A. Start the session context
// //         const sessionRes = await api.post(`/consultations/start/${bookingId}`);
// //         setConsultation(sessionRes.data);

// //         // B. Discovery Polling: Check if the doctor has initialized the room yet
// //         const discoverRoom = async () => {
// //           try {
// //             const roomRes = await api.get(`/consultations/active/${bookingId}`);
// //             if (roomRes.data) {
// //               setActiveRoomId(roomRes.data);
// //               setLoading(false);
// //               clearInterval(pollInterval);
// //               console.log("DISCOVERY_SUCCESS: Entering Doctor's Room:", roomRes.data);
// //             }
// //           } catch (err) {
// //             // Doctor hasn't "stamped" the room ID yet; we keep polling
// //             console.log("Waiting for Physician to broadcast room...");
// //           }
// //         };

// //         // Start polling every 3 seconds
// //         pollInterval = setInterval(discoverRoom, 3000);
// //         // Run once immediately
// //         discoverRoom();

// //       } catch (err) {
// //         console.error("Clinical Handshake Failed:", err);
// //         toast.error("Handshake failed. Ensure your appointment is valid.");
// //         navigate("/patient/dashboard");
// //       }
// //     };

// //     initHandshake();
// //     return () => clearInterval(pollInterval); // Cleanup on exit
// //   }, [bookingId, navigate]);

// //   const handleEndCall = async () => {
// //     if (!consultation?.id) return;
// //     try {
// //       setIsEnding(true);
// //       // Finalizes the patient-side perspective and exits
// //       await api.patch(`/consultations/end/${consultation.id}`, notes);
// //       toast.success("Session closed. Returning to dashboard.");
// //       navigate("/patient/consultations"); 
// //     } catch (err) {
// //       toast.error("Unable to archive session. Redirecting...");
// //       navigate("/patient/dashboard");
// //     } finally {
// //       setIsEnding(false);
// //     }
// //   };

// //   // UI STATE: Waiting for Doctor
// //   if (loading) return (
// //     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
// //       <div className="relative mb-8">
// //         <Loader2 className="animate-spin text-accent" size={64} />
// //         <User className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-foreground/50" size={24} />
// //       </div>
// //       <h2 className="text-xl font-bold text-foreground mb-2">Waiting for Dr. Elena...</h2>
// //       <p className="text-muted-foreground animate-pulse text-sm">Synchronizing your encrypted clinical tunnel.</p>
// //     </div>
// //   );

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-7xl mx-auto space-y-6 h-[calc(100vh-8rem)] flex flex-col">
        
// //         {/* Header: Identity & Security */}
// //         <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
// //           <div>
// //             <h1 className="font-display text-2xl font-bold flex items-center gap-2 text-foreground">
// //               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
// //               Live Consultation Room
// //             </h1>
// //             <p className="text-[10px] text-muted-foreground flex items-center gap-1.5 mt-1 uppercase tracking-widest font-black">
// //               <ShieldCheck size={12} className="text-success" /> Handshake Verified: {consultation?.id.substring(0,8)}
// //             </p>
// //           </div>
          
// //           <button 
// //             onClick={handleEndCall} 
// //             disabled={isEnding}
// //             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
// //           >
// //             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
// //             End & Exit Call
// //           </button>
// //         </div>

// //         <div className="grid lg:grid-cols-[1fr_350px] gap-6 flex-1 min-h-0">
          
// //           {/* WEBRTC VIEWPORT (Authoritative Room) */}
// //           <div className="glass rounded-3xl overflow-hidden relative border-white/5 bg-black/40">
// //             {activeRoomId && (
// //               <JitsiMeeting
// //                 domain="meet.jit.si"
// //                 roomName={activeRoomId} // Use the EXACT string discovered from Elena
// //                 configOverwrite={{
// //                   startWithAudioMuted: true, // Prevents feedback on same-PC tests
// //                   startWithVideoMuted: true, // Frees hardware for the other browser
// //                   prejoinPageEnabled: false,
// //                   disableDeepLinking: true
// //                 }}
// //                 interfaceConfigOverwrite={{
// //                   TOOLBAR_BUTTONS: ['microphone', 'camera', 'chat', 'tileview', 'raisehand'],
// //                   SHOW_JITSI_WATERMARK: false,
// //                 }}
// //                 getIFrameRef={(iframeRef) => {
// //                   iframeRef.style.height = '100%';
// //                   iframeRef.style.width = '100%';
// //                 }}
// //               />
// //             )}
// //           </div>

// //           {/* PATIENT NOTES SIDEBAR */}
// //           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
// //             <div className="p-5 border-b border-white/10 bg-white/5">
// //               <h3 className="font-bold text-sm flex items-center gap-2 text-accent uppercase tracking-wider">
// //                 <FileText size={16} /> Patient Scratchpad
// //               </h3>
// //             </div>
            
// //             <textarea 
// //               value={notes} 
// //               onChange={(e) => setNotes(e.target.value)}
// //               placeholder="Jot down questions for your doctor here. These will be saved to your dashboard after the call..."
// //               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/20 font-medium"
// //             />
            
// //             <div className="p-5 bg-black/20 border-t border-white/5">
// //                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
// //                   <ClipboardCheck size={14} className="text-success" /> 
// //                   <span>Session Tunnel Verified</span>
// //                </div>
// //             </div>
// //           </div>

// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default VideoConsultation;











// import { useState, useEffect } from "react";
// import { useParams, useNavigate } from "react-router-dom";
// import { JitsiMeeting } from "@jitsi/react-sdk";
// import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck, User } from "lucide-react";
// import DashboardLayout from "@/components/DashboardLayout";
// import api from "@/lib/api";
// import { toast } from "sonner";

// const VideoConsultation = () => {
//   const { bookingId } = useParams(); 
//   const navigate = useNavigate();
  
//   const [consultation, setConsultation] = useState<any>(null);
//   const [activeRoomId, setActiveRoomId] = useState<string>(""); 
//   const [loading, setLoading] = useState(true);
//   const [notes, setNotes] = useState("");
//   const [isEnding, setIsEnding] = useState(false);

//   // 1. AUTHORITATIVE DISCOVERY LOGIC
//   useEffect(() => {
//     let pollInterval: NodeJS.Timeout;

//     const initHandshake = async () => {
//       try {
//         // Step A: Register presence on the backend
//         const sessionRes = await api.post(`/consultations/start/${bookingId}`);
//         setConsultation(sessionRes.data);

//         // Step B: Define the discovery function
//         const discoverRoom = async () => {
//           try {
//             // Ask backend: "Has Dr. Elena broadcasted the room ID yet?"
//             const roomRes = await api.get(`/api/consultations/active/${bookingId}`);
//             if (roomRes.data) {
//               setActiveRoomId(roomRes.data);
//               setLoading(false);
//               clearInterval(pollInterval); // Stop asking once found
//               console.log("DISCOVERY_SUCCESS: Joining authoritative room:", roomRes.data);
//             }
//           } catch (err) {
//             // 404 means Elena hasn't entered Jitsi yet; we stay on the loading screen
//             console.log("Discovery: Waiting for physician signal...");
//           }
//         };

//         // Start polling every 3 seconds to ensure instant connection when doctor is ready
//         pollInterval = setInterval(discoverRoom, 3000);
//         discoverRoom(); // Initial check

//       } catch (err) {
//         console.error("Discovery Handshake Failed:", err);
//         toast.error("Handshake failed. Ensure your appointment is active.");
//         navigate("/patient/dashboard");
//       }
//     };

//     initHandshake();
//     return () => clearInterval(pollInterval); // Cleanup on component unmount
//   }, [bookingId, navigate]);

//   // 2. WRAP-UP: End call and save patient-side findings
//   const handleEndCall = async () => {
//     if (!consultation?.id) return;
//     try {
//       setIsEnding(true);
//       await api.patch(`/api/consultations/end/${consultation.id}`, notes);
//       toast.success("Consultation session archived.");
//       navigate("/patient/consultations"); 
//     } catch (err) {
//       toast.error("Unable to save notes. Redirecting...");
//       navigate("/patient/dashboard");
//     } finally {
//       setIsEnding(false);
//     }
//   };

//   // UI STATE: Polling/Waiting for Doctor Discovery
//   if (loading) return (
//     <div className="min-h-screen flex flex-col items-center justify-center bg-background">
//       <div className="relative mb-8">
//         <Loader2 className="animate-spin text-accent" size={64} />
//         <User className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-foreground/50" size={24} />
//       </div>
//       <h2 className="text-xl font-bold text-foreground mb-2">Connecting to Dr. Elena...</h2>
//       <p className="text-muted-foreground animate-pulse text-sm">Please wait while the doctor prepares your clinical tunnel.</p>
//     </div>
//   );

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-7xl mx-auto space-y-6 h-[calc(100vh-8rem)] flex flex-col">
        
//         {/* Patient Header */}
//         <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
//           <div>
//             <h1 className="font-display text-2xl font-bold flex items-center gap-2 text-foreground">
//               <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
//               Live Consultation Room
//             </h1>
//             <p className="text-[10px] text-muted-foreground flex items-center gap-1.5 mt-1 uppercase tracking-widest font-black">
//               <ShieldCheck size={12} className="text-success" /> HIPAA-Verified Connection: {consultation?.id.substring(0,8)}
//             </p>
//           </div>
          
//           <button 
//             onClick={handleEndCall} 
//             disabled={isEnding}
//             className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3.5 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 transition-all active:scale-95 disabled:opacity-50"
//           >
//             {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
//             Finish & Exit Call
//           </button>
//         </div>

//         <div className="grid lg:grid-cols-[1fr_350px] gap-6 flex-1 min-h-0">
          
//           {/* JITSI VIEWPORT (Discovered Room ID) */}
//           <div className="glass rounded-3xl overflow-hidden relative border-white/5 bg-black/40">
//             {activeRoomId && (
//               <JitsiMeeting
//                 domain="meet.jit.si"
//                 roomName={activeRoomId} // Force-joins the doctor's specific ID
//                 configOverwrite={{
//                   startWithAudioMuted: true, // Prevents feedback loop on one-PC tests
//                   startWithVideoMuted: true, // Frees hardware for the doctor side
//                   prejoinPageEnabled: false,
//                   disableDeepLinking: true
//                 }}
//                 interfaceConfigOverwrite={{
//                   TOOLBAR_BUTTONS: ['microphone', 'camera', 'chat', 'tileview', 'raisehand'],
//                   SHOW_JITSI_WATERMARK: false,
//                 }}
//                 getIFrameRef={(iframeRef) => {
//                   iframeRef.style.height = '100%';
//                   iframeRef.style.width = '100%';
//                 }}
//               />
//             )}
//           </div>

//           {/* PATIENT WORKSPACE */}
//           <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
//             <div className="p-5 border-b border-white/10 bg-white/5">
//               <h3 className="font-bold text-sm flex items-center gap-2 text-accent uppercase tracking-wider">
//                 <FileText size={16} /> Session Scratchpad
//               </h3>
//             </div>
            
//             <textarea 
//               value={notes} 
//               onChange={(e) => setNotes(e.target.value)}
//               placeholder="Keep track of the doctor's advice or jot down symptoms here..."
//               className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 placeholder:text-muted-foreground/20 font-medium"
//             />
            
//             <div className="p-5 bg-black/20 border-t border-white/5">
//                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase">
//                   <ClipboardCheck size={14} className="text-success" /> 
//                   <span>Synced Medical Tunnel</span>
//                </div>
//             </div>
//           </div>

//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default VideoConsultation;






import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { JitsiMeeting } from "@jitsi/react-sdk";
import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck, User } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";
import { toast } from "sonner";

const VideoConsultation = () => {
  const { bookingId } = useParams(); 
  const navigate = useNavigate();
  
  const [consultation, setConsultation] = useState<any>(null);
  const [activeRoomId, setActiveRoomId] = useState<string>(""); 
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState("");
  const [isEnding, setIsEnding] = useState(false);

  useEffect(() => {
    let pollInterval: NodeJS.Timeout;

    const initHandshake = async () => {
      try {
        const sessionRes = await api.post(`/consultations/start/${bookingId}`);
        setConsultation(sessionRes.data);

        const discoverRoom = async () => {
          try {
            const roomRes = await api.get(`/consultations/active/${bookingId}`);
            if (roomRes.data) {
              setActiveRoomId(roomRes.data);
              setLoading(false);
              clearInterval(pollInterval);
            }
          } catch (err) {
            console.log("Discovery: Waiting for Dr. Elena...");
          }
        };

        pollInterval = setInterval(discoverRoom, 3000);
        discoverRoom();

      } catch (err) {
        toast.error("Handshake failed. Verify appointment status.");
        navigate("/patient/dashboard");
      }
    };

    initHandshake();
    return () => clearInterval(pollInterval);
  }, [bookingId, navigate]);

  const handleEndCall = async () => {
    if (!consultation?.id) return;
    try {
      setIsEnding(true);
      // FIXED: Wrap 'notes' in an object to match the ConsultationEndRequest DTO
      await api.patch(`/consultations/end/${consultation.id}`, { notes: notes }); 
      
      toast.success("Consultation archived.");
      navigate("/patient/consultations"); 
    } catch (err) {
      toast.error("Unable to save session. Redirecting...");
      navigate("/patient/dashboard");
    } finally {
      setIsEnding(false);
    }
  };

  if (loading) return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background">
      <Loader2 className="animate-spin text-accent mb-4" size={44} />
      <h2 className="text-xl font-bold">Connecting to Physician...</h2>
      <p className="text-muted-foreground animate-pulse text-sm">Validating your encrypted clinical tunnel.</p>
    </div>
  );

  return (
    <DashboardLayout role="patient">
      <div className="max-w-7xl mx-auto space-y-6 h-[calc(100vh-8rem)] flex flex-col">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="font-display text-2xl font-bold flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-destructive animate-ping" />
              Live Consultation
            </h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-black">
              <ShieldCheck size={12} className="text-success" /> HIPAA SECURE
            </p>
          </div>
          <button onClick={handleEndCall} disabled={isEnding} className="bg-destructive text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 active:scale-95 transition-all">
            {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
            Finish & Exit
          </button>
        </div>

        <div className="grid lg:grid-cols-[1fr_350px] gap-6 flex-1 min-h-0">
          <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
            {activeRoomId && (
              <JitsiMeeting
                domain="meet.jit.si"
                roomName={activeRoomId}
                configOverwrite={{ startWithAudioMuted: true, startWithVideoMuted: true, prejoinPageEnabled: false }}
                getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; iframeRef.style.width = '100%'; }}
              />
            )}
          </div>
          <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
            <div className="p-5 border-b border-white/10 bg-white/5 flex items-center gap-2 text-accent font-bold text-sm uppercase tracking-wider">
              <FileText size={16} /> My Notes
            </div>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Type notes for your record..." className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 font-medium" />
            <div className="p-4 bg-black/20 border-t border-white/5 text-[10px] text-muted-foreground font-bold uppercase flex items-center gap-2">
              <ClipboardCheck size={14} className="text-success" /> Session Sync Active
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default VideoConsultation;