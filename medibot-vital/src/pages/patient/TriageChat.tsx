



// // import { useState, useRef, useEffect } from "react";
// // import { motion, AnimatePresence } from "framer-motion";
// // import { Send, Bot, User, Sparkles, Save, AlertCircle, CheckCircle, Loader2 } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import { patientService } from "@/services/patientService";
// // import api from "@/lib/api"; // FIX: Use the customized api instance with interceptors

// // interface Disease {
// //   name: string;
// //   confidence: number;
// // }

// // interface Message {
// //   id: number;
// //   role: "user" | "ai";
// //   text: string;
// //   diseases?: Disease[];
// //   tips?: string[];
// //   warning?: string;
// // }

// // const TriageChat = () => {
// //   const [messages, setMessages] = useState<Message[]>([
// //     { id: 0, role: "ai", text: "Hello! I'm your AI health assistant. Describe your symptoms and I'll provide a clinical analysis." },
// //   ]);
// //   const [input, setInput] = useState("");
// //   const [typing, setTyping] = useState(false);
  
// //   // Track state for the "Save to Timeline" functionality
// //   const [lastResult, setLastResult] = useState<any>(null);
// //   const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">("idle");
  
// //   const endRef = useRef<HTMLDivElement>(null);

// //   useEffect(() => {
// //     endRef.current?.scrollIntoView({ behavior: "smooth" });
// //   }, [messages, typing]);

// //   const handleSend = async () => {
// //     if (!input.trim()) return;

// //     const userMsg: Message = { id: Date.now(), role: "user", text: input };
// //     setMessages((prev) => [...prev, userMsg]);
// //     const currentInput = input;
// //     setInput("");
// //     setTyping(true);
// //     setSaveStatus("idle"); 

// //     try {
// //       const symptomsList = currentInput.split(',').map(s => s.trim()).filter(s => s !== "");
// //       const data = await patientService.analyzeSymptoms(symptomsList);

// //       const isGuardrail = data.predictedDisease === "Needs More Detail" || data.confidence === 0;

// //       // Store results locally to enable the "Save" functionality later
// //       if (!isGuardrail) {
// //         setLastResult({
// //           symptoms: currentInput,
// //           disease: data.predictedDisease,
// //           confidence: data.confidence, // Matches @RequestParam in TriageHistoryController
// //           tips: data.preventionTips    // Matches @RequestBody List<String> tips
// //         });
// //       }

// //       const allPredictions: Disease[] = !isGuardrail ? [
// //         { name: data.predictedDisease, confidence: Math.round(data.confidence * 100) },
// //         ...(data.otherSuggestions || [])
// //       ] : [];

// //       const aiResponse: Message = {
// //         id: Date.now(),
// //         role: "ai",
// //         text: isGuardrail 
// //           ? "I need a bit more detail to give you an accurate analysis."
// //           : `Analysis complete. Based on your symptoms, the most likely condition is ${data.predictedDisease}. I recommend visiting the ${data.recommendedDepartment} department.`,
// //         diseases: allPredictions,
// //         tips: data.preventionTips,
// //         warning: data.redFlagWarning 
// //       };

// //       setMessages((prev) => [...prev, aiResponse]);
// //     } catch (error) {
// //       console.error("Triage Error:", error);
// //       setMessages((prev) => [...prev, { 
// //         id: Date.now(), 
// //         role: "ai", 
// //         text: "I apologize, but I'm having trouble reaching the analysis engine." 
// //       }]);
// //     } finally {
// //       setTyping(false);
// //     }
// //   };

// //   /**
// //    * Persists AI results to the backend TriageHistoryController
// //    */
// //   const handleSaveToRecalls = async () => {
// //     if (!lastResult || saveStatus !== "idle") return;

// //     // FIX: Retrieve keys consistent with your AuthService.ts
// //     const token = localStorage.getItem("accessToken");
// //     const patientId = localStorage.getItem("userId");

// //     if (!patientId || !token || patientId === "undefined") {
// //         alert("Session error. Please log out and log in again to save your record.");
// //         return;
// //     }

// //     setSaveStatus("saving");
// //     try {
// //       // Endpoint: /api/triage/history/save/{patientId}
// //       // RequestBody: lastResult.tips
// //       // RequestParams: disease, confidence, symptoms
// //       await api.post(
// //         `/triage/history/save/${patientId}`, 
// //         lastResult.tips, 
// //         { 
// //           params: { 
// //             disease: lastResult.disease,
// //             confidence: lastResult.confidence,
// //             symptoms: lastResult.symptoms 
// //           }
// //         }
// //       );

// //       setSaveStatus("saved");
// //       setTimeout(() => setSaveStatus("idle"), 4000);
// //     } catch (error) {
// //       console.error("Save failed:", error);
// //       setSaveStatus("idle");
// //       alert("Verification failed. Please ensure your session is active.");
// //     }
// //   };

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-3xl mx-auto h-[calc(100vh-8rem)] flex flex-col">
// //         <div className="flex items-center justify-between mb-4">
// //           <div>
// //             <h1 className="font-display text-2xl font-bold text-foreground flex items-center gap-2">
// //               <Sparkles size={22} className="text-accent" /> AI Triage
// //             </h1>
// //             <p className="text-sm text-muted-foreground">ML-Driven Symptom Analysis & Clinical Advice</p>
// //           </div>
          
// //           <button 
// //             onClick={handleSaveToRecalls}
// //             disabled={!lastResult || saveStatus !== "idle"}
// //             className={`glass rounded-xl px-4 py-2 text-sm font-medium transition-all flex items-center gap-2 ${
// //               saveStatus === "saved" ? "text-success border-success/50" : "text-foreground hover:shadow-glow-accent"
// //             } disabled:opacity-30`}
// //           >
// //             {saveStatus === "saving" ? (
// //               <Loader2 size={14} className="animate-spin text-accent" />
// //             ) : saveStatus === "saved" ? (
// //               <CheckCircle size={14} className="text-success" />
// //             ) : (
// //               <Save size={14} />
// //             )}
// //             {saveStatus === "saving" ? "Saving..." : saveStatus === "saved" ? "Saved to Timeline" : "Save to Recalls"}
// //           </button>
// //         </div>

// //         <div className="flex-1 glass rounded-2xl p-4 overflow-y-auto space-y-4 mb-4">
// //           <AnimatePresence>
// //             {messages.map((msg) => (
// //               <motion.div
// //                 key={msg.id}
// //                 initial={{ opacity: 0, y: 10, scale: 0.95 }}
// //                 animate={{ opacity: 1, y: 0, scale: 1 }}
// //                 className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
// //               >
// //                 {msg.role === "ai" && (
// //                   <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center flex-shrink-0 mt-1">
// //                     <Bot size={16} className="text-accent-foreground" />
// //                   </div>
// //                 )}
// //                 <div className={`max-w-[80%] ${msg.role === "user" ? "bg-gradient-to-r from-primary to-accent text-accent-foreground" : "glass-strong"} rounded-2xl p-4`}>
// //                   <p className="text-sm leading-relaxed">{msg.text}</p>

// //                   {msg.diseases && msg.diseases.length > 0 && (
// //                     <div className="mt-4 space-y-3">
// //                       <p className="text-xs font-semibold uppercase tracking-wider opacity-70">ML Prediction Confidence</p>
// //                       {msg.diseases.map((d) => (
// //                         <div key={d.name} className="space-y-1">
// //                           <div className="flex justify-between text-xs">
// //                             <span className="font-medium">{d.name}</span>
// //                             <span>{d.confidence}%</span>
// //                           </div>
// //                           <div className="w-full h-2 rounded-full bg-foreground/10 overflow-hidden">
// //                             <motion.div
// //                               initial={{ width: 0 }}
// //                               animate={{ width: `${d.confidence}%` }}
// //                               transition={{ duration: 1, delay: 0.3 }}
// //                               className="h-full rounded-full bg-gradient-to-r from-accent to-success"
// //                             />
// //                           </div>
// //                         </div>
// //                       ))}
// //                     </div>
// //                   )}

// //                   {msg.tips && msg.tips.length > 0 && (
// //                     <div className="mt-4 space-y-2">
// //                       <p className="text-xs font-semibold uppercase tracking-wider opacity-70">Clinical Advice</p>
// //                       {msg.tips.map((tip, i) => (
// //                         <p key={i} className="text-xs opacity-80 flex gap-2">
// //                           <span className="text-success">•</span> {tip}
// //                         </p>
// //                       ))}
// //                     </div>
// //                   )}

// //                   {msg.warning && (
// //                     <div className="mt-4 p-3 rounded-xl bg-destructive/10 border border-destructive/20 flex gap-2 items-start">
// //                       <AlertCircle size={14} className="text-destructive shrink-0 mt-0.5" />
// //                       <p className="text-[11px] text-destructive font-semibold leading-tight">{msg.warning}</p>
// //                     </div>
// //                   )}
// //                 </div>
// //                 {msg.role === "user" && (
// //                   <div className="w-8 h-8 rounded-full bg-secondary flex items-center justify-center flex-shrink-0 mt-1">
// //                     <User size={16} className="text-foreground" />
// //                   </div>
// //                 )}
// //               </motion.div>
// //             ))}
// //           </AnimatePresence>
// //           {typing && <div className="flex gap-3 items-start"><Bot size={16} /><div className="glass-strong rounded-2xl px-4 py-3 animate-pulse italic text-sm">Thinking...</div></div>}
// //           <div ref={endRef} />
// //         </div>

// //         <div className="glass-strong rounded-2xl p-3 flex items-center gap-3">
// //           <input
// //             type="text"
// //             value={input}
// //             onChange={(e) => setInput(e.target.value)}
// //             onKeyDown={(e) => e.key === "Enter" && handleSend()}
// //             placeholder="Describe symptoms (e.g. headache, high fever)..."
// //             className="flex-1 bg-transparent outline-none px-2 text-sm text-foreground"
// //           />
// //           <button
// //             onClick={handleSend}
// //             disabled={!input.trim() || typing}
// //             className="w-10 h-10 rounded-xl bg-gradient-to-r from-primary to-accent flex items-center justify-center text-accent-foreground hover:scale-105 active:scale-95 transition-all disabled:opacity-50"
// //           >
// //             <Send size={16} />
// //           </button>
// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default TriageChat;


// import { useState, useRef, useEffect } from "react";
// import { motion, AnimatePresence } from "framer-motion";
// import { Send, Bot, User, Sparkles, Save, AlertCircle, CheckCircle, Loader2, CalendarDays } from "lucide-react"; // Added CalendarDays icon
// import DashboardLayout from "@/components/DashboardLayout";
// import { patientService } from "@/services/patientService";
// import { useNavigate } from "react-router-dom"; // Added useNavigate for the bridge
// import api from "@/lib/api"; 


// import { Button } from "@/components/ui/button"; // FIX: This removes the red line error

// interface Disease {
//   name: string;
//   confidence: number;
// }

// interface Message {
//   id: number;
//   role: "user" | "ai";
//   text: string;
//   diseases?: Disease[];
//   tips?: string[];
//   warning?: string;
//   deptId?: string;   // Added to store recommended dept for the button
//   deptName?: string; // Added to store recommended dept name
// }

// const TriageChat = () => {
//   const navigate = useNavigate(); // Hook for navigation bridge
//   const [messages, setMessages] = useState<Message[]>([
//     { id: 0, role: "ai", text: "Hello! I'm your AI health assistant. Describe your symptoms and I'll provide a clinical analysis." },
//   ]);
//   const [input, setInput] = useState("");
//   const [typing, setTyping] = useState(false);
  
//   const [lastResult, setLastResult] = useState<any>(null);
//   const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">("idle");
  
//   const endRef = useRef<HTMLDivElement>(null);

//   useEffect(() => {
//     endRef.current?.scrollIntoView({ behavior: "smooth" });
//   }, [messages, typing]);

//   const handleSend = async () => {
//     if (!input.trim()) return;

//     const userMsg: Message = { id: Date.now(), role: "user", text: input };
//     setMessages((prev) => [...prev, userMsg]);
//     const currentInput = input;
//     setInput("");
//     setTyping(true);
//     setSaveStatus("idle"); 

//     try {
//       const symptomsList = currentInput.split(',').map(s => s.trim()).filter(s => s !== "");
//       const data = await patientService.analyzeSymptoms(symptomsList);

//       const isGuardrail = data.predictedDisease === "Needs More Detail" || data.confidence === 0;

//       if (!isGuardrail) {
//         setLastResult({
//           symptoms: currentInput,
//           disease: data.predictedDisease,
//           confidence: data.confidence,
//           tips: data.preventionTips,
//           deptId: data.recommendedDepartmentId, // Store for the "Save" metadata
//           deptName: data.recommendedDepartment
//         });
//       }

//       const allPredictions: Disease[] = !isGuardrail ? [
//         { name: data.predictedDisease, confidence: Math.round(data.confidence * 100) },
//         ...(data.otherSuggestions || [])
//       ] : [];

//       const aiResponse: Message = {
//         id: Date.now(),
//         role: "ai",
//         text: isGuardrail 
//           ? "I need a bit more detail to give you an accurate analysis."
//           : `Analysis complete. Based on your symptoms, the most likely condition is ${data.predictedDisease}. I recommend visiting the ${data.recommendedDepartment} department.`,
//         diseases: allPredictions,
//         tips: data.preventionTips,
//         warning: data.redFlagWarning,
//         deptId: data.recommendedDepartmentId, // Attach for the specific message button
//         deptName: data.recommendedDepartment
//       };

//       setMessages((prev) => [...prev, aiResponse]);
//     } catch (error) {
//       console.error("Triage Error:", error);
//       setMessages((prev) => [...prev, { 
//         id: Date.now(), 
//         role: "ai", 
//         text: "I apologize, but I'm having trouble reaching the analysis engine." 
//       }]);
//     } finally {
//       setTyping(false);
//     }
//   };

//   const handleSaveToRecalls = async () => {
//     if (!lastResult || saveStatus !== "idle") return;

//     const token = localStorage.getItem("accessToken");
//     const patientId = localStorage.getItem("userId");

//     if (!patientId || !token || patientId === "undefined") {
//         alert("Session error. Please log out and log in again.");
//         return;
//     }

//     setSaveStatus("saving");
//     try {
//       await api.post(
//         `/triage/history/save/${patientId}`, 
//         lastResult.tips, 
//         { 
//           params: { 
//             disease: lastResult.disease,
//             confidence: lastResult.confidence,
//             symptoms: lastResult.symptoms 
//           }
//         }
//       );

//       setSaveStatus("saved");
//       setTimeout(() => setSaveStatus("idle"), 4000);
//     } catch (error) {
//       console.error("Save failed:", error);
//       setSaveStatus("idle");
//       alert("Verification failed. Please ensure your session is active.");
//     }
//   };

//   // Bridge function to navigate to Booking page with filter state
//   const handleBookSpecialist = (deptId: string, deptName: string) => {
//     navigate("/patient/book-appointment", { 
//       state: { 
//         recommendedDeptId: deptId,
//         recommendedDeptName: deptName 
//       } 
//     });
//   };

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-3xl mx-auto h-[calc(100vh-8rem)] flex flex-col">
//         <div className="flex items-center justify-between mb-4">
//           <div>
//             <h1 className="font-display text-2xl font-bold text-foreground flex items-center gap-2">
//               <Sparkles size={22} className="text-accent" /> AI Triage
//             </h1>
//             <p className="text-sm text-muted-foreground">ML-Driven Symptom Analysis & Clinical Advice</p>
//           </div>
          
//           <button 
//             onClick={handleSaveToRecalls}
//             disabled={!lastResult || saveStatus !== "idle"}
//             className={`glass rounded-xl px-4 py-2 text-sm font-medium transition-all flex items-center gap-2 ${
//               saveStatus === "saved" ? "text-success border-success/50" : "text-foreground hover:shadow-glow-accent"
//             } disabled:opacity-30`}
//           >
//             {saveStatus === "saving" ? <Loader2 size={14} className="animate-spin text-accent" /> : 
//              saveStatus === "saved" ? <CheckCircle size={14} className="text-success" /> : <Save size={14} />}
//             {saveStatus === "saving" ? "Saving..." : saveStatus === "saved" ? "Saved to Timeline" : "Save to Recalls"}
//           </button>
//         </div>

//         <div className="flex-1 glass rounded-2xl p-4 overflow-y-auto space-y-4 mb-4">
//           <AnimatePresence>
//             {messages.map((msg) => (
//               <motion.div
//                 key={msg.id}
//                 initial={{ opacity: 0, y: 10, scale: 0.95 }}
//                 animate={{ opacity: 1, y: 0, scale: 1 }}
//                 className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
//               >
//                 {msg.role === "ai" && (
//                   <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center flex-shrink-0 mt-1">
//                     <Bot size={16} className="text-accent-foreground" />
//                   </div>
//                 )}
//                 <div className={`max-w-[80%] ${msg.role === "user" ? "bg-gradient-to-r from-primary to-accent text-accent-foreground" : "glass-strong"} rounded-2xl p-4`}>
//                   <p className="text-sm leading-relaxed">{msg.text}</p>

//                   {/* Top 3 Prediction Bars */}
//                   {msg.diseases && msg.diseases.length > 0 && (
//                     <div className="mt-4 space-y-3">
//                       <p className="text-xs font-semibold uppercase tracking-wider opacity-70">ML Prediction Confidence</p>
//                       {msg.diseases.map((d) => (
//                         <div key={d.name} className="space-y-1">
//                           <div className="flex justify-between text-xs">
//                             <span className="font-medium">{d.name}</span>
//                             <span>{d.confidence}%</span>
//                           </div>
//                           <div className="w-full h-2 rounded-full bg-foreground/10 overflow-hidden">
//                             <motion.div
//                               initial={{ width: 0 }}
//                               animate={{ width: `${d.confidence}%` }}
//                               transition={{ duration: 1, delay: 0.3 }}
//                               className="h-full rounded-full bg-gradient-to-r from-accent to-success"
//                             />
//                           </div>
//                         </div>
//                       ))}
//                     </div>
//                   )}

//                   {/* Preventive Advice */}
//                   {msg.tips && msg.tips.length > 0 && (
//                     <div className="mt-4 space-y-2">
//                       <p className="text-xs font-semibold uppercase tracking-wider opacity-70">Clinical Advice</p>
//                       {msg.tips.map((tip, i) => (
//                         <p key={i} className="text-xs opacity-80 flex gap-2">
//                           <span className="text-success">•</span> {tip}
//                         </p>
//                       ))}
//                     </div>
//                   )}

//                   {/* Specialist Booking Bridge Button */}
//                   {msg.deptId && (
//                     <div className="mt-6 pt-4 border-t border-white/10">
//                        <p className="text-[10px] text-muted-foreground mb-3 uppercase tracking-widest font-bold">Recommended Specialist</p>
//                        <Button 
//                          onClick={() => handleBookSpecialist(msg.deptId!, msg.deptName!)}
//                          className="w-full bg-accent text-accent-foreground hover:shadow-glow-accent transition-all flex items-center justify-center gap-2 py-5 rounded-xl font-bold text-xs"
//                        >
//                          <CalendarDays size={16} />
//                          Book {msg.deptName} Specialist
//                        </Button>
//                     </div>
//                   )}

//                   {/* Red Flag Warning */}
//                   {msg.warning && (
//                     <div className="mt-4 p-3 rounded-xl bg-destructive/10 border border-destructive/20 flex gap-2 items-start">
//                       <AlertCircle size={14} className="text-destructive shrink-0 mt-0.5" />
//                       <p className="text-[11px] text-destructive font-semibold leading-tight">{msg.warning}</p>
//                     </div>
//                   )}
//                 </div>
//                 {msg.role === "user" && (
//                   <div className="w-8 h-8 rounded-full bg-secondary flex items-center justify-center flex-shrink-0 mt-1">
//                     <User size={16} className="text-foreground" />
//                   </div>
//                 )}
//               </motion.div>
//             ))}
//           </AnimatePresence>
//           {typing && <div className="flex gap-3 items-start"><Bot size={16} /><div className="glass-strong rounded-2xl px-4 py-3 animate-pulse italic text-sm">Thinking...</div></div>}
//           <div ref={endRef} />
//         </div>

//         <div className="glass-strong rounded-2xl p-3 flex items-center gap-3">
//           <input
//             type="text"
//             value={input}
//             onChange={(e) => setInput(e.target.value)}
//             onKeyDown={(e) => e.key === "Enter" && handleSend()}
//             placeholder="Describe symptoms (e.g. headache, high fever)..."
//             className="flex-1 bg-transparent outline-none px-2 text-sm text-foreground"
//           />
//           <button
//             onClick={handleSend}
//             disabled={!input.trim() || typing}
//             className="w-10 h-10 rounded-xl bg-gradient-to-r from-primary to-accent flex items-center justify-center text-accent-foreground hover:scale-105 active:scale-95 transition-all disabled:opacity-50"
//           >
//             <Send size={16} />
//           </button>
//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default TriageChat;



import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Send, Bot, User, Sparkles, Save, AlertCircle, CheckCircle, Loader2, CalendarDays } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import { patientService } from "@/services/patientService";
import { useNavigate } from "react-router-dom"; 
import api from "@/lib/api"; 
import { Button } from "@/components/ui/button"; 

interface Disease {
  name: string;
  confidence: number;
}

interface Message {
  id: number;
  role: "user" | "ai";
  text: string;
  diseases?: Disease[];
  tips?: string[];
  warning?: string;
  deptId?: string;   
  deptName?: string; 
}

const TriageChat = () => {
  const navigate = useNavigate(); 
  const [messages, setMessages] = useState<Message[]>([
    { id: 0, role: "ai", text: "Hello! I'm your AI health assistant. Describe your symptoms and I'll provide a clinical analysis." },
  ]);
  const [input, setInput] = useState("");
  const [typing, setTyping] = useState(false);
  
  const [lastResult, setLastResult] = useState<any>(null);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">("idle");
  
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, typing]);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMsg: Message = { id: Date.now(), role: "user", text: input };
    setMessages((prev) => [...prev, userMsg]);
    const currentInput = input;
    setInput("");
    setTyping(true);
    setSaveStatus("idle"); 

    try {
      const symptomsList = currentInput.split(',').map(s => s.trim()).filter(s => s !== "");
      const data = await patientService.analyzeSymptoms(symptomsList);

      const isGuardrail = data.predictedDisease === "Needs More Detail" || data.confidence === 0;

      if (!isGuardrail) {
        setLastResult({
          symptoms: currentInput,
          disease: data.predictedDisease,
          confidence: data.confidence,
          tips: data.preventionTips,
          deptId: data.recommendedDepartmentId,
          deptName: data.recommendedDepartment
        });
      }

      const allPredictions: Disease[] = !isGuardrail ? [
        { name: data.predictedDisease, confidence: Math.round(data.confidence * 100) },
        ...(data.otherSuggestions || [])
      ] : [];

      const aiResponse: Message = {
        id: Date.now(),
        role: "ai",
        text: isGuardrail 
          ? "I need a bit more detail to give you an accurate analysis."
          : `Analysis complete. Based on your symptoms, the most likely condition is ${data.predictedDisease}. I recommend visiting the ${data.recommendedDepartment} department.`,
        diseases: allPredictions,
        tips: data.preventionTips,
        warning: data.redFlagWarning,
        deptId: data.recommendedDepartmentId, 
        deptName: data.recommendedDepartment
      };

      setMessages((prev) => [...prev, aiResponse]);
    } catch (error) {
      console.error("Triage Error:", error);
      setMessages((prev) => [...prev, { 
        id: Date.now(), 
        role: "ai", 
        text: "I apologize, but I'm having trouble reaching the analysis engine." 
      }]);
    } finally {
      setTyping(false);
    }
  };

  const handleSaveToRecalls = async () => {
    if (!lastResult || saveStatus !== "idle") return;

    const token = localStorage.getItem("accessToken");
    const patientId = localStorage.getItem("userId");

    if (!patientId || !token || patientId === "undefined") {
        alert("Session error. Please log out and log in again.");
        return;
    }

    setSaveStatus("saving");
    try {
      await api.post(
        `/triage/history/save/${patientId}`, 
        lastResult.tips, 
        { 
          params: { 
            disease: lastResult.disease,
            confidence: lastResult.confidence,
            symptoms: lastResult.symptoms 
          }
        }
      );

      setSaveStatus("saved");
      setTimeout(() => setSaveStatus("idle"), 4000);
    } catch (error) {
      console.error("Save failed:", error);
      setSaveStatus("idle");
      alert("Verification failed. Please ensure your session is active.");
    }
  };

  /**
   * BRIDGE NAVIGATION FIX
   * Changed from '/patient/book-appointment' to '/patient/book' to match App.tsx
   */
  const handleBookSpecialist = (deptId: string, deptName: string) => {
    navigate("/patient/book", { 
      state: { 
        recommendedDeptId: deptId,
        recommendedDeptName: deptName 
      } 
    });
  };

  return (
    <DashboardLayout role="patient">
      <div className="max-w-3xl mx-auto h-[calc(100vh-8rem)] flex flex-col">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="font-display text-2xl font-bold text-foreground flex items-center gap-2">
              <Sparkles size={22} className="text-accent" /> AI Triage
            </h1>
            <p className="text-sm text-muted-foreground">ML-Driven Analysis & Clinical Advice</p>
          </div>
          
          <button 
            onClick={handleSaveToRecalls}
            disabled={!lastResult || saveStatus !== "idle"}
            className={`glass rounded-xl px-4 py-2 text-sm font-medium transition-all flex items-center gap-2 ${
              saveStatus === "saved" ? "text-success border-success/50" : "text-foreground hover:shadow-glow-accent"
            } disabled:opacity-30`}
          >
            {saveStatus === "saving" ? <Loader2 size={14} className="animate-spin text-accent" /> : 
             saveStatus === "saved" ? <CheckCircle size={14} className="text-success" /> : <Save size={14} />}
            {saveStatus === "saving" ? "Saving..." : saveStatus === "saved" ? "Saved to Timeline" : "Save to Recalls"}
          </button>
        </div>

        <div className="flex-1 glass rounded-2xl p-4 overflow-y-auto space-y-4 mb-4">
          <AnimatePresence>
            {messages.map((msg) => (
              <motion.div
                key={msg.id}
                initial={{ opacity: 0, y: 10, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
              >
                {msg.role === "ai" && (
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center flex-shrink-0 mt-1">
                    <Bot size={16} className="text-accent-foreground" />
                  </div>
                )}
                <div className={`max-w-[80%] ${msg.role === "user" ? "bg-gradient-to-r from-primary to-accent text-accent-foreground" : "glass-strong"} rounded-2xl p-4 shadow-float`}>
                  <p className="text-sm leading-relaxed">{msg.text}</p>

                  {/* ML Confidence bars */}
                  {msg.diseases && msg.diseases.length > 0 && (
                    <div className="mt-4 space-y-3">
                      <p className="text-[10px] font-bold uppercase tracking-wider opacity-60">Confidence Score</p>
                      {msg.diseases.map((d) => (
                        <div key={d.name} className="space-y-1">
                          <div className="flex justify-between text-[10px] font-bold">
                            <span>{d.name}</span>
                            <span>{d.confidence}%</span>
                          </div>
                          <div className="w-full h-1.5 rounded-full bg-foreground/10 overflow-hidden">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${d.confidence}%` }}
                              transition={{ duration: 1, delay: 0.3 }}
                              className="h-full rounded-full bg-gradient-to-r from-accent to-success"
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Specialist Bridge Action */}
                  {msg.deptId && (
                    <div className="mt-6 pt-4 border-t border-white/5">
                       <Button 
                         onClick={() => handleBookSpecialist(msg.deptId!, msg.deptName!)}
                         className="w-full bg-accent text-accent-foreground hover:shadow-glow-accent py-5 rounded-xl font-bold text-xs"
                       >
                         <CalendarDays size={16} className="mr-2" />
                         Book {msg.deptName} Specialist
                       </Button>
                    </div>
                  )}

                  {msg.warning && (
                    <div className="mt-4 p-3 rounded-xl bg-destructive/10 border border-destructive/20 flex gap-2 items-start">
                      <AlertCircle size={14} className="text-destructive shrink-0 mt-0.5" />
                      <p className="text-[10px] text-destructive font-semibold">{msg.warning}</p>
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
          {typing && <div className="flex gap-3 items-start"><Bot size={16} /><div className="glass rounded-2xl px-4 py-3 animate-pulse italic text-sm">Analyzing...</div></div>}
          <div ref={endRef} />
        </div>

        <div className="glass-strong rounded-2xl p-3 flex items-center gap-3">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder="Describe symptoms..."
            className="flex-1 bg-transparent outline-none px-2 text-sm text-foreground"
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || typing}
            className="w-10 h-10 rounded-xl bg-gradient-to-r from-primary to-accent flex items-center justify-center text-accent-foreground hover:scale-105 active:scale-95 transition-all disabled:opacity-50"
          >
            <Send size={16} />
          </button>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default TriageChat;