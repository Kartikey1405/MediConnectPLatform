

// // // // // // import { useState, useEffect } from "react";
// // // // // // import { motion, AnimatePresence } from "framer-motion";
// // // // // // import { Search, Star, Calendar, Clock, CreditCard, Check, ArrowRight, ArrowLeft, Loader2, Hospital, BadgeCheck, User } from "lucide-react";
// // // // // // import { Button } from "@/components/ui/button";
// // // // // // import { useLocation, useNavigate } from "react-router-dom"; 
// // // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // // import GlassCard from "@/components/GlassCard";
// // // // // // import api from "@/lib/api"; 

// // // // // // // RESTORED: Profile step added back to the flow
// // // // // // type Step = "search" | "profile" | "slot" | "payment" | "success";

// // // // // // const BookAppointment = () => {
// // // // // //   const location = useLocation();
// // // // // //   const navigate = useNavigate();
// // // // // //   const initialDeptId = location.state?.recommendedDeptId;
// // // // // //   const initialDeptName = location.state?.recommendedDeptName;

// // // // // //   const [step, setStep] = useState<Step>("search");
// // // // // //   const [search, setSearch] = useState("");
// // // // // //   const [doctors, setDoctors] = useState<any[]>([]);
// // // // // //   const [slots, setSlots] = useState<any[]>([]);
// // // // // //   const [selectedDoctor, setSelectedDoctor] = useState<any>(null);
// // // // // //   const [selectedSlot, setSelectedSlot] = useState<any>(null);
// // // // // //   const [loading, setLoading] = useState(true);
// // // // // //   const [processing, setProcessing] = useState(false);

// // // // // //   useEffect(() => {
// // // // // //     const fetchDoctors = async () => {
// // // // // //       try {
// // // // // //         setLoading(true);
// // // // // //         const endpoint = initialDeptId 
// // // // // //           ? `/public/doctors/department/${initialDeptId}` 
// // // // // //           : `/public/doctors/all`; 
// // // // // //         const res = await api.get(endpoint);
// // // // // //         setDoctors(res.data);
// // // // // //       } catch (err) {
// // // // // //         console.error("Fetch failed", err);
// // // // // //       } finally { setLoading(false); }
// // // // // //     };
// // // // // //     fetchDoctors();
// // // // // //   }, [initialDeptId]);

// // // // // //   useEffect(() => {
// // // // // //     if (selectedDoctor && step === "slot") {
// // // // // //       const fetchSlots = async () => {
// // // // // //         try {
// // // // // //           const res = await api.get(`/public/doctors/${selectedDoctor.id}/available-slots`);
// // // // // //           setSlots(res.data); 
// // // // // //         } catch (err) { console.error("Slots fetch error", err); }
// // // // // //       };
// // // // // //       fetchSlots();
// // // // // //     }
// // // // // //   }, [selectedDoctor, step]);

// // // // // //   const handleConfirmPayment = async () => {
// // // // // //     setProcessing(true);
// // // // // //     try {
// // // // // //       const patientId = localStorage.getItem("userId");
// // // // // //       await api.post(`/payments/verify`, {
// // // // // //         slotId: selectedSlot.id,
// // // // // //         patientId: patientId,
// // // // // //         amount: selectedDoctor.consultationFee
// // // // // //       });
// // // // // //       setStep("success");
// // // // // //     } catch (err) {
// // // // // //       alert("Booking failed. Check your connection.");
// // // // // //     } finally { setProcessing(false); }
// // // // // //   };

// // // // // //   const filteredDoctors = doctors.filter((d) =>
// // // // // //     d.fullName.toLowerCase().includes(search.toLowerCase()) ||
// // // // // //     d.specialization.toLowerCase().includes(search.toLowerCase())
// // // // // //   );

// // // // // //   return (
// // // // // //     <DashboardLayout role="patient">
// // // // // //       <div className="max-w-4xl mx-auto">
// // // // // //         <AnimatePresence mode="wait">
          
// // // // // //           {/* STEP 1: SEARCH */}
// // // // // //           {step === "search" && (
// // // // // //             <motion.div key="search" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // // // // //               <div className="mb-8">
// // // // // //                 <h1 className="font-display text-3xl font-bold text-foreground">
// // // // // //                   {initialDeptName ? `Specialists for ${initialDeptName}` : "Find a Specialist"}
// // // // // //                 </h1>
// // // // // //               </div>

// // // // // //               {loading ? (
// // // // // //                 <div className="text-center py-20"><Loader2 className="animate-spin mx-auto text-accent" size={32} /></div>
// // // // // //               ) : (
// // // // // //                 <div className="grid md:grid-cols-2 gap-4">
// // // // // //                   {filteredDoctors.map((doc) => (
// // // // // //                     <GlassCard key={doc.id} className="p-0 overflow-hidden cursor-pointer hover:border-accent/30 transition-all">
// // // // // //                       {/* FIX: onClick moved to internal div to avoid GlassCard red line */}
// // // // // //                       <div className="p-5" onClick={() => { setSelectedDoctor(doc); setStep("profile"); }}>
// // // // // //                         <div className="flex items-center gap-3">
// // // // // //                           <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold text-xl">{doc.fullName.charAt(0)}</div>
// // // // // //                           <div className="flex-1">
// // // // // //                             <h3 className="font-display font-bold text-foreground">{doc.fullName}</h3>
// // // // // //                             <p className="text-xs text-muted-foreground">{doc.specialization}</p>
// // // // // //                           </div>
// // // // // //                           <div className="text-accent text-sm font-bold">${doc.consultationFee}</div>
// // // // // //                         </div>
// // // // // //                       </div>
// // // // // //                     </GlassCard>
// // // // // //                   ))}
// // // // // //                 </div>
// // // // // //               )}
// // // // // //             </motion.div>
// // // // // //           )}

// // // // // //           {/* STEP 2: PROFILE VIEW */}
// // // // // //           {step === "profile" && selectedDoctor && (
// // // // // //             <motion.div key="profile" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // // // // //               <button onClick={() => setStep("search")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6"><ArrowLeft size={16}/> Back to search</button>
// // // // // //               <GlassCard className="p-8">
// // // // // //                 <div className="flex flex-col md:flex-row gap-6 items-center md:items-start">
// // // // // //                   <div className="w-24 h-24 rounded-3xl bg-accent/10 flex items-center justify-center text-accent font-bold text-4xl">{selectedDoctor.fullName.charAt(0)}</div>
// // // // // //                   <div className="flex-1 text-center md:text-left">
// // // // // //                     <h2 className="text-2xl font-bold text-foreground mb-2">{selectedDoctor.fullName}</h2>
// // // // // //                     <p className="text-muted-foreground mb-6">{selectedDoctor.specialization} · {selectedDoctor.hospitalName}</p>
// // // // // //                     <Button onClick={() => setStep("slot")} className="bg-accent text-accent-foreground px-10 py-6 rounded-xl font-bold">
// // // // // //                        Book Consultation <ArrowRight className="ml-2" size={18} />
// // // // // //                     </Button>
// // // // // //                   </div>
// // // // // //                 </div>
// // // // // //               </GlassCard>
// // // // // //             </motion.div>
// // // // // //           )}

// // // // // //           {/* STEP 3: SLOTS */}
// // // // // //           {step === "slot" && (
// // // // // //             <motion.div key="slot" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>
// // // // // //               <button onClick={() => setStep("profile")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6"><ArrowLeft size={16}/> Back to profile</button>
// // // // // //               <h2 className="font-display text-2xl font-bold mb-6 flex items-center gap-2"><Calendar className="text-accent" /> Available Slots</h2>
// // // // // //               <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
// // // // // //                 {slots.length > 0 ? slots.map((s) => (
// // // // // //                   <button key={s.id} onClick={() => setSelectedSlot(s)} className={`glass rounded-xl py-4 text-sm transition-all ${selectedSlot?.id === s.id ? "ring-2 ring-accent text-accent shadow-glow-accent" : "text-foreground"}`}>
// // // // // //                     {new Date(s.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // // // // //                   </button>
// // // // // //                 )) : <p className="text-muted-foreground italic">No available slots found.</p>}
// // // // // //               </div>
// // // // // //               <Button onClick={() => setStep("payment")} disabled={!selectedSlot} className="bg-accent px-12 py-6 rounded-xl font-bold">Confirm Selection</Button>
// // // // // //             </motion.div>
// // // // // //           )}

// // // // // //           {/* Step 4 & 5 (Payment & Success) remain standard */}
// // // // // //           {step === "success" && (
// // // // // //             <div className="text-center py-20">
// // // // // //               <Check size={48} className="text-success mx-auto mb-4" />
// // // // // //               <h2 className="text-3xl font-bold">Booking Confirmed!</h2>
// // // // // //               <Button onClick={() => navigate("/patient/consultations")} className="mt-8">View My Appointments</Button>
// // // // // //             </div>
// // // // // //           )}
// // // // // //         </AnimatePresence>
// // // // // //       </div>
// // // // // //     </DashboardLayout>
// // // // // //   );
// // // // // // };

// // // // // // export default BookAppointment;



































// // // // // import { useState, useEffect } from "react";
// // // // // import { motion, AnimatePresence } from "framer-motion";
// // // // // import { Search, Calendar, Clock, CreditCard, Check, ArrowRight, ArrowLeft, Loader2, Hospital, BadgeCheck } from "lucide-react";
// // // // // import { Button } from "@/components/ui/button";
// // // // // import { useLocation, useNavigate } from "react-router-dom"; 
// // // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // // import GlassCard from "@/components/GlassCard";
// // // // // import api from "@/lib/api"; 
// // // // // import { toast } from "sonner";

// // // // // type Step = "search" | "profile" | "slot" | "payment" | "success";

// // // // // const BookAppointment = () => {
// // // // //   const location = useLocation();
// // // // //   const navigate = useNavigate();
// // // // //   const initialDeptId = location.state?.recommendedDeptId;
  
// // // // //   const [step, setStep] = useState<Step>("search");
// // // // //   const [search, setSearch] = useState("");
// // // // //   const [doctors, setDoctors] = useState<any[]>([]);
// // // // //   const [slots, setSlots] = useState<any[]>([]);
// // // // //   const [selectedDoctor, setSelectedDoctor] = useState<any>(null);
// // // // //   const [selectedSlot, setSelectedSlot] = useState<any>(null);
// // // // //   const [loading, setLoading] = useState(true);
// // // // //   const [processing, setProcessing] = useState(false);

// // // // //   // Load Razorpay Script
// // // // //   useEffect(() => {
// // // // //     const script = document.createElement("script");
// // // // //     script.src = "https://checkout.razorpay.com/v1/checkout.js";
// // // // //     script.async = true;
// // // // //     document.body.appendChild(script);
// // // // //   }, []);

// // // // //   useEffect(() => {
// // // // //     const fetchDoctors = async () => {
// // // // //       try {
// // // // //         setLoading(true);
// // // // //         const endpoint = initialDeptId ? `/public/doctors/department/${initialDeptId}` : `/public/doctors/all`; 
// // // // //         const res = await api.get(endpoint);
// // // // //         setDoctors(Array.isArray(res.data) ? res.data : []);
// // // // //       } catch (err) { console.error("Fetch failed", err); } finally { setLoading(false); }
// // // // //     };
// // // // //     fetchDoctors();
// // // // //   }, [initialDeptId]);

// // // // //   useEffect(() => {
// // // // //     if (selectedDoctor && step === "slot") {
// // // // //       const fetchSlots = async () => {
// // // // //         try {
// // // // //           const res = await api.get(`/public/doctors/${selectedDoctor.id}/available-slots`);
// // // // //           setSlots(Array.isArray(res.data) ? res.data : []); 
// // // // //         } catch (err) { console.error("Slots fetch error", err); }
// // // // //       };
// // // // //       fetchSlots();
// // // // //     }
// // // // //   }, [selectedDoctor, step]);

// // // // //   // --- RAZORPAY HANDLER ---
// // // // //   const handlePaymentFlow = async () => {
// // // // //     setProcessing(true);
// // // // //     try {
// // // // //       // Step 1: Create Order in Backend
// // // // //       const orderRes = await api.post(`/payments/create-order?slotId=${selectedSlot.id}&amount=${selectedDoctor.consultationFee}`);
// // // // //       const orderId = orderRes.data; // This is the Razorpay Order ID string

// // // // //       // Step 2: Open Razorpay Modal
// // // // //       const options = {
// // // // //         key: "YOUR_RAZORPAY_KEY_ID", // Replace with your test key
// // // // //         amount: selectedDoctor.consultationFee * 100,
// // // // //         currency: "INR",
// // // // //         name: "MediBot Healthcare",
// // // // //         description: `Consultation with Dr. ${selectedDoctor.fullName}`,
// // // // //         order_id: orderId,
// // // // //         handler: async (response: any) => {
// // // // //           try {
// // // // //             // Step 3: Verify Payment in Backend
// // // // //             await api.post("/payments/verify-payment", {
// // // // //               razorpay_order_id: response.razorpay_order_id,
// // // // //               razorpay_payment_id: response.razorpay_payment_id,
// // // // //               razorpay_signature: response.razorpay_signature
// // // // //             });
// // // // //             setStep("success");
// // // // //             toast.success("Consultation Booked!");
// // // // //           } catch (err) {
// // // // //             toast.error("Payment verification failed.");
// // // // //           }
// // // // //         },
// // // // //         theme: { color: "#0EA5E9" } // Matches your primary accent
// // // // //       };

// // // // //       const rzp = (window as any).Razorpay(options);
// // // // //       rzp.open();

// // // // //     } catch (err) {
// // // // //       toast.error("Failed to initialize payment. Slot might be locked.");
// // // // //     } finally {
// // // // //       setProcessing(false);
// // // // //     }
// // // // //   };

// // // // //   const filteredDoctors = doctors.filter((d) =>
// // // // //     (d.fullName || "").toLowerCase().includes(search.toLowerCase()) ||
// // // // //     (d.specialization || "").toLowerCase().includes(search.toLowerCase())
// // // // //   );

// // // // //   return (
// // // // //     <DashboardLayout role="patient">
// // // // //       <div className="max-w-4xl mx-auto">
// // // // //         <AnimatePresence mode="wait">
          
// // // // //           {/* STEP 1: DOCTOR SEARCH */}
// // // // //           {step === "search" && (
// // // // //             <motion.div key="search" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // // // //               <div className="mb-8">
// // // // //                 <h1 className="font-display text-3xl font-bold text-foreground">Find a Specialist</h1>
// // // // //                 <p className="text-muted-foreground mt-1">Select a verified professional for your consultation</p>
// // // // //               </div>
// // // // //               <div className="relative mb-6">
// // // // //                 <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
// // // // //                 <input type="text" placeholder="Search by name or specialty..." className="w-full pl-12 pr-4 py-4 glass rounded-2xl outline-none focus:ring-2 focus:ring-accent/50" value={search} onChange={(e) => setSearch(e.target.value)} />
// // // // //               </div>
// // // // //               {loading ? <div className="text-center py-20"><Loader2 className="animate-spin mx-auto text-accent" /></div> : (
// // // // //                 <div className="grid md:grid-cols-2 gap-4">
// // // // //                   {filteredDoctors.map((doc) => (
// // // // //                     <GlassCard key={doc.id} className="p-5 cursor-pointer hover:border-accent/30 transition-all" onClick={() => { setSelectedDoctor(doc); setStep("profile"); }}>
// // // // //                       <div className="flex items-center gap-3">
// // // // //                         <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold text-xl">{doc.fullName.charAt(0)}</div>
// // // // //                         <div className="flex-1">
// // // // //                           <h3 className="font-display font-bold text-foreground">{doc.fullName}</h3>
// // // // //                           <p className="text-xs text-muted-foreground">{doc.specialization}</p>
// // // // //                         </div>
// // // // //                         <div className="text-accent text-sm font-bold">₹{doc.consultationFee}</div>
// // // // //                       </div>
// // // // //                     </GlassCard>
// // // // //                   ))}
// // // // //                 </div>
// // // // //               )}
// // // // //             </motion.div>
// // // // //           )}

// // // // //           {/* STEP 2: PROFILE & CONFIRM */}
// // // // //           {step === "profile" && selectedDoctor && (
// // // // //             <motion.div key="profile" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // // // //               <button onClick={() => setStep("search")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6"><ArrowLeft size={16}/> Back</button>
// // // // //               <GlassCard className="p-8 text-center md:text-left">
// // // // //                 <div className="flex flex-col md:flex-row gap-6 items-center">
// // // // //                   <div className="w-24 h-24 rounded-3xl bg-accent/10 flex items-center justify-center text-accent font-bold text-4xl">{selectedDoctor.fullName.charAt(0)}</div>
// // // // //                   <div className="flex-1">
// // // // //                     <h2 className="text-2xl font-bold text-foreground">{selectedDoctor.fullName}</h2>
// // // // //                     <p className="text-muted-foreground mb-6">{selectedDoctor.specialization} · {selectedDoctor.hospitalName}</p>
// // // // //                     <Button onClick={() => setStep("slot")} className="bg-accent text-white px-10 py-6 rounded-xl font-bold">Check Availability <ArrowRight className="ml-2" size={18} /></Button>
// // // // //                   </div>
// // // // //                 </div>
// // // // //               </GlassCard>
// // // // //             </motion.div>
// // // // //           )}

// // // // //           {/* STEP 3: SLOT SELECTION */}
// // // // //           {step === "slot" && (
// // // // //             <motion.div key="slot" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>
// // // // //               <button onClick={() => setStep("profile")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6"><ArrowLeft size={16}/> Back</button>
// // // // //               <h2 className="font-display text-2xl font-bold mb-6 flex items-center gap-2"><Calendar className="text-accent" /> Available Slots</h2>
// // // // //               <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
// // // // //                 {slots.length > 0 ? slots.map((s) => (
// // // // //                   <button key={s.id} onClick={() => setSelectedSlot(s)} className={`glass rounded-xl py-4 text-sm transition-all ${selectedSlot?.id === s.id ? "ring-2 ring-accent text-accent shadow-glow-accent" : "text-foreground"}`}>
// // // // //                     {new Date(s.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // // // //                   </button>
// // // // //                 )) : <p className="text-muted-foreground italic">No slots available for today.</p>}
// // // // //               </div>
// // // // //               <Button onClick={() => setStep("payment")} disabled={!selectedSlot} className="bg-accent px-12 py-6 rounded-xl font-bold">Review Appointment</Button>
// // // // //             </motion.div>
// // // // //           )}

// // // // //           {/* STEP 4: PAYMENT SUMMARY */}
// // // // //           {step === "payment" && (
// // // // //             <motion.div key="payment" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
// // // // //               <GlassCard className="p-8 max-w-md mx-auto" tilt={false}>
// // // // //                 <div className="w-16 h-16 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-4"><CreditCard size={28} className="text-accent" /></div>
// // // // //                 <h2 className="font-display text-2xl font-bold text-center mb-6">Booking Summary</h2>
// // // // //                 <div className="glass rounded-xl p-4 mb-6 space-y-3 text-sm">
// // // // //                   <div className="flex justify-between"><span className="text-muted-foreground">Specialist</span><span className="font-bold">{selectedDoctor.fullName}</span></div>
// // // // //                   <div className="flex justify-between"><span className="text-muted-foreground">Time</span><span className="font-bold">{new Date(selectedSlot.startTime).toLocaleTimeString()}</span></div>
// // // // //                   <div className="border-t border-white/10 pt-3 flex justify-between"><span className="text-muted-foreground">Total Fee</span><span className="font-bold text-accent text-lg">₹{selectedDoctor.consultationFee}</span></div>
// // // // //                 </div>
// // // // //                 <Button onClick={handlePaymentFlow} disabled={processing} className="w-full bg-gradient-to-r from-primary to-accent py-7 rounded-xl font-bold shadow-glow-accent">
// // // // //                   {processing ? <Loader2 className="animate-spin mr-2" /> : "Pay & Book Consultation"}
// // // // //                 </Button>
// // // // //               </GlassCard>
// // // // //             </motion.div>
// // // // //           )}

// // // // //           {/* STEP 5: SUCCESS */}
// // // // //           {step === "success" && (
// // // // //             <motion.div key="success" initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="text-center py-20">
// // // // //               <div className="w-20 h-20 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-6"><Check size={40} className="text-success" /></div>
// // // // //               <h2 className="font-display text-3xl font-bold text-foreground mb-2">Booking Confirmed!</h2>
// // // // //               <p className="text-muted-foreground mb-8">Redirecting to your dashboard to view your meeting link...</p>
// // // // //               <Button onClick={() => navigate("/patient/dashboard")} className="bg-success text-white px-10 py-6 rounded-xl font-bold">Go to Dashboard</Button>
// // // // //             </motion.div>
// // // // //           )}

// // // // //         </AnimatePresence>
// // // // //       </div>
// // // // //     </DashboardLayout>
// // // // //   );
// // // // // };

// // // // // export default BookAppointment;













// // // // import { useState, useEffect } from "react";
// // // // import { motion, AnimatePresence } from "framer-motion";
// // // // import { Search, Calendar, Clock, CreditCard, Check, ArrowRight, ArrowLeft, Loader2, BadgeCheck } from "lucide-react";
// // // // import { Button } from "@/components/ui/button";
// // // // import { useLocation, useNavigate } from "react-router-dom"; 
// // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // import GlassCard from "@/components/GlassCard";
// // // // import api from "@/lib/api"; 
// // // // import { toast } from "sonner";

// // // // // Use Vite environment variables for easy deployment handling
// // // // const RAZORPAY_KEY = import.meta.env.VITE_RAZORPAY_KEY_ID || "rzp_test_RqODjBUvVW2YIl";

// // // // type Step = "search" | "profile" | "slot" | "payment" | "success";

// // // // const BookAppointment = () => {
// // // //   const location = useLocation();
// // // //   const navigate = useNavigate();
// // // //   const initialDeptId = location.state?.recommendedDeptId;
// // // //   const initialDeptName = location.state?.recommendedDeptName;

// // // //   const [step, setStep] = useState<Step>("search");
// // // //   const [search, setSearch] = useState("");
// // // //   const [doctors, setDoctors] = useState<any[]>([]);
// // // //   const [slots, setSlots] = useState<any[]>([]);
// // // //   const [selectedDoctor, setSelectedDoctor] = useState<any>(null);
// // // //   const [selectedSlot, setSelectedSlot] = useState<any>(null);
// // // //   const [loading, setLoading] = useState(true);
// // // //   const [processing, setProcessing] = useState(false);

// // // //   // 1. Dynamically load Razorpay SDK
// // // //   useEffect(() => {
// // // //     const script = document.createElement("script");
// // // //     script.src = "https://checkout.razorpay.com/v1/checkout.js";
// // // //     script.async = true;
// // // //     document.body.appendChild(script);
// // // //   }, []);

// // // //   // 2. Fetch Doctors (Handles AI Recommendations or General Discovery)
// // // //   useEffect(() => {
// // // //     const fetchDoctors = async () => {
// // // //       try {
// // // //         setLoading(true);
// // // //         const endpoint = initialDeptId 
// // // //           ? `/public/doctors/department/${initialDeptId}` 
// // // //           : `/public/doctors/all`; 
// // // //         const res = await api.get(endpoint);
// // // //         setDoctors(Array.isArray(res.data) ? res.data : []);
// // // //       } catch (err) {
// // // //         console.error("Fetch failed", err);
// // // //         setDoctors([]);
// // // //       } finally { setLoading(false); }
// // // //     };
// // // //     fetchDoctors();
// // // //   }, [initialDeptId]);

// // // //   // 3. Fetch Available Slots for selected specialist
// // // //   useEffect(() => {
// // // //     if (selectedDoctor && step === "slot") {
// // // //       const fetchSlots = async () => {
// // // //         try {
// // // //           const res = await api.get(`/public/doctors/${selectedDoctor.id}/available-slots`);
// // // //           setSlots(Array.isArray(res.data) ? res.data : []); 
// // // //         } catch (err) { console.error("Slots fetch error", err); }
// // // //       };
// // // //       fetchSlots();
// // // //     }
// // // //   }, [selectedDoctor, step]);

// // // //   // --- HANDLER: RAZORPAY INTEGRATION ---
// // // //   const handlePaymentFlow = async () => {
// // // //     if (!selectedSlot || !selectedDoctor) return;
// // // //     setProcessing(true);
    
// // // //     try {
// // // //       // Step A: Create Order in Backend
// // // //       const orderRes = await api.post(`/payments/create-order?slotId=${selectedSlot.id}&amount=${selectedDoctor.consultationFee}`);
// // // //       const orderId = orderRes.data; 

// // // //       // Step B: Open Razorpay Modal
// // // //       const options = {
// // // //         key: RAZORPAY_KEY,
// // // //         amount: selectedDoctor.consultationFee * 100, // In paise
// // // //         currency: "INR",
// // // //         name: "MediBot Healthcare",
// // // //         description: `Consultation with Dr. ${selectedDoctor.fullName}`,
// // // //         order_id: orderId,
// // // //         handler: async (response: any) => {
// // // //           try {
// // // //             // Step C: Verify Payment & Confirm Booking in DB
// // // //             await api.post("/payments/verify-payment", {
// // // //               razorpay_order_id: response.razorpay_order_id,
// // // //               razorpay_payment_id: response.razorpay_payment_id,
// // // //               razorpay_signature: response.razorpay_signature
// // // //             });
// // // //             setStep("success");
// // // //             toast.success("Booking Confirmed!");
// // // //           } catch (err) {
// // // //             toast.error("Payment verification failed. Please contact support.");
// // // //           }
// // // //         },
// // // //         theme: { color: "#0EA5E9" },
// // // //         prefill: {
// // // //             email: JSON.parse(localStorage.getItem("user") || "{}").email || ""
// // // //         }
// // // //       };

// // // //       const rzp = (window as any).Razorpay(options);
// // // //       rzp.open();

// // // //     } catch (err: any) {
// // // //       toast.error(err.response?.data || "Transaction failed. Slot may be locked.");
// // // //     } finally {
// // // //       setProcessing(false);
// // // //     }
// // // //   };

// // // //   const filteredDoctors = doctors.filter((d) =>
// // // //     (d.fullName || "").toLowerCase().includes(search.toLowerCase()) ||
// // // //     (d.specialization || "").toLowerCase().includes(search.toLowerCase())
// // // //   );

// // // //   return (
// // // //     <DashboardLayout role="patient">
// // // //       <div className="max-w-4xl mx-auto">
// // // //         <AnimatePresence mode="wait">
          
// // // //           {/* STEP 1: SEARCH */}
// // // //           {step === "search" && (
// // // //             <motion.div key="search" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // // //               <div className="mb-8">
// // // //                 <h1 className="font-display text-3xl font-bold text-foreground">
// // // //                   {initialDeptName ? `Specialists for ${initialDeptName}` : "Find a Specialist"}
// // // //                 </h1>
// // // //                 <p className="text-muted-foreground mt-1">Select a verified professional for your consultation</p>
// // // //               </div>
// // // //               <div className="relative mb-6">
// // // //                 <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
// // // //                 <input type="text" placeholder="Search by name or specialty..." className="w-full pl-12 pr-4 py-4 glass rounded-2xl outline-none focus:ring-2 focus:ring-accent/50" value={search} onChange={(e) => setSearch(e.target.value)} />
// // // //               </div>
// // // //               {loading ? <div className="text-center py-20"><Loader2 className="animate-spin mx-auto text-accent" size={32} /></div> : (
// // // //                 <div className="grid md:grid-cols-2 gap-4">
// // // //                   {filteredDoctors.map((doc) => (
// // // //                     <GlassCard key={doc.id} className="p-0 overflow-hidden cursor-pointer hover:border-accent/30 transition-all">
// // // //                       <div className="p-5" onClick={() => { setSelectedDoctor(doc); setStep("profile"); }}>
// // // //                         <div className="flex items-center gap-3">
// // // //                           <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold text-xl">{doc.fullName?.charAt(0)}</div>
// // // //                           <div className="flex-1">
// // // //                             <h3 className="font-display font-bold text-foreground flex items-center gap-1">
// // // //                                 {doc.fullName} {doc.isVerified && <BadgeCheck size={14} className="text-accent" />}
// // // //                             </h3>
// // // //                             <p className="text-xs text-muted-foreground">{doc.specialization} · {doc.hospitalName}</p>
// // // //                           </div>
// // // //                           <div className="text-accent text-sm font-bold">₹{doc.consultationFee}</div>
// // // //                         </div>
// // // //                       </div>
// // // //                     </GlassCard>
// // // //                   ))}
// // // //                 </div>
// // // //               )}
// // // //             </motion.div>
// // // //           )}

// // // //           {/* STEP 2: DOCTOR PROFILE */}
// // // //           {step === "profile" && selectedDoctor && (
// // // //             <motion.div key="profile" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // // //               <button onClick={() => setStep("search")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to search</button>
// // // //               <GlassCard className="p-8">
// // // //                 <div className="flex flex-col md:flex-row gap-6 items-center md:items-start">
// // // //                   <div className="w-24 h-24 rounded-3xl bg-accent/10 flex items-center justify-center text-accent font-bold text-4xl">{selectedDoctor.fullName?.charAt(0)}</div>
// // // //                   <div className="flex-1 text-center md:text-left">
// // // //                     <h2 className="text-2xl font-bold text-foreground mb-2">{selectedDoctor.fullName}</h2>
// // // //                     <p className="text-muted-foreground mb-4">{selectedDoctor.specialization} · {selectedDoctor.hospitalName}</p>
// // // //                     <p className="text-sm text-muted-foreground leading-relaxed mb-6 italic">"{selectedDoctor.bio || 'Verified medical professional dedicated to patient care.'}"</p>
// // // //                     <Button onClick={() => setStep("slot")} className="bg-accent text-accent-foreground px-10 py-6 rounded-xl font-bold shadow-glow-accent">
// // // //                         Check Availability <ArrowRight className="ml-2" size={18} />
// // // //                     </Button>
// // // //                   </div>
// // // //                 </div>
// // // //               </GlassCard>
// // // //             </motion.div>
// // // //           )}

// // // //           {/* STEP 3: SLOTS */}
// // // //           {step === "slot" && (
// // // //             <motion.div key="slot" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>
// // // //               <button onClick={() => setStep("profile")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to profile</button>
// // // //               <h2 className="font-display text-2xl font-bold mb-6 flex items-center gap-2"><Calendar className="text-accent" /> Available Sessions</h2>
// // // //               <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
// // // //                 {slots.length > 0 ? slots.map((s) => (
// // // //                   <button key={s.id} onClick={() => setSelectedSlot(s)} className={`glass rounded-xl py-4 text-sm font-medium transition-all ${selectedSlot?.id === s.id ? "ring-2 ring-accent text-accent shadow-glow-accent scale-[1.02]" : "text-foreground hover:bg-white/5"}`}>
// // // //                     <Clock size={14} className="mx-auto mb-1 opacity-50" />
// // // //                     {new Date(s.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // // //                   </button>
// // // //                 )) : <p className="text-muted-foreground italic col-span-full text-center py-10">No available slots for today.</p>}
// // // //               </div>
// // // //               <Button onClick={() => setStep("payment")} disabled={!selectedSlot} className="bg-accent px-12 py-6 rounded-xl font-bold text-accent-foreground">Next: Summary</Button>
// // // //             </motion.div>
// // // //           )}

// // // //           {/* STEP 4: PAYMENT */}
// // // //           {step === "payment" && selectedSlot && (
// // // //             <motion.div key="payment" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
// // // //                <button onClick={() => setStep("slot")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Change Slot</button>
// // // //                <GlassCard className="p-8 max-w-md mx-auto" tilt={false}>
// // // //                   <div className="w-16 h-16 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-4"><CreditCard size={28} className="text-accent" /></div>
// // // //                   <h2 className="font-display text-2xl font-bold text-center mb-6">Confirm Booking</h2>
// // // //                   <div className="glass rounded-xl p-4 mb-6 space-y-3 text-sm">
// // // //                     <div className="flex justify-between"><span className="text-muted-foreground">Specialist</span><span className="font-bold">{selectedDoctor.fullName}</span></div>
// // // //                     <div className="flex justify-between"><span className="text-muted-foreground">Session</span><span className="font-bold">{new Date(selectedSlot.startTime).toLocaleTimeString()}</span></div>
// // // //                     <div className="border-t border-white/10 pt-3 flex justify-between font-bold text-accent text-lg"><span>Total Fee</span><span>₹{selectedDoctor.consultationFee}</span></div>
// // // //                   </div>
// // // //                   <Button onClick={handlePaymentFlow} disabled={processing} className="w-full bg-gradient-to-r from-primary to-accent py-7 rounded-xl font-bold shadow-glow-accent">
// // // //                     {processing ? <Loader2 className="animate-spin mr-2" /> : "Complete Secure Payment"}
// // // //                   </Button>
// // // //                </GlassCard>
// // // //             </motion.div>
// // // //           )}

// // // //           {/* STEP 5: SUCCESS */}
// // // //           {step === "success" && (
// // // //             <motion.div key="success" initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="text-center py-20">
// // // //               <div className="w-24 h-24 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-6"><Check size={48} className="text-success" /></div>
// // // //               <h2 className="font-display text-4xl font-bold text-foreground mb-3">Booking Confirmed!</h2>
// // // //               <p className="text-muted-foreground mb-10 max-w-sm mx-auto leading-relaxed">Your specialist is ready. You can find the secure meeting link in your dashboard now.</p>
// // // //               <Button onClick={() => navigate("/patient/dashboard")} className="bg-success text-white px-12 py-6 rounded-xl font-bold hover:scale-105 transition-all">Go to My Dashboard</Button>
// // // //             </motion.div>
// // // //           )}

// // // //         </AnimatePresence>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );
// // // // };
// // // // export default BookAppointment;

















// // // import { useState, useEffect } from "react";
// // // import { motion, AnimatePresence } from "framer-motion";
// // // import { Search, Calendar, Clock, CreditCard, Check, ArrowRight, ArrowLeft, Loader2, BadgeCheck } from "lucide-react";
// // // import { Button } from "@/components/ui/button";
// // // import { useLocation, useNavigate } from "react-router-dom"; 
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import GlassCard from "@/components/GlassCard";
// // // import api from "@/lib/api"; 
// // // import { toast } from "sonner";

// // // // Use Vite environment variables for easy deployment handling
// // // const RAZORPAY_KEY = import.meta.env.VITE_RAZORPAY_KEY_ID || "rzp_test_RqODjBUvVW2YIl";

// // // type Step = "search" | "profile" | "slot" | "payment" | "success";

// // // const BookAppointment = () => {
// // //   const location = useLocation();
// // //   const navigate = useNavigate();
  
// // //   // Bridge Logic: Extract AI recommendation state if coming from Triage Chat
// // //   const initialDeptId = location.state?.recommendedDeptId;
// // //   const initialDeptName = location.state?.recommendedDeptName;

// // //   const [step, setStep] = useState<Step>("search");
// // //   const [search, setSearch] = useState("");
// // //   const [doctors, setDoctors] = useState<any[]>([]);
// // //   const [slots, setSlots] = useState<any[]>([]);
// // //   const [selectedDoctor, setSelectedDoctor] = useState<any>(null);
// // //   const [selectedSlot, setSelectedSlot] = useState<any>(null);
// // //   const [loading, setLoading] = useState(true);
// // //   const [processing, setProcessing] = useState(false);

// // //   // 1. Dynamically load Razorpay SDK
// // //   useEffect(() => {
// // //     const script = document.createElement("script");
// // //     script.src = "https://checkout.razorpay.com/v1/checkout.js";
// // //     script.async = true;
// // //     document.body.appendChild(script);
// // //   }, []);

// // //   // 2. Fetch Doctors based on AI Recommendation or All Verified
// // //   useEffect(() => {
// // //     const fetchDoctors = async () => {
// // //       try {
// // //         setLoading(true);
// // //         const endpoint = initialDeptId 
// // //           ? `/public/doctors/department/${initialDeptId}` 
// // //           : `/public/doctors/all`; 
// // //         const res = await api.get(endpoint);
// // //         setDoctors(Array.isArray(res.data) ? res.data : []);
// // //       } catch (err) {
// // //         console.error("Fetch failed", err);
// // //         setDoctors([]);
// // //       } finally { setLoading(false); }
// // //     };
// // //     fetchDoctors();
// // //   }, [initialDeptId]);

// // //   // 3. Fetch Available Slots for selected specialist
// // //   useEffect(() => {
// // //     if (selectedDoctor && step === "slot") {
// // //       const fetchSlots = async () => {
// // //         try {
// // //           const res = await api.get(`/public/doctors/${selectedDoctor.id}/available-slots`);
// // //           setSlots(Array.isArray(res.data) ? res.data : []); 
// // //         } catch (err) { console.error("Slots fetch error", err); }
// // //       };
// // //       fetchSlots();
// // //     }
// // //   }, [selectedDoctor, step]);

// // //   // --- HANDLER: RAZORPAY INTEGRATION ---
// // //   const handlePaymentFlow = async () => {
// // //     if (!selectedSlot || !selectedDoctor) return;
// // //     setProcessing(true);
    
// // //     try {
// // //       // Step A: Create Order in Backend
// // //       const orderRes = await api.post(`/payments/create-order?slotId=${selectedSlot.id}&amount=${selectedDoctor.consultationFee}`);
// // //       const orderId = orderRes.data; 

// // //       // Step B: Open Razorpay Modal
// // //       const options = {
// // //         key: RAZORPAY_KEY,
// // //         amount: selectedDoctor.consultationFee * 100, // In paise
// // //         currency: "INR",
// // //         name: "MediBot Healthcare",
// // //         description: `Consultation with Dr. ${selectedDoctor.fullName}`,
// // //         order_id: orderId,
// // //         handler: async (response: any) => {
// // //           try {
// // //             // Step C: Verify Payment & Confirm Booking in DB
// // //             await api.post("/payments/verify-payment", {
// // //               razorpay_order_id: response.razorpay_order_id,
// // //               razorpay_payment_id: response.razorpay_payment_id,
// // //               razorpay_signature: response.razorpay_signature
// // //             });
// // //             setStep("success");
// // //             toast.success("Booking Confirmed!");
// // //           } catch (err) {
// // //             toast.error("Security verification failed. Please contact support.");
// // //           }
// // //         },
// // //         theme: { color: "#0EA5E9" },
// // //         prefill: {
// // //             email: JSON.parse(localStorage.getItem("user") || "{}").email || ""
// // //         }
// // //       };

// // //       const rzp = (window as any).Razorpay(options);
// // //       rzp.open();

// // //     } catch (err: any) {
// // //       toast.error(err.response?.data || "Transaction failed. Slot may be locked.");
// // //     } finally {
// // //       setProcessing(false);
// // //     }
// // //   };

// // //   const filteredDoctors = doctors.filter((d) =>
// // //     (d.fullName || "").toLowerCase().includes(search.toLowerCase()) ||
// // //     (d.specialization || "").toLowerCase().includes(search.toLowerCase())
// // //   );

// // //   return (
// // //     <DashboardLayout role="patient">
// // //       <div className="max-w-4xl mx-auto">
// // //         <AnimatePresence mode="wait">
          
// // //           {/* STEP 1: SEARCH */}
// // //           {step === "search" && (
// // //             <motion.div key="search" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // //               <div className="mb-8">
// // //                 <h1 className="font-display text-3xl font-bold text-foreground">
// // //                   {initialDeptName ? `Specialists for ${initialDeptName}` : "Find a Specialist"}
// // //                 </h1>
// // //                 <p className="text-muted-foreground mt-1">Select a verified professional for your consultation</p>
// // //               </div>
// // //               <div className="relative mb-6">
// // //                 <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
// // //                 <input type="text" placeholder="Search by name or specialty..." className="w-full pl-12 pr-4 py-4 glass rounded-2xl outline-none focus:ring-2 focus:ring-accent/50 transition-all" value={search} onChange={(e) => setSearch(e.target.value)} />
// // //               </div>
// // //               {loading ? <div className="text-center py-20"><Loader2 className="animate-spin mx-auto text-accent" size={32} /></div> : (
// // //                 <div className="grid md:grid-cols-2 gap-4">
// // //                   {filteredDoctors.map((doc) => (
// // //                     <GlassCard key={doc.id} className="p-0 overflow-hidden cursor-pointer hover:border-accent/30 transition-all">
// // //                       {/* FIX: Moved onClick into a div to solve GlassCard property error */}
// // //                       <div className="p-5" onClick={() => { setSelectedDoctor(doc); setStep("profile"); }}>
// // //                         <div className="flex items-center gap-3">
// // //                           <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold text-xl">{doc.fullName?.charAt(0)}</div>
// // //                           <div className="flex-1">
// // //                             <h3 className="font-display font-bold text-foreground flex items-center gap-1">
// // //                                 {doc.fullName} {doc.isVerified && <BadgeCheck size={14} className="text-accent" />}
// // //                             </h3>
// // //                             <p className="text-xs text-muted-foreground">{doc.specialization} · {doc.hospitalName}</p>
// // //                           </div>
// // //                           <div className="text-accent text-sm font-bold">₹{doc.consultationFee}</div>
// // //                         </div>
// // //                       </div>
// // //                     </GlassCard>
// // //                   ))}
// // //                 </div>
// // //               )}
// // //             </motion.div>
// // //           )}

// // //           {/* STEP 2: DOCTOR PROFILE */}
// // //           {step === "profile" && selectedDoctor && (
// // //             <motion.div key="profile" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// // //               <button onClick={() => setStep("search")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to search</button>
// // //               <GlassCard className="p-8">
// // //                 <div className="flex flex-col md:flex-row gap-8 items-center md:items-start">
// // //                   <div className="w-32 h-32 rounded-3xl bg-accent/10 flex items-center justify-center text-accent font-bold text-5xl">{selectedDoctor.fullName?.charAt(0)}</div>
// // //                   <div className="flex-1 text-center md:text-left">
// // //                     <h2 className="text-3xl font-bold text-foreground mb-2">{selectedDoctor.fullName}</h2>
// // //                     <p className="text-muted-foreground text-lg mb-4">{selectedDoctor.specialization} · {selectedDoctor.hospitalName}</p>
// // //                     <p className="text-sm text-muted-foreground leading-relaxed mb-8 max-w-xl">
// // //                         {selectedDoctor.bio || 'Experienced medical professional dedicated to providing high-quality digital healthcare and patient wellness.'}
// // //                     </p>
// // //                     <Button onClick={() => setStep("slot")} className="bg-accent text-accent-foreground px-12 py-7 rounded-2xl font-bold shadow-glow-accent hover:scale-[1.02] transition-all">
// // //                         Check Availability <ArrowRight className="ml-2" size={20} />
// // //                     </Button>
// // //                   </div>
// // //                 </div>
// // //               </GlassCard>
// // //             </motion.div>
// // //           )}

// // //           {/* STEP 3: SLOTS */}
// // //           {step === "slot" && (
// // //             <motion.div key="slot" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>
// // //               <button onClick={() => setStep("profile")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to profile</button>
// // //               <h2 className="font-display text-2xl font-bold mb-6 flex items-center gap-2"><Calendar className="text-accent" /> Select Session Time</h2>
// // //               <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-10">
// // //                 {slots.length > 0 ? slots.map((s) => (
// // //                   <button key={s.id} onClick={() => setSelectedSlot(s)} className={`glass rounded-2xl py-5 text-sm font-bold transition-all ${selectedSlot?.id === s.id ? "ring-2 ring-accent text-accent shadow-glow-accent scale-[1.02]" : "text-foreground hover:bg-white/5"}`}>
// // //                     <Clock size={16} className="mx-auto mb-2 opacity-50" />
// // //                     {new Date(s.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// // //                   </button>
// // //                 )) : <p className="text-muted-foreground italic col-span-full text-center py-12 glass rounded-2xl border-dashed border-2">No available slots found for today.</p>}
// // //               </div>
// // //               <Button onClick={() => setStep("payment")} disabled={!selectedSlot} className="bg-accent px-16 py-7 rounded-2xl font-bold text-accent-foreground shadow-glow-accent">Review Booking Summary</Button>
// // //             </motion.div>
// // //           )}

// // //           {/* STEP 4: PAYMENT SUMMARY */}
// // //           {step === "payment" && selectedSlot && (
// // //             <motion.div key="payment" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
// // //                <button onClick={() => setStep("slot")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Change Slot</button>
// // //                <GlassCard className="p-10 max-w-md mx-auto" tilt={false}>
// // //                   <div className="w-20 h-20 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-6"><CreditCard size={32} className="text-accent" /></div>
// // //                   <h2 className="font-display text-2xl font-bold text-center mb-8">Confirm Appointment</h2>
// // //                   <div className="glass rounded-2xl p-6 mb-8 space-y-4 text-sm">
// // //                     <div className="flex justify-between items-center"><span className="text-muted-foreground">Professional</span><span className="font-bold text-foreground">{selectedDoctor.fullName}</span></div>
// // //                     <div className="flex justify-between items-center"><span className="text-muted-foreground">Session</span><span className="font-bold text-foreground">{new Date(selectedSlot.startTime).toLocaleTimeString()}</span></div>
// // //                     <div className="border-t border-white/10 pt-4 flex justify-between items-center font-bold text-accent text-xl"><span>Total Fee</span><span>₹{selectedDoctor.consultationFee}</span></div>
// // //                   </div>
// // //                   <Button onClick={handlePaymentFlow} disabled={processing} className="w-full bg-gradient-to-r from-primary to-accent py-8 rounded-2xl font-bold shadow-glow-accent hover:scale-[1.01] active:scale-[0.98] transition-all">
// // //                     {processing ? <Loader2 className="animate-spin mr-2" /> : "Authorize Secure Payment"}
// // //                   </Button>
// // //                   <p className="text-[10px] text-center text-muted-foreground mt-4 uppercase tracking-widest opacity-50">🔒 Protected by 256-bit SSL Encryption</p>
// // //                </GlassCard>
// // //             </motion.div>
// // //           )}

// // //           {/* STEP 5: SUCCESS */}
// // //           {step === "success" && (
// // //             <motion.div key="success" initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="text-center py-20">
// // //               <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", damping: 12 }} className="w-28 h-28 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-8">
// // //                 <Check size={56} className="text-success" />
// // //               </motion.div>
// // //               <h2 className="font-display text-4xl font-bold text-foreground mb-4">Consultation Confirmed!</h2>
// // //               <p className="text-muted-foreground mb-12 max-w-sm mx-auto leading-relaxed">Your specialist is ready. You can access the secure meeting link in your dashboard timeline.</p>
// // //               <Button onClick={() => navigate("/patient/dashboard")} className="bg-success text-white px-16 py-7 rounded-2xl font-bold hover:scale-105 transition-all shadow-glow-success">Return to Dashboard</Button>
// // //             </motion.div>
// // //           )}

// // //         </AnimatePresence>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default BookAppointment;

















// // import { useState, useEffect } from "react";
// // import { motion, AnimatePresence } from "framer-motion";
// // import { Search, Calendar, Clock, CreditCard, Check, ArrowRight, ArrowLeft, Loader2, BadgeCheck } from "lucide-react";
// // import { Button } from "@/components/ui/button";
// // import { useLocation, useNavigate } from "react-router-dom"; 
// // import DashboardLayout from "@/components/DashboardLayout";
// // import GlassCard from "@/components/GlassCard";
// // import api from "@/lib/api"; 
// // import { toast } from "sonner";

// // // Use Vite environment variables for easy deployment handling
// // const RAZORPAY_KEY = import.meta.env.VITE_RAZORPAY_KEY_ID || "rzp_test_RqODjBUvVW2YIl";

// // type Step = "search" | "profile" | "slot" | "payment" | "success";

// // const BookAppointment = () => {
// //   const location = useLocation();
// //   const navigate = useNavigate();
  
// //   // AI Bridge: Retrieve recommended department from Triage Chat
// //   const initialDeptId = location.state?.recommendedDeptId;
// //   const initialDeptName = location.state?.recommendedDeptName;

// //   const [step, setStep] = useState<Step>("search");
// //   const [search, setSearch] = useState("");
// //   const [doctors, setDoctors] = useState<any[]>([]);
// //   const [slots, setSlots] = useState<any[]>([]);
// //   const [selectedDoctor, setSelectedDoctor] = useState<any>(null);
// //   const [selectedSlot, setSelectedSlot] = useState<any>(null);
// //   const [loading, setLoading] = useState(true);
// //   const [processing, setProcessing] = useState(false);

// //   // 1. Dynamically load Razorpay SDK
// //   useEffect(() => {
// //     const script = document.createElement("script");
// //     script.src = "https://checkout.razorpay.com/v1/checkout.js";
// //     script.async = true;
// //     document.body.appendChild(script);
// //   }, []);

// //   // 2. Fetch Doctors (Handles AI Recommendations)
// //   useEffect(() => {
// //     const fetchDoctors = async () => {
// //       try {
// //         setLoading(true);
// //         const endpoint = initialDeptId 
// //           ? `/public/doctors/department/${initialDeptId}` 
// //           : `/public/doctors/all`; 
// //         const res = await api.get(endpoint);
// //         setDoctors(Array.isArray(res.data) ? res.data : []);
// //       } catch (err) {
// //         console.error("Fetch failed", err);
// //         setDoctors([]);
// //       } finally { setLoading(false); }
// //     };
// //     fetchDoctors();
// //   }, [initialDeptId]);

// //   // 3. Fetch Available Slots for selected specialist
// //   useEffect(() => {
// //     if (selectedDoctor && step === "slot") {
// //       const fetchSlots = async () => {
// //         try {
// //           const res = await api.get(`/public/doctors/${selectedDoctor.id}/available-slots`);
// //           setSlots(Array.isArray(res.data) ? res.data : []); 
// //         } catch (err) { console.error("Slots fetch error", err); }
// //       };
// //       fetchSlots();
// //     }
// //   }, [selectedDoctor, step]);

// //   // --- HANDLER: RAZORPAY HANDSHAKE ---
// //   const handlePaymentFlow = async () => {
// //     if (!selectedSlot || !selectedDoctor) return;
// //     setProcessing(true);
    
// //     try {
// //       // Step A: Create Order in Backend
// //       const orderRes = await api.post(`/payments/create-order?slotId=${selectedSlot.id}&amount=${selectedDoctor.consultationFee}`);
// //       const orderId = orderRes.data; 

// //       // Step B: Open Razorpay Modal
// //       const options = {
// //         key: RAZORPAY_KEY,
// //         amount: selectedDoctor.consultationFee * 100, // In paise
// //         currency: "INR",
// //         name: "MediBot Healthcare",
// //         description: `Consultation with Dr. ${selectedDoctor.fullName}`,
// //         order_id: orderId,
// //         handler: async (response: any) => {
// //           try {
// //             // Step C: Verify & Confirm Booking
// //             await api.post("/payments/verify-payment", {
// //               razorpay_order_id: response.razorpay_order_id,
// //               razorpay_payment_id: response.razorpay_payment_id,
// //               razorpay_signature: response.razorpay_signature
// //             });
// //             setStep("success");
// //             toast.success("Booking Confirmed!");
// //           } catch (err) {
// //             toast.error("Security verification failed. Contact support.");
// //           }
// //         },
// //         theme: { color: "#0EA5E9" },
// //         prefill: {
// //             email: JSON.parse(localStorage.getItem("user") || "{}").email || ""
// //         }
// //       };

// //       const rzp = (window as any).Razorpay(options);
// //       rzp.open();

// //     } catch (err: any) {
// //       toast.error(err.response?.data || "Transaction failed. Slot may be locked.");
// //     } finally {
// //       setProcessing(false);
// //     }
// //   };

// //   const filteredDoctors = doctors.filter((d) =>
// //     (d.fullName || "").toLowerCase().includes(search.toLowerCase()) ||
// //     (d.specialization || "").toLowerCase().includes(search.toLowerCase())
// //   );

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-4xl mx-auto">
// //         <AnimatePresence mode="wait">
          
// //           {/* STEP 1: SEARCH */}
// //           {step === "search" && (
// //             <motion.div key="search" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// //               <div className="mb-8">
// //                 <h1 className="font-display text-3xl font-bold text-foreground">
// //                   {initialDeptName ? `Specialists for ${initialDeptName}` : "Find a Specialist"}
// //                 </h1>
// //                 <p className="text-muted-foreground mt-1">Select a verified professional for your consultation</p>
// //               </div>
// //               <div className="relative mb-6">
// //                 <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
// //                 <input type="text" placeholder="Search by name or specialty..." className="w-full pl-12 pr-4 py-4 glass rounded-2xl outline-none focus:ring-2 focus:ring-accent/50 transition-all" value={search} onChange={(e) => setSearch(e.target.value)} />
// //               </div>
// //               {loading ? <div className="text-center py-20"><Loader2 className="animate-spin mx-auto text-accent" size={32} /></div> : (
// //                 <div className="grid md:grid-cols-2 gap-4">
// //                   {filteredDoctors.map((doc) => (
// //                     <GlassCard key={doc.id} className="p-0 overflow-hidden cursor-pointer hover:border-accent/30 transition-all">
// //                       {/* FIX: Nested div handles onClick to resolve GlassCard property error */}
// //                       <div className="p-5" onClick={() => { setSelectedDoctor(doc); setStep("profile"); }}>
// //                         <div className="flex items-center gap-3">
// //                           <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold text-xl">{doc.fullName?.charAt(0)}</div>
// //                           <div className="flex-1">
// //                             <h3 className="font-display font-bold text-foreground flex items-center gap-1">
// //                                 {doc.fullName} {doc.isVerified && <BadgeCheck size={14} className="text-accent" />}
// //                             </h3>
// //                             <p className="text-xs text-muted-foreground">{doc.specialization} · {doc.hospitalName}</p>
// //                           </div>
// //                           <div className="text-accent text-sm font-bold">₹{doc.consultationFee}</div>
// //                         </div>
// //                       </div>
// //                     </GlassCard>
// //                   ))}
// //                 </div>
// //               )}
// //             </motion.div>
// //           )}

// //           {/* STEP 2: DOCTOR PROFILE */}
// //           {step === "profile" && selectedDoctor && (
// //             <motion.div key="profile" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
// //               <button onClick={() => setStep("search")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to search</button>
// //               <GlassCard className="p-8">
// //                 <div className="flex flex-col md:flex-row gap-8 items-center md:items-start">
// //                   <div className="w-32 h-32 rounded-3xl bg-accent/10 flex items-center justify-center text-accent font-bold text-5xl">{selectedDoctor.fullName?.charAt(0)}</div>
// //                   <div className="flex-1 text-center md:text-left">
// //                     <h2 className="text-3xl font-bold text-foreground mb-2">{selectedDoctor.fullName}</h2>
// //                     <p className="text-muted-foreground text-lg mb-4">{selectedDoctor.specialization} · {selectedDoctor.hospitalName}</p>
// //                     <p className="text-sm text-muted-foreground leading-relaxed mb-8 max-w-xl">
// //                         {selectedDoctor.bio || 'Experienced medical professional dedicated to providing high-quality digital healthcare.'}
// //                     </p>
// //                     <Button onClick={() => setStep("slot")} className="bg-accent text-accent-foreground px-12 py-7 rounded-2xl font-bold shadow-glow-accent hover:scale-[1.02] transition-all">
// //                         Check Availability <ArrowRight className="ml-2" size={20} />
// //                     </Button>
// //                   </div>
// //                 </div>
// //               </GlassCard>
// //             </motion.div>
// //           )}

// //           {/* STEP 3: SLOTS */}
// //           {step === "slot" && (
// //             <motion.div key="slot" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>
// //               <button onClick={() => setStep("profile")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to profile</button>
// //               <h2 className="font-display text-2xl font-bold mb-6 flex items-center gap-2"><Calendar className="text-accent" /> Available Sessions</h2>
// //               <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-10">
// //                 {slots.length > 0 ? slots.map((s) => (
// //                   <button key={s.id} onClick={() => setSelectedSlot(s)} className={`glass rounded-2xl py-5 text-sm font-bold transition-all ${selectedSlot?.id === s.id ? "ring-2 ring-accent text-accent shadow-glow-accent scale-[1.02]" : "text-foreground hover:bg-white/5"}`}>
// //                     <Clock size={16} className="mx-auto mb-2 opacity-50" />
// //                     {new Date(s.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
// //                   </button>
// //                 )) : <p className="text-muted-foreground italic col-span-full text-center py-12 glass rounded-2xl border-dashed border-2">No available slots for today.</p>}
// //               </div>
// //               <Button onClick={() => setStep("payment")} disabled={!selectedSlot} className="bg-accent px-16 py-7 rounded-2xl font-bold text-accent-foreground shadow-glow-accent">Review Booking Summary</Button>
// //             </motion.div>
// //           )}

// //           {/* STEP 4: PAYMENT SUMMARY */}
// //           {step === "payment" && selectedSlot && (
// //             <motion.div key="payment" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
// //                <button onClick={() => setStep("slot")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Change Slot</button>
// //                <GlassCard className="p-10 max-w-md mx-auto" tilt={false}>
// //                   <div className="w-20 h-20 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-6"><CreditCard size={32} className="text-accent" /></div>
// //                   <h2 className="font-display text-2xl font-bold text-center mb-8">Confirm Appointment</h2>
// //                   <div className="glass rounded-2xl p-6 mb-8 space-y-4 text-sm">
// //                     <div className="flex justify-between items-center"><span className="text-muted-foreground">Professional</span><span className="font-bold text-foreground">{selectedDoctor.fullName}</span></div>
// //                     <div className="flex justify-between items-center"><span className="text-muted-foreground">Session</span><span className="font-bold text-foreground">{new Date(selectedSlot.startTime).toLocaleTimeString()}</span></div>
// //                     <div className="border-t border-white/10 pt-4 flex justify-between items-center font-bold text-accent text-xl"><span>Total Fee</span><span>₹{selectedDoctor.consultationFee}</span></div>
// //                   </div>
// //                   <Button onClick={handlePaymentFlow} disabled={processing} className="w-full bg-gradient-to-r from-primary to-accent py-8 rounded-2xl font-bold shadow-glow-accent hover:scale-[1.01] active:scale-[0.98] transition-all">
// //                     {processing ? <Loader2 className="animate-spin mr-2" /> : "Authorize Secure Payment"}
// //                   </Button>
// //                </GlassCard>
// //             </motion.div>
// //           )}

// //           {/* STEP 5: SUCCESS */}
// //           {step === "success" && (
// //             <motion.div key="success" initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="text-center py-20">
// //               <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", damping: 12 }} className="w-28 h-28 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-8">
// //                 <Check size={56} className="text-success" />
// //               </motion.div>
// //               <h2 className="font-display text-4xl font-bold text-foreground mb-4">Consultation Confirmed!</h2>
// //               <p className="text-muted-foreground mb-12 max-w-sm mx-auto leading-relaxed">Your specialist is ready. You can access the secure meeting link in your dashboard timeline.</p>
// //               <Button onClick={() => navigate("/patient/dashboard")} className="bg-success text-white px-16 py-7 rounded-2xl font-bold hover:scale-105 transition-all shadow-glow-success">Return to Dashboard</Button>
// //             </motion.div>
// //           )}

// //         </AnimatePresence>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default BookAppointment;









// import { useState, useEffect } from "react";
// import { motion, AnimatePresence } from "framer-motion";
// import { Search, Calendar, Clock, CreditCard, Check, ArrowRight, ArrowLeft, Loader2, BadgeCheck } from "lucide-react";
// import { Button } from "@/components/ui/button";
// import { useLocation, useNavigate } from "react-router-dom"; 
// import DashboardLayout from "@/components/DashboardLayout";
// import GlassCard from "@/components/GlassCard";
// import api from "@/lib/api"; 
// import { toast } from "sonner";

// const RAZORPAY_KEY = import.meta.env.VITE_RAZORPAY_KEY_ID || "rzp_test_RqODjBUvVW2YIl";

// type Step = "search" | "profile" | "slot" | "payment" | "success";

// const BookAppointment = () => {
//   const location = useLocation();
//   const navigate = useNavigate();
//   const initialDeptId = location.state?.recommendedDeptId;
//   const initialDeptName = location.state?.recommendedDeptName;

//   const [step, setStep] = useState<Step>("search");
//   const [search, setSearch] = useState("");
//   const [doctors, setDoctors] = useState<any[]>([]);
//   const [slots, setSlots] = useState<any[]>([]);
//   const [selectedDoctor, setSelectedDoctor] = useState<any>(null);
//   const [selectedSlot, setSelectedSlot] = useState<any>(null);
//   const [loading, setLoading] = useState(true);
//   const [processing, setProcessing] = useState(false);

//   // 1. Load Razorpay SDK
//   useEffect(() => {
//     const script = document.createElement("script");
//     script.src = "https://checkout.razorpay.com/v1/checkout.js";
//     script.async = true;
//     document.body.appendChild(script);
//   }, []);

//   // 2. Fetch Specialists
//   useEffect(() => {
//     const fetchDoctors = async () => {
//       try {
//         setLoading(true);
//         const endpoint = initialDeptId ? `/public/doctors/department/${initialDeptId}` : `/public/doctors/all`; 
//         const res = await api.get(endpoint);
//         setDoctors(Array.isArray(res.data) ? res.data : []);
//       } catch (err) {
//         console.error("Fetch failed", err);
//         setDoctors([]);
//       } finally { setLoading(false); }
//     };
//     fetchDoctors();
//   }, [initialDeptId]);

//   // 3. Fetch Available Slots
//   useEffect(() => {
//     if (selectedDoctor && step === "slot") {
//       const fetchSlots = async () => {
//         try {
//           const res = await api.get(`/public/doctors/${selectedDoctor.id}/available-slots`);
//           setSlots(Array.isArray(res.data) ? res.data : []); 
//         } catch (err) { console.error("Slots fetch error", err); }
//       };
//       fetchSlots();
//     }
//   }, [selectedDoctor, step]);

//   // --- HANDLER: RAZORPAY INTEGRATION ---
//   const handlePaymentFlow = async () => {
//     if (!selectedSlot || !selectedDoctor) return;
//     setProcessing(true);
    
//     try {
//       // Step A: Create Order (Backend identifies patient via Principal/Token)
//       const orderRes = await api.post(`/payments/create-order?slotId=${selectedSlot.id}&amount=${selectedDoctor.consultationFee}`);
//       const orderId = orderRes.data; 

//       // Step B: Razorpay Modal
//       const options = {
//         key: RAZORPAY_KEY,
//         amount: selectedDoctor.consultationFee * 100,
//         currency: "INR",
//         name: "MediBot Healthcare",
//         description: `Consultation with Dr. ${selectedDoctor.fullName}`,
//         order_id: orderId,
//         handler: async (response: any) => {
//           try {
//             // Step C: Verify & Confirm (Database constraints handled by logEntry.patient)
//             await api.post("/payments/verify-payment", {
//               razorpay_order_id: response.razorpay_order_id,
//               razorpay_payment_id: response.razorpay_payment_id,
//               razorpay_signature: response.razorpay_signature
//             });
//             setStep("success");
//             toast.success("Booking Confirmed!");
//           } catch (err) {
//             toast.error("Verification failed. Please contact support.");
//           }
//         },
//         theme: { color: "#0EA5E9" },
//         prefill: { email: JSON.parse(localStorage.getItem("user") || "{}").email || "" }
//       };

//       const rzp = (window as any).Razorpay(options);
//       rzp.open();

//     } catch (err: any) {
//       toast.error(err.response?.data || "Transaction failed. Slot may be locked.");
//     } finally {
//       setProcessing(false);
//     }
//   };

//   const filteredDoctors = doctors.filter((d) =>
//     (d.fullName || "").toLowerCase().includes(search.toLowerCase()) ||
//     (d.specialization || "").toLowerCase().includes(search.toLowerCase())
//   );

//   // Date Formatting Helper
//   const formatSlotDate = (dateStr: string) => {
//     const d = new Date(dateStr);
//     return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
//   };

//   const formatSlotTime = (dateStr: string) => {
//     const d = new Date(dateStr);
//     return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
//   };

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-4xl mx-auto">
//         <AnimatePresence mode="wait">
          
//           {/* STEP 1: DOCTOR SEARCH */}
//           {step === "search" && (
//             <motion.div key="search" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
//               <div className="mb-8">
//                 <h1 className="font-display text-3xl font-bold text-foreground">
//                   {initialDeptName ? `Specialists for ${initialDeptName}` : "Find a Specialist"}
//                 </h1>
//                 <p className="text-muted-foreground mt-1">Book an expert for your health needs</p>
//               </div>
//               <div className="relative mb-6">
//                 <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
//                 <input type="text" placeholder="Search by name or specialty..." className="w-full pl-12 pr-4 py-4 glass rounded-2xl outline-none focus:ring-2 focus:ring-accent/50 transition-all" value={search} onChange={(e) => setSearch(e.target.value)} />
//               </div>
//               {loading ? <div className="text-center py-20"><Loader2 className="animate-spin mx-auto text-accent" size={32} /></div> : (
//                 <div className="grid md:grid-cols-2 gap-4">
//                   {filteredDoctors.map((doc) => (
//                     <GlassCard key={doc.id} className="p-0 overflow-hidden cursor-pointer hover:border-accent/30 transition-all">
//                       <div className="p-5" onClick={() => { setSelectedDoctor(doc); setStep("profile"); }}>
//                         <div className="flex items-center gap-3">
//                           <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold text-xl">{doc.fullName?.charAt(0)}</div>
//                           <div className="flex-1">
//                             <h3 className="font-display font-bold text-foreground flex items-center gap-1">
//                                 {doc.fullName} {doc.isVerified && <BadgeCheck size={14} className="text-accent" />}
//                             </h3>
//                             <p className="text-xs text-muted-foreground">{doc.specialization} · {doc.hospitalName}</p>
//                           </div>
//                           <div className="text-accent text-sm font-bold">₹{doc.consultationFee}</div>
//                         </div>
//                       </div>
//                     </GlassCard>
//                   ))}
//                 </div>
//               )}
//             </motion.div>
//           )}

//           {/* STEP 2: DOCTOR PROFILE */}
//           {step === "profile" && selectedDoctor && (
//             <motion.div key="profile" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
//               <button onClick={() => setStep("search")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back</button>
//               <GlassCard className="p-8">
//                 <div className="flex flex-col md:flex-row gap-8 items-center md:items-start">
//                   <div className="w-32 h-32 rounded-3xl bg-accent/10 flex items-center justify-center text-accent font-bold text-5xl">{selectedDoctor.fullName?.charAt(0)}</div>
//                   <div className="flex-1 text-center md:text-left">
//                     <h2 className="text-3xl font-bold text-foreground mb-2">{selectedDoctor.fullName}</h2>
//                     <p className="text-muted-foreground text-lg mb-4">{selectedDoctor.specialization} · {selectedDoctor.hospitalName}</p>
//                     <p className="text-sm text-muted-foreground leading-relaxed mb-8 max-w-xl italic">
//                         {selectedDoctor.bio || 'Verified medical professional dedicated to digital healthcare.'}
//                     </p>
//                     <Button onClick={() => setStep("slot")} className="bg-accent text-accent-foreground px-12 py-7 rounded-2xl font-bold shadow-glow-accent">
//                         View Schedule <ArrowRight className="ml-2" size={20} />
//                     </Button>
//                   </div>
//                 </div>
//               </GlassCard>
//             </motion.div>
//           )}

//           {/* STEP 3: SLOTS (NO CALENDAR NEEDED - DATE SHOWN ON BUTTON) */}
//           {step === "slot" && (
//             <motion.div key="slot" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>
//               <button onClick={() => setStep("profile")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back</button>
//               <h2 className="font-display text-2xl font-bold mb-6 flex items-center gap-2"><Calendar className="text-accent" /> Upcoming Sessions</h2>
//               <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-10">
//                 {slots.length > 0 ? slots.map((s) => (
//                   <button key={s.id} onClick={() => setSelectedSlot(s)} className={`glass rounded-2xl p-5 text-center transition-all ${selectedSlot?.id === s.id ? "ring-2 ring-accent text-accent shadow-glow-accent scale-[1.02]" : "text-foreground hover:bg-white/5"}`}>
//                     <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1">{formatSlotDate(s.startTime)}</div>
//                     <div className="text-lg font-bold flex items-center justify-center gap-2"><Clock size={16} /> {formatSlotTime(s.startTime)}</div>
//                   </button>
//                 )) : <p className="text-muted-foreground italic col-span-full text-center py-12 glass rounded-2xl border-dashed border-2">No upcoming slots found.</p>}
//               </div>
//               <Button onClick={() => setStep("payment")} disabled={!selectedSlot} className="bg-accent px-16 py-7 rounded-2xl font-bold text-accent-foreground shadow-glow-accent">Proceed to Checkout</Button>
//             </motion.div>
//           )}

//           {/* STEP 4: PAYMENT SUMMARY */}
//           {step === "payment" && selectedSlot && (
//             <motion.div key="payment" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
//                <button onClick={() => setStep("slot")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Change Slot</button>
//                <GlassCard className="p-10 max-w-md mx-auto" tilt={false}>
//                   <div className="w-20 h-20 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-6"><CreditCard size={32} className="text-accent" /></div>
//                   <h2 className="font-display text-2xl font-bold text-center mb-8">Confirm Booking</h2>
//                   <div className="glass rounded-2xl p-6 mb-8 space-y-4 text-sm">
//                     <div className="flex justify-between items-center"><span className="text-muted-foreground">Expert</span><span className="font-bold text-foreground">{selectedDoctor.fullName}</span></div>
//                     <div className="flex justify-between items-center"><span className="text-muted-foreground">Date</span><span className="font-bold text-foreground">{formatSlotDate(selectedSlot.startTime)}</span></div>
//                     <div className="flex justify-between items-center"><span className="text-muted-foreground">Time</span><span className="font-bold text-foreground">{formatSlotTime(selectedSlot.startTime)}</span></div>
//                     <div className="border-t border-white/10 pt-4 flex justify-between items-center font-bold text-accent text-xl"><span>Consultation Fee</span><span>₹{selectedDoctor.consultationFee}</span></div>
//                   </div>
//                   <Button onClick={handlePaymentFlow} disabled={processing} className="w-full bg-gradient-to-r from-primary to-accent py-8 rounded-2xl font-bold shadow-glow-accent hover:scale-[1.01] active:scale-[0.98] transition-all">
//                     {processing ? <Loader2 className="animate-spin mr-2" /> : "Pay & Confirm Booking"}
//                   </Button>
//                   <p className="text-[10px] text-center text-muted-foreground mt-4 opacity-50 uppercase tracking-widest">🔒 Powered by Razorpay Secure</p>
//                </GlassCard>
//             </motion.div>
//           )}

//           {/* STEP 5: SUCCESS */}
//           {step === "success" && (
//             <motion.div key="success" initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="text-center py-20">
//               <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", damping: 12 }} className="w-28 h-28 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-8">
//                 <Check size={56} className="text-success" />
//               </motion.div>
//               <h2 className="font-display text-4xl font-bold text-foreground mb-4">Success!</h2>
//               <p className="text-muted-foreground mb-12 max-w-sm mx-auto leading-relaxed">Your consultation has been secured. Your doctor will see you at the scheduled time.</p>
//               <Button onClick={() => navigate("/patient/dashboard")} className="bg-success text-white px-16 py-7 rounded-2xl font-bold hover:scale-105 transition-all shadow-glow-success">View Appointments</Button>
//             </motion.div>
//           )}

//         </AnimatePresence>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default BookAppointment;



import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search, Calendar, Clock, CreditCard, Check, ArrowRight, ArrowLeft, Loader2, BadgeCheck, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useLocation, useNavigate } from "react-router-dom"; 
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import api from "@/lib/api"; 
import { toast } from "sonner";

const RAZORPAY_KEY = import.meta.env.VITE_RAZORPAY_KEY_ID || "rzp_test_RqODjBUvVW2YIl";

type Step = "search" | "profile" | "slot" | "payment" | "success";

const BookAppointment = () => {
  const location = useLocation();
  const navigate = useNavigate();
  
  // AI Recommendation Bridge
  const initialDeptId = location.state?.recommendedDeptId;
  const initialDeptName = location.state?.recommendedDeptName;

  const [step, setStep] = useState<Step>("search");
  const [search, setSearch] = useState("");
  const [doctors, setDoctors] = useState<any[]>([]);
  const [slots, setSlots] = useState<any[]>([]);
  const [selectedDoctor, setSelectedDoctor] = useState<any>(null);
  const [selectedSlot, setSelectedSlot] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);

  // 1. Load Razorpay SDK Script
  useEffect(() => {
    const script = document.createElement("script");
    script.src = "https://checkout.razorpay.com/v1/checkout.js";
    script.async = true;
    document.body.appendChild(script);
  }, []);

  // 2. Fetch Doctors (Supports AI recommendation filtering)
  useEffect(() => {
    const fetchDoctors = async () => {
      try {
        setLoading(true);
        const endpoint = initialDeptId ? `/public/doctors/department/${initialDeptId}` : `/public/doctors/all`; 
        const res = await api.get(endpoint);
        setDoctors(Array.isArray(res.data) ? res.data : []);
      } catch (err) {
        console.error("Specialist fetch failed", err);
        setDoctors([]);
      } finally { setLoading(false); }
    };
    fetchDoctors();
  }, [initialDeptId]);

  // 3. Fetch Real-Time Available Slots
  // This automatically picks up slots reset to AVAILABLE by the backend endConsultation method.
  useEffect(() => {
    if (selectedDoctor && step === "slot") {
      const fetchSlots = async () => {
        try {
          // Hits SlotRepository.findAvailableSlots on backend
          const res = await api.get(`/public/doctors/${selectedDoctor.id}/available-slots`);
          setSlots(Array.isArray(res.data) ? res.data : []); 
        } catch (err) { console.error("Slots synchronization error", err); }
      };
      fetchSlots();
    }
  }, [selectedDoctor, step]);

  // --- RAZORPAY PAYMENT ORCHESTRATION ---
  const handlePaymentFlow = async () => {
    if (!selectedSlot || !selectedDoctor) return;
    setProcessing(true);
    
    try {
      // Step A: Create Order (Backend removes stale logs to avoid Duplicate Key errors)
      const orderRes = await api.post(`/payments/create-order?slotId=${selectedSlot.id}&amount=${selectedDoctor.consultationFee}`);
      const orderId = orderRes.data; 

      // Step B: Razorpay UI
      const options = {
        key: RAZORPAY_KEY,
        amount: Math.round(selectedDoctor.consultationFee * 100), // In paise
        currency: "INR",
        name: "MediBot Healthcare",
        description: `Session with Dr. ${selectedDoctor.fullName}`,
        order_id: orderId,
        handler: async (response: any) => {
          try {
            // Step C: Secure Verification and Booking Confirmation
            await api.post("/payments/verify-payment", {
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature
            });
            setStep("success");
            toast.success("Consultation secured successfully!");
          } catch (err) {
            toast.error("Security verification failed. Please contact support.");
          }
        },
        theme: { color: "#0EA5E9" },
        prefill: { email: JSON.parse(localStorage.getItem("user") || "{}").email || "" }
      };

      const rzp = (window as any).Razorpay(options);
      rzp.open();

    } catch (err: any) {
      toast.error(err.response?.data || "Slot is temporarily locked by another user.");
    } finally {
      setProcessing(false);
    }
  };

  const filteredDoctors = doctors.filter((d) =>
    (d.fullName || "").toLowerCase().includes(search.toLowerCase()) ||
    (d.specialization || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <DashboardLayout role="patient">
      <div className="max-w-4xl mx-auto">
        <AnimatePresence mode="wait">
          
          {/* STEP 1: DISCOVERY */}
          {step === "search" && (
            <motion.div key="search" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
              <div className="mb-8">
                <h1 className="font-display text-3xl font-bold text-foreground">
                  {initialDeptName ? `Specialists: ${initialDeptName}` : "Find a Specialist"}
                </h1>
                <p className="text-muted-foreground mt-1">Select a verified professional to begin your consultation</p>
              </div>
              <div className="relative mb-6">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
                <input type="text" placeholder="Search by name or clinical specialty..." className="w-full pl-12 pr-4 py-4 glass rounded-2xl outline-none focus:ring-2 focus:ring-accent/50 transition-all" value={search} onChange={(e) => setSearch(e.target.value)} />
              </div>
              {loading ? <div className="text-center py-20"><Loader2 className="animate-spin mx-auto text-accent" size={32} /></div> : (
                <div className="grid md:grid-cols-2 gap-4">
                  {filteredDoctors.map((doc) => (
                    <GlassCard key={doc.id} className="p-0 overflow-hidden cursor-pointer hover:border-accent/30 transition-all">
                      <div className="p-5" onClick={() => { setSelectedDoctor(doc); setStep("profile"); }}>
                        <div className="flex items-center gap-3">
                          <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent font-bold text-xl">{doc.fullName?.charAt(0)}</div>
                          <div className="flex-1">
                            <h3 className="font-display font-bold text-foreground flex items-center gap-1">
                                {doc.fullName} {doc.isVerified && <BadgeCheck size={14} className="text-accent" />}
                            </h3>
                            <p className="text-xs text-muted-foreground">{doc.specialization} · {doc.hospitalName}</p>
                          </div>
                          <div className="text-accent text-sm font-bold">₹{doc.consultationFee}</div>
                        </div>
                      </div>
                    </GlassCard>
                  ))}
                </div>
              )}
            </motion.div>
          )}

          {/* STEP 2: PROFESSIONAL PROFILE */}
          {step === "profile" && selectedDoctor && (
            <motion.div key="profile" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
              <button onClick={() => setStep("search")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to search</button>
              <GlassCard className="p-8">
                <div className="flex flex-col md:flex-row gap-8 items-center md:items-start">
                  <div className="w-32 h-32 rounded-3xl bg-accent/10 flex items-center justify-center text-accent font-bold text-5xl">{selectedDoctor.fullName?.charAt(0)}</div>
                  <div className="flex-1 text-center md:text-left">
                    <h2 className="text-3xl font-bold text-foreground mb-2">{selectedDoctor.fullName}</h2>
                    <p className="text-muted-foreground text-lg mb-4">{selectedDoctor.specialization} · {selectedDoctor.hospitalName}</p>
                    <p className="text-sm text-muted-foreground leading-relaxed mb-8 max-w-xl italic opacity-80">
                        {selectedDoctor.bio || 'Verified medical professional dedicated to providing high-quality digital healthcare.'}
                    </p>
                    <Button onClick={() => setStep("slot")} className="bg-accent text-accent-foreground px-12 py-7 rounded-2xl font-bold shadow-glow-accent hover:scale-[1.02] transition-all">
                        View Availability <ArrowRight className="ml-2" size={20} />
                    </Button>
                  </div>
                </div>
              </GlassCard>
            </motion.div>
          )}

          {/* STEP 3: LIVE SLOTS (REFRESHED FROM BACKEND) */}
          {step === "slot" && (
            <motion.div key="slot" initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>
              <button onClick={() => setStep("profile")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Back to profile</button>
              <h2 className="font-display text-2xl font-bold mb-6 flex items-center gap-2"><Calendar className="text-accent" /> Select Session Time</h2>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-10">
                {slots.length > 0 ? slots.map((s) => (
                  <button key={s.id} onClick={() => setSelectedSlot(s)} className={`glass rounded-2xl py-5 text-sm font-bold transition-all ${selectedSlot?.id === s.id ? "ring-2 ring-accent text-accent shadow-glow-accent scale-[1.02]" : "text-foreground hover:bg-white/5"}`}>
                    <div className="text-[10px] uppercase tracking-widest opacity-40 mb-1">{new Date(s.startTime).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</div>
                    <div className="flex items-center justify-center gap-1.5"><Clock size={14} /> {new Date(s.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                  </button>
                )) : (
                  <div className="col-span-full py-12 glass rounded-2xl border-dashed border-2 border-white/5 text-center">
                    <p className="text-muted-foreground italic">No available slots found for the chosen specialist.</p>
                  </div>
                )}
              </div>
              <Button onClick={() => setStep("payment")} disabled={!selectedSlot} className="bg-accent px-16 py-7 rounded-2xl font-bold text-accent-foreground shadow-glow-accent">Review Appointment Summary</Button>
            </motion.div>
          )}

          {/* STEP 4: CHECKOUT SUMMARY */}
          {step === "payment" && selectedSlot && (
            <motion.div key="payment" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
               <button onClick={() => setStep("slot")} className="flex items-center gap-2 text-sm text-muted-foreground mb-6 hover:text-foreground transition-colors"><ArrowLeft size={16}/> Change session time</button>
               <GlassCard className="p-10 max-w-md mx-auto" tilt={false}>
                  <div className="w-20 h-20 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-6"><CreditCard size={32} className="text-accent" /></div>
                  <h2 className="font-display text-2xl font-bold text-center mb-8">Confirm Appointment</h2>
                  <div className="glass rounded-2xl p-6 mb-8 space-y-4 text-sm border-white/5">
                    <div className="flex justify-between items-center"><span className="text-muted-foreground">Expert</span><span className="font-bold text-foreground">{selectedDoctor.fullName}</span></div>
                    <div className="flex justify-between items-center"><span className="text-muted-foreground">Session</span><span className="font-bold text-foreground">{new Date(selectedSlot.startTime).toLocaleString()}</span></div>
                    <div className="border-t border-white/10 pt-4 flex justify-between items-center font-bold text-accent text-xl"><span>Consultation Fee</span><span>₹{selectedDoctor.consultationFee}</span></div>
                  </div>
                  <Button onClick={handlePaymentFlow} disabled={processing} className="w-full bg-gradient-to-r from-primary to-accent py-8 rounded-2xl font-bold shadow-glow-accent hover:scale-[1.01] active:scale-[0.98] transition-all">
                    {processing ? <Loader2 className="animate-spin mr-2" /> : "Complete Secure Payment"}
                  </Button>
                  <p className="text-[10px] text-center text-muted-foreground mt-4 opacity-50 uppercase tracking-widest flex items-center justify-center gap-1">
                    <ShieldCheck size={10} /> 256-bit SSL Secure Handshake
                  </p>
               </GlassCard>
            </motion.div>
          )}

          {/* STEP 5: SUCCESS ARCHIVE */}
          {step === "success" && (
            <motion.div key="success" initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="text-center py-20">
              <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", damping: 12 }} className="w-28 h-28 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-8">
                <Check size={56} className="text-success" />
              </motion.div>
              <h2 className="font-display text-4xl font-bold text-foreground mb-4">Success!</h2>
              <p className="text-muted-foreground mb-12 max-w-sm mx-auto leading-relaxed">Your consultation has been secured. Your doctor will see you at the scheduled time in the virtual room.</p>
              <Button onClick={() => navigate("/patient/dashboard")} className="bg-success text-white px-16 py-7 rounded-2xl font-bold hover:scale-105 transition-all shadow-glow-success">View Appointments</Button>
            </motion.div>
          )}

        </AnimatePresence>
      </div>
    </DashboardLayout>
  );
};

export default BookAppointment;