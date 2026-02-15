// // import { useState } from "react";
// // import { motion, AnimatePresence } from "framer-motion";
// // import { Mail, Lock, User, Phone, Stethoscope, Building2, Clock, ArrowRight, Eye, EyeOff } from "lucide-react";
// // import { Button } from "@/components/ui/button";
// // import { Link } from "react-router-dom";

// // const inputClass = "w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all";

// // const InputField = ({ icon: Icon, ...props }: { icon: any } & React.InputHTMLAttributes<HTMLInputElement>) => (
// //   <div className="relative">
// //     <Icon size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// //     <input {...props} className={inputClass} />
// //   </div>
// // );

// // const Signup = () => {
// //   const [role, setRole] = useState<"patient" | "doctor">("patient");
// //   const [loading, setLoading] = useState(false);
// //   const [success, setSuccess] = useState(false);
// //   const [showPassword, setShowPassword] = useState(false);

// //   const handleSubmit = (e: React.FormEvent) => {
// //     e.preventDefault();
// //     setLoading(true);
// //     setTimeout(() => {
// //       setLoading(false);
// //       setSuccess(true);
// //     }, 1500);
// //   };

// //   return (
// //     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
// //       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
// //       <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

// //       <motion.div
// //         initial={{ opacity: 0, scale: 0.95, y: 20 }}
// //         animate={{ opacity: 1, scale: 1, y: 0 }}
// //         transition={{ duration: 0.6 }}
// //         className="w-full max-w-md"
// //       >
// //         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
// //           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
// //             <span className="text-accent-foreground font-bold">M</span>
// //           </div>
// //           <span className="font-display text-2xl font-bold text-foreground">Medi<span className="text-gradient-accent">bot</span></span>
// //         </Link>

// //         <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
// //           <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Create Account</h2>
// //           <p className="text-muted-foreground text-center text-sm mb-6">Join the future of healthcare</p>

// //           {/* Role Toggle */}
// //           <div className="flex glass rounded-2xl p-1 mb-6">
// //             {(["patient", "doctor"] as const).map((r) => (
// //               <button
// //                 key={r}
// //                 onClick={() => setRole(r)}
// //                 className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all duration-300 ${
// //                   role === r
// //                     ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent"
// //                     : "text-muted-foreground hover:text-foreground"
// //                 }`}
// //               >
// //                 {r === "patient" ? <User size={16} /> : <Stethoscope size={16} />}
// //                 {r === "patient" ? "Patient" : "Doctor"}
// //               </button>
// //             ))}
// //           </div>

// //           <AnimatePresence mode="wait">
// //             {success ? (
// //               <motion.div key="success" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} className="text-center py-8">
// //                 <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
// //                   <ArrowRight size={32} className="text-success" />
// //                 </div>
// //                 <h3 className="font-display text-xl font-bold text-foreground mb-2">Account Created!</h3>
// //                 <p className="text-muted-foreground text-sm">Redirecting to login...</p>
// //               </motion.div>
// //             ) : (
// //               <motion.form key={role} initial={{ opacity: 0, x: role === "patient" ? -20 : 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.3 }} onSubmit={handleSubmit} className="space-y-3">
// //                 <InputField icon={User} placeholder="Full Name" type="text" required />
// //                 <InputField icon={Mail} placeholder="Email Address" type="email" required />
// //                 <div className="relative">
// //                   <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// //                   <input type={showPassword ? "text" : "password"} placeholder="Password" required className={inputClass + " pr-11"} />
// //                   <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
// //                     {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
// //                   </button>
// //                 </div>
// //                 <InputField icon={Phone} placeholder="Phone Number" type="tel" required />

// //                 {role === "doctor" && (
// //                   <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} className="space-y-3">
// //                     <InputField icon={Stethoscope} placeholder="Specialization" type="text" required />
// //                     <InputField icon={Building2} placeholder="Hospital / Clinic" type="text" required />
// //                     <InputField icon={Clock} placeholder="Years of Experience" type="number" required />
// //                   </motion.div>
// //                 )}

// //                 <Button type="submit" disabled={loading} className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group mt-2">
// //                   {loading ? (
// //                     <div className="flex items-center gap-2">
// //                       <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
// //                       Creating Account...
// //                     </div>
// //                   ) : (
// //                     <>Create Account <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" /></>
// //                   )}
// //                 </Button>
// //               </motion.form>
// //             )}
// //           </AnimatePresence>

// //           <p className="text-center text-sm text-muted-foreground mt-6">
// //             Already have an account? <Link to="/login" className="text-accent font-semibold hover:underline">Sign In</Link>
// //           </p>
// //         </div>
// //       </motion.div>
// //     </div>
// //   );
// // };

// // export default Signup;


// import { useState } from "react";
// import { motion, AnimatePresence } from "framer-motion";
// import { Mail, Lock, User, Phone, Stethoscope, Building2, Clock, ArrowRight, Eye, EyeOff, Calendar, Users, ClipboardList } from "lucide-react";
// import { Button } from "@/components/ui/button";
// import { Link, useNavigate } from "react-router-dom";
// import { signup } from "@/services/authService"; // Import the integrated service

// const inputClass = "w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all";

// const InputField = ({ icon: Icon, ...props }: { icon: any } & React.InputHTMLAttributes<HTMLInputElement>) => (
//   <div className="relative">
//     <Icon size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//     <input {...props} className={inputClass} />
//   </div>
// );

// const Signup = () => {
//   const navigate = useNavigate();
//   const [role, setRole] = useState<"patient" | "doctor">("patient");
//   const [loading, setLoading] = useState(false);
//   const [success, setSuccess] = useState(false);
//   const [showPassword, setShowPassword] = useState(false);
//   const [error, setError] = useState("");

//   // State for mandatory backend fields
//   const [formData, setFormData] = useState({
//     firstName: "",
//     lastName: "",
//     email: "",
//     password: "",
//     age: "",
//     gender: "Male",
//     medicalHistory: "",
//   });

//   const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
//     setFormData({ ...formData, [e.target.name]: e.target.value });
//   };

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setLoading(true);
//     setError("");

//     try {
//       // Prepare payload to match Spring Boot User Entity
//       const payload = {
//         ...formData,
//         age: parseInt(formData.age),
//         role: role.toUpperCase(),
//         // For Doctors, we default medicalHistory to "Specialist Profile" as discussed
//         medicalHistory: role === "doctor" ? "Specialist Profile" : formData.medicalHistory
//       };

//       await signup(payload);
      
//       setLoading(false);
//       setSuccess(true);
//       setTimeout(() => navigate("/login"), 2000);
//     } catch (err: any) {
//       setLoading(false);
//       setError(err.response?.data?.message || "Registration failed. Please try again.");
//     }
//   };

//   return (
//     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
//       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
//       <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

//       <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} transition={{ duration: 0.6 }} className="w-full max-w-md py-8">
//         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
//           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
//             <span className="text-accent-foreground font-bold">M</span>
//           </div>
//           <span className="font-display text-2xl font-bold text-foreground">Medi<span className="text-gradient-accent">bot</span></span>
//         </Link>

//         <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
//           <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Create Account</h2>
//           <p className="text-muted-foreground text-center text-sm mb-6">Join the future of healthcare</p>

//           <div className="flex glass rounded-2xl p-1 mb-6">
//             {(["patient", "doctor"] as const).map((r) => (
//               <button key={r} type="button" onClick={() => setRole(r)} className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all duration-300 ${role === r ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent" : "text-muted-foreground hover:text-foreground"}`}>
//                 {r === "patient" ? <User size={16} /> : <Stethoscope size={16} />}
//                 {r === "patient" ? "Patient" : "Doctor"}
//               </button>
//             ))}
//           </div>

//           <AnimatePresence mode="wait">
//             {success ? (
//               <motion.div key="success" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} className="text-center py-8">
//                 <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
//                   <ArrowRight size={32} className="text-success" />
//                 </div>
//                 <h3 className="font-display text-xl font-bold text-foreground mb-2">Account Created!</h3>
//                 <p className="text-muted-foreground text-sm">Redirecting to login...</p>
//               </motion.div>
//             ) : (
//               <motion.form key={role} initial={{ opacity: 0, x: role === "patient" ? -20 : 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.3 }} onSubmit={handleSubmit} className="space-y-3">
                
//                 {/* Name Fields */}
//                 <div className="grid grid-cols-2 gap-3">
//                   <InputField icon={User} name="firstName" placeholder="First Name" type="text" onChange={handleInputChange} required />
//                   <InputField icon={User} name="lastName" placeholder="Last Name" type="text" onChange={handleInputChange} required />
//                 </div>

//                 <InputField icon={Mail} name="email" placeholder="Email Address" type="email" onChange={handleInputChange} required />
                
//                 <div className="relative">
//                   <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                   <input name="password" type={showPassword ? "text" : "password"} placeholder="Password" required onChange={handleInputChange} className={inputClass + " pr-11"} />
//                   <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
//                     {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
//                   </button>
//                 </div>

//                 {/* Age and Gender Fields */}
//                 <div className="grid grid-cols-2 gap-3">
//                   <InputField icon={Calendar} name="age" placeholder="Age" type="number" onChange={handleInputChange} required />
//                   <div className="relative">
//                     <Users size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                     <select name="gender" onChange={handleInputChange} className={inputClass}>
//                       <option value="Male">Male</option>
//                       <option value="Female">Female</option>
//                       <option value="Other">Other</option>
//                     </select>
//                   </div>
//                 </div>

//                 {/* Patient Specific Fields */}
//                 {role === "patient" && (
//                   <div className="relative">
//                     <ClipboardList size={16} className="absolute left-4 top-4 text-muted-foreground" />
//                     <textarea name="medicalHistory" placeholder="Medical History (e.g. Allergies, chronic conditions)" onChange={handleInputChange} className={inputClass + " pl-11 h-24 resize-none pt-3"} required />
//                   </div>
//                 )}

//                 {error && <p className="text-destructive text-xs text-center">{error}</p>}

//                 <Button type="submit" disabled={loading} className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group mt-2">
//                   {loading ? (
//                     <div className="flex items-center gap-2">
//                       <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
//                       Creating Account...
//                     </div>
//                   ) : (
//                     <>Create Account <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" /></>
//                   )}
//                 </Button>
//               </motion.form>
//             )}
//           </AnimatePresence>

//           <p className="text-center text-sm text-muted-foreground mt-6">
//             Already have an account? <Link to="/login" className="text-accent font-semibold hover:underline">Sign In</Link>
//           </p>
//         </div>
//       </motion.div>
//     </div>
//   );
// };

// export default Signup;

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mail, Lock, User, Phone, Stethoscope, ArrowRight, Eye, EyeOff, Calendar, Users, ClipboardList, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link, useNavigate } from "react-router-dom";
import { signup } from "@/services/authService";

const inputClass = "w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all";

const InputField = ({ icon: Icon, ...props }: { icon: any } & React.InputHTMLAttributes<HTMLInputElement>) => (
  <div className="relative">
    <Icon size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
    <input {...props} className={inputClass} />
  </div>
);

const Signup = () => {
  const navigate = useNavigate();
  const [role, setRole] = useState<"patient" | "doctor">("patient");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  // Initialized state to prevent "undefined" errors during typing
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
    age: "",
    gender: "Male",
    medicalHistory: "",
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      // Backend synchronization: Convert age to number and role to uppercase
      const payload = {
        ...formData,
        age: parseInt(formData.age) || 0,
        role: role.toUpperCase(),
        // Default medical history if empty to satisfy backend @NotBlank if applicable
        medicalHistory: role === "doctor" ? "Specialist Profile" : (formData.medicalHistory || "No history provided")
      };

      await signup(payload);
      
      setLoading(false);
      setSuccess(true);
      
      // Delay navigation to allow success animation to show
      setTimeout(() => navigate("/login"), 2000);
    } catch (err: any) {
      setLoading(false);
      // Fallback message to prevent crashing on empty responses
      const errorMessage = err.response?.data?.message || "Registration failed. Please check your connection.";
      setError(errorMessage);
    }
  };

  return (
    <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
      {/* Ambient backgrounds */}
      <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
      <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

      <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} transition={{ duration: 0.6 }} className="w-full max-w-md py-8">
        <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
            <span className="text-accent-foreground font-bold">M</span>
          </div>
          <span className="font-display text-2xl font-bold text-foreground">Medi<span className="text-gradient-accent">bot</span></span>
        </Link>

        <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
          <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Create Account</h2>
          <p className="text-muted-foreground text-center text-sm mb-6">Join the future of healthcare</p>

          {/* Role Toggle - type="button" is required to prevent accidental form submission */}
          <div className="flex glass rounded-2xl p-1 mb-6">
            {(["patient", "doctor"] as const).map((r) => (
              <button 
                key={r} 
                type="button" 
                onClick={() => setRole(r)} 
                className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all duration-300 ${role === r ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent" : "text-muted-foreground hover:text-foreground"}`}
              >
                {r === "patient" ? <User size={16} /> : <Stethoscope size={16} />}
                {r === "patient" ? "Patient" : "Doctor"}
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {success ? (
              <motion.div key="success" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} className="text-center py-8">
                <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
                  <ArrowRight size={32} className="text-success" />
                </div>
                <h3 className="font-display text-xl font-bold text-foreground mb-2">Account Created!</h3>
                <p className="text-muted-foreground text-sm">Redirecting to login...</p>
              </motion.div>
            ) : (
              <motion.form key={role} initial={{ opacity: 0, x: role === "patient" ? -20 : 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.3 }} onSubmit={handleSubmit} className="space-y-3">
                
                <div className="grid grid-cols-2 gap-3">
                  <InputField icon={User} name="firstName" placeholder="First Name" type="text" value={formData.firstName} onChange={handleInputChange} required />
                  <InputField icon={User} name="lastName" placeholder="Last Name" type="text" value={formData.lastName} onChange={handleInputChange} required />
                </div>

                <InputField icon={Mail} name="email" placeholder="Email Address" type="email" value={formData.email} onChange={handleInputChange} required />
                
                <div className="relative">
                  <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
                  <input name="password" type={showPassword ? "text" : "password"} placeholder="Password" required value={formData.password} onChange={handleInputChange} className={inputClass + " pr-11"} />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <InputField icon={Calendar} name="age" placeholder="Age" type="number" value={formData.age} onChange={handleInputChange} required />
                  <div className="relative">
                    <Users size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <select name="gender" value={formData.gender} onChange={handleInputChange} className={inputClass}>
                      <option value="Male">Male</option>
                      <option value="Female">Female</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>
                </div>

                {role === "patient" && (
                  <div className="relative">
                    <ClipboardList size={16} className="absolute left-4 top-4 text-muted-foreground" />
                    <textarea name="medicalHistory" placeholder="Medical History (Allergies, conditions...)" value={formData.medicalHistory} onChange={handleInputChange} className={inputClass + " pl-11 h-24 resize-none pt-3"} required />
                  </div>
                )}

                {error && <p className="text-destructive text-xs text-center font-medium bg-destructive/5 py-2 rounded-lg">{error}</p>}

                <Button type="submit" disabled={loading} className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group mt-2">
                  {loading ? (
                    <div className="flex items-center gap-2">
                      <Loader2 className="animate-spin" size={16} />
                      Creating Account...
                    </div>
                  ) : (
                    <>Create Account <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" /></>
                  )}
                </Button>
              </motion.form>
            )}
          </AnimatePresence>

          <p className="text-center text-sm text-muted-foreground mt-6">
            Already have an account? <Link to="/login" className="text-accent font-semibold hover:underline">Sign In</Link>
          </p>
        </div>
      </motion.div>
    </div>
  );
};

export default Signup;