// // // import { useState } from "react";
// // // import { motion, AnimatePresence } from "framer-motion";
// // // import { Mail, Lock, ArrowRight, Stethoscope, User, Eye, EyeOff } from "lucide-react";
// // // import { Button } from "@/components/ui/button";
// // // import { Link } from "react-router-dom";

// // // const Login = () => {
// // //   const [role, setRole] = useState<"patient" | "doctor">("patient");
// // //   const [email, setEmail] = useState("");
// // //   const [password, setPassword] = useState("");
// // //   const [showPassword, setShowPassword] = useState(false);
// // //   const [loading, setLoading] = useState(false);
// // //   const [error, setError] = useState("");
// // //   const [success, setSuccess] = useState(false);

// // //   const handleSubmit = (e: React.FormEvent) => {
// // //     e.preventDefault();
// // //     setError("");
// // //     if (!email || !password) {
// // //       setError("Please fill in all fields");
// // //       return;
// // //     }
// // //     setLoading(true);
// // //     setTimeout(() => {
// // //       setLoading(false);
// // //       setSuccess(true);
// // //     }, 1500);
// // //   };

// // //   return (
// // //     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
// // //       {/* Ambient blobs */}
// // //       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
// // //       <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

// // //       <motion.div
// // //         initial={{ opacity: 0, scale: 0.95, y: 20 }}
// // //         animate={{ opacity: 1, scale: 1, y: 0 }}
// // //         transition={{ duration: 0.6, ease: "easeOut" }}
// // //         className="w-full max-w-md"
// // //       >
// // //         {/* Logo */}
// // //         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
// // //           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
// // //             <span className="text-accent-foreground font-bold">M</span>
// // //           </div>
// // //           <span className="font-display text-2xl font-bold text-foreground">
// // //             Medi<span className="text-gradient-accent">bot</span>
// // //           </span>
// // //         </Link>

// // //         <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
// // //           <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Welcome Back</h2>
// // //           <p className="text-muted-foreground text-center text-sm mb-6">Sign in to continue your healthcare journey</p>

// // //           {/* Role Toggle */}
// // //           <div className="flex glass rounded-2xl p-1 mb-6">
// // //             {(["patient", "doctor"] as const).map((r) => (
// // //               <button
// // //                 key={r}
// // //                 onClick={() => setRole(r)}
// // //                 className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all duration-300 ${
// // //                   role === r
// // //                     ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent"
// // //                     : "text-muted-foreground hover:text-foreground"
// // //                 }`}
// // //               >
// // //                 {r === "patient" ? <User size={16} /> : <Stethoscope size={16} />}
// // //                 {r === "patient" ? "Patient" : "Doctor"}
// // //               </button>
// // //             ))}
// // //           </div>

// // //           <AnimatePresence mode="wait">
// // //             {success ? (
// // //               <motion.div
// // //                 key="success"
// // //                 initial={{ opacity: 0, scale: 0.8 }}
// // //                 animate={{ opacity: 1, scale: 1 }}
// // //                 className="text-center py-8"
// // //               >
// // //                 <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
// // //                   <ArrowRight size={32} className="text-success" />
// // //                 </div>
// // //                 <h3 className="font-display text-xl font-bold text-foreground mb-2">Login Successful!</h3>
// // //                 <p className="text-muted-foreground text-sm">Redirecting to your dashboard...</p>
// // //               </motion.div>
// // //             ) : (
// // //               <motion.form
// // //                 key="form"
// // //                 onSubmit={handleSubmit}
// // //                 initial={{ opacity: 0 }}
// // //                 animate={{ opacity: 1 }}
// // //                 exit={{ opacity: 0 }}
// // //                 className="space-y-4"
// // //               >
// // //                 <div>
// // //                   <label className="text-sm font-medium text-foreground mb-1.5 block">Email</label>
// // //                   <div className="relative">
// // //                     <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// // //                     <input
// // //                       type="email"
// // //                       value={email}
// // //                       onChange={(e) => setEmail(e.target.value)}
// // //                       placeholder="your@email.com"
// // //                       className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
// // //                     />
// // //                   </div>
// // //                 </div>

// // //                 <div>
// // //                   <label className="text-sm font-medium text-foreground mb-1.5 block">Password</label>
// // //                   <div className="relative">
// // //                     <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// // //                     <input
// // //                       type={showPassword ? "text" : "password"}
// // //                       value={password}
// // //                       onChange={(e) => setPassword(e.target.value)}
// // //                       placeholder="••••••••"
// // //                       className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
// // //                     />
// // //                     <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
// // //                       {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
// // //                     </button>
// // //                   </div>
// // //                 </div>

// // //                 {error && (
// // //                   <motion.p
// // //                     initial={{ opacity: 0, x: -10 }}
// // //                     animate={{ opacity: 1, x: [0, -5, 5, -5, 0] }}
// // //                     transition={{ duration: 0.4 }}
// // //                     className="text-destructive text-sm text-center"
// // //                   >
// // //                     {error}
// // //                   </motion.p>
// // //                 )}

// // //                 <Button
// // //                   type="submit"
// // //                   disabled={loading}
// // //                   className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group"
// // //                 >
// // //                   {loading ? (
// // //                     <div className="flex items-center gap-2">
// // //                       <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
// // //                       Signing in...
// // //                     </div>
// // //                   ) : (
// // //                     <>
// // //                       Sign In
// // //                       <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" />
// // //                     </>
// // //                   )}
// // //                 </Button>
// // //               </motion.form>
// // //             )}
// // //           </AnimatePresence>

// // //           <p className="text-center text-sm text-muted-foreground mt-6">
// // //             Don't have an account?{" "}
// // //             <Link to="/signup" className="text-accent font-semibold hover:underline">
// // //               Sign Up
// // //             </Link>
// // //           </p>
// // //         </div>
// // //       </motion.div>
// // //     </div>
// // //   );
// // // };

// // // export default Login;


// // import { useState } from "react";
// // import { motion, AnimatePresence } from "framer-motion";
// // import { Mail, Lock, ArrowRight, Stethoscope, User, Eye, EyeOff } from "lucide-react";
// // import { Button } from "@/components/ui/button";
// // import { Link, useNavigate } from "react-router-dom"; // Added useNavigate
// // import { login } from "@/services/authService"; // Imported your service

// // const Login = () => {
// //   const navigate = useNavigate();
// //   const [role, setRole] = useState<"patient" | "doctor">("patient");
// //   const [email, setEmail] = useState("");
// //   const [password, setPassword] = useState("");
// //   const [showPassword, setShowPassword] = useState(false);
// //   const [loading, setLoading] = useState(false);
// //   const [error, setError] = useState("");
// //   const [success, setSuccess] = useState(false);

// //   const handleSubmit = async (e: React.FormEvent) => {
// //     e.preventDefault();
// //     setError("");
    
// //     if (!email || !password) {
// //       setError("Please fill in all fields");
// //       return;
// //     }
    
// //     setLoading(true);

// //     try {
// //       // Direct integration with your Spring Boot /api/auth/login
// //       const data = await login({ email, password });
      
// //       setLoading(false);
// //       setSuccess(true);

// //       // Role-based redirection logic using the backend's response
// //       setTimeout(() => {
// //         const userRole = data.role.toUpperCase();
// //         if (userRole === "ADMIN") {
// //           navigate("/admin/dashboard");
// //         } else if (userRole === "DOCTOR") {
// //           navigate("/doctor/dashboard");
// //         } else {
// //           navigate("/patient/dashboard");
// //         }
// //       }, 1500);
      
// //     } catch (err: any) {
// //       setLoading(false);
// //       // Handles 401 Unauthorized or 404 from your backend
// //       setError(err.response?.data?.message || "Invalid email or password. Please try again.");
// //     }
// //   };

// //   return (
// //     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
// //       {/* Ambient blobs */}
// //       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
// //       <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

// //       <motion.div
// //         initial={{ opacity: 0, scale: 0.95, y: 20 }}
// //         animate={{ opacity: 1, scale: 1, y: 0 }}
// //         transition={{ duration: 0.6, ease: "easeOut" }}
// //         className="w-full max-w-md"
// //       >
// //         {/* Logo */}
// //         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
// //           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
// //             <span className="text-accent-foreground font-bold">M</span>
// //           </div>
// //           <span className="font-display text-2xl font-bold text-foreground">
// //             Medi<span className="text-gradient-accent">bot</span>
// //           </span>
// //         </Link>

// //         <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
// //           <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Welcome Back</h2>
// //           <p className="text-muted-foreground text-center text-sm mb-6">Sign in to continue your healthcare journey</p>

// //           {/* Role Toggle */}
// //           <div className="flex glass rounded-2xl p-1 mb-6">
// //             {(["patient", "doctor"] as const).map((r) => (
// //               <button
// //                 key={r}
// //                 type="button"
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
// //               <motion.div
// //                 key="success"
// //                 initial={{ opacity: 0, scale: 0.8 }}
// //                 animate={{ opacity: 1, scale: 1 }}
// //                 className="text-center py-8"
// //               >
// //                 <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
// //                   <ArrowRight size={32} className="text-success" />
// //                 </div>
// //                 <h3 className="font-display text-xl font-bold text-foreground mb-2">Login Successful!</h3>
// //                 <p className="text-muted-foreground text-sm">Redirecting to your dashboard...</p>
// //               </motion.div>
// //             ) : (
// //               <motion.form
// //                 key="form"
// //                 onSubmit={handleSubmit}
// //                 initial={{ opacity: 0 }}
// //                 animate={{ opacity: 1 }}
// //                 exit={{ opacity: 0 }}
// //                 className="space-y-4"
// //               >
// //                 <div>
// //                   <label className="text-sm font-medium text-foreground mb-1.5 block">Email</label>
// //                   <div className="relative">
// //                     <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// //                     <input
// //                       type="email"
// //                       value={email}
// //                       onChange={(e) => setEmail(e.target.value)}
// //                       placeholder="your@email.com"
// //                       className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
// //                       required
// //                     />
// //                   </div>
// //                 </div>

// //                 <div>
// //                   <label className="text-sm font-medium text-foreground mb-1.5 block">Password</label>
// //                   <div className="relative">
// //                     <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// //                     <input
// //                       type={showPassword ? "text" : "password"}
// //                       value={password}
// //                       onChange={(e) => setPassword(e.target.value)}
// //                       placeholder="••••••••"
// //                       className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
// //                       required
// //                     />
// //                     <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
// //                       {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
// //                     </button>
// //                   </div>
// //                 </div>

// //                 {error && (
// //                   <motion.p
// //                     initial={{ opacity: 0, x: -10 }}
// //                     animate={{ opacity: 1, x: [0, -5, 5, -5, 0] }}
// //                     transition={{ duration: 0.4 }}
// //                     className="text-destructive text-sm text-center"
// //                   >
// //                     {error}
// //                   </motion.p>
// //                 )}

// //                 <Button
// //                   type="submit"
// //                   disabled={loading}
// //                   className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group"
// //                 >
// //                   {loading ? (
// //                     <div className="flex items-center gap-2">
// //                       <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
// //                       Signing in...
// //                     </div>
// //                   ) : (
// //                     <>
// //                       Sign In
// //                       <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" />
// //                     </>
// //                   )}
// //                 </Button>
// //               </motion.form>
// //             )}
// //           </AnimatePresence>

// //           <p className="text-center text-sm text-muted-foreground mt-6">
// //             Don't have an account?{" "}
// //             <Link to="/signup" className="text-accent font-semibold hover:underline">
// //               Sign Up
// //             </Link>
// //           </p>
// //         </div>
// //       </motion.div>
// //     </div>
// //   );
// // };

// // export default Login;




// import { useState } from "react";
// import { motion, AnimatePresence } from "framer-motion";
// import { Mail, Lock, ArrowRight, Stethoscope, User, Eye, EyeOff } from "lucide-react";
// import { Button } from "@/components/ui/button";
// import { Link, useNavigate } from "react-router-dom"; 
// import { login } from "@/services/authService"; 

// const Login = () => {
//   const navigate = useNavigate();
//   const [role, setRole] = useState<"patient" | "doctor">("patient");
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [showPassword, setShowPassword] = useState(false);
//   const [loading, setLoading] = useState(false);
//   const [error, setError] = useState("");
//   const [success, setSuccess] = useState(false);

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setError("");
    
//     if (!email || !password) {
//       setError("Please fill in all fields");
//       return;
//     }
    
//     setLoading(true);

//     try {
//       // Direct integration with your authService
//       const data = await login({ email, password });
      
//       setLoading(false);
//       setSuccess(true);

//       // Robust redirection logic using the role returned from the backend
//       setTimeout(() => {
//         const userRole = data.role?.toUpperCase();
//         if (userRole === "ADMIN") {
//           navigate("/admin/dashboard");
//         } else if (userRole === "DOCTOR") {
//           navigate("/doctor/dashboard");
//         } else {
//           // Default to patient if role is PATIENT or unknown
//           navigate("/patient/dashboard");
//         }
//       }, 1500);
      
//     } catch (err: any) {
//       setLoading(false);
//       // Handles 401 Unauthorized or 404 from your backend
//       const errorMessage = err.response?.data?.message || "Invalid email or password. Please try again.";
//       setError(errorMessage);
//       console.error("Login attempt failed:", err);
//     }
//   };

//   return (
//     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
//       {/* Ambient blobs */}
//       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
//       <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

//       <motion.div
//         initial={{ opacity: 0, scale: 0.95, y: 20 }}
//         animate={{ opacity: 1, scale: 1, y: 0 }}
//         transition={{ duration: 0.6, ease: "easeOut" }}
//         className="w-full max-w-md"
//       >
//         {/* Logo */}
//         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
//           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
//             <span className="text-accent-foreground font-bold">M</span>
//           </div>
//           <span className="font-display text-2xl font-bold text-foreground">
//             Medi<span className="text-gradient-accent">bot</span>
//           </span>
//         </Link>

//         <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
//           <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Welcome Back</h2>
//           <p className="text-muted-foreground text-center text-sm mb-6">Sign in to continue your healthcare journey</p>

//           {/* Role Toggle */}
//           <div className="flex glass rounded-2xl p-1 mb-6">
//             {(["patient", "doctor"] as const).map((r) => (
//               <button
//                 key={r}
//                 type="button" // Fix: prevent form submission on toggle
//                 onClick={() => setRole(r)}
//                 className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all duration-300 ${
//                   role === r
//                     ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent"
//                     : "text-muted-foreground hover:text-foreground"
//                 }`}
//               >
//                 {r === "patient" ? <User size={16} /> : <Stethoscope size={16} />}
//                 {r === "patient" ? "Patient" : "Doctor"}
//               </button>
//             ))}
//           </div>

//           <AnimatePresence mode="wait">
//             {success ? (
//               <motion.div
//                 key="success"
//                 initial={{ opacity: 0, scale: 0.8 }}
//                 animate={{ opacity: 1, scale: 1 }}
//                 className="text-center py-8"
//               >
//                 <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
//                   <ArrowRight size={32} className="text-success" />
//                 </div>
//                 <h3 className="font-display text-xl font-bold text-foreground mb-2">Login Successful!</h3>
//                 <p className="text-muted-foreground text-sm">Redirecting to your dashboard...</p>
//               </motion.div>
//             ) : (
//               <motion.form
//                 key="form"
//                 onSubmit={handleSubmit}
//                 initial={{ opacity: 0 }}
//                 animate={{ opacity: 1 }}
//                 exit={{ opacity: 0 }}
//                 className="space-y-4"
//               >
//                 <div>
//                   <label className="text-sm font-medium text-foreground mb-1.5 block">Email</label>
//                   <div className="relative">
//                     <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                     <input
//                       type="email"
//                       value={email}
//                       onChange={(e) => setEmail(e.target.value)}
//                       placeholder="your@email.com"
//                       className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
//                       required
//                     />
//                   </div>
//                 </div>

//                 <div>
//                   <label className="text-sm font-medium text-foreground mb-1.5 block">Password</label>
//                   <div className="relative">
//                     <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                     <input
//                       type={showPassword ? "text" : "password"}
//                       value={password}
//                       onChange={(e) => setPassword(e.target.value)}
//                       placeholder="••••••••"
//                       className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
//                       required
//                     />
//                     <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
//                       {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
//                     </button>
//                   </div>
//                 </div>

//                 {error && (
//                   <motion.p
//                     initial={{ opacity: 0, x: -10 }}
//                     animate={{ opacity: 1, x: [0, -5, 5, -5, 0] }}
//                     transition={{ duration: 0.4 }}
//                     className="text-destructive text-sm text-center"
//                   >
//                     {error}
//                   </motion.p>
//                 )}

//                 <Button
//                   type="submit"
//                   disabled={loading}
//                   className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group"
//                 >
//                   {loading ? (
//                     <div className="flex items-center gap-2">
//                       <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
//                       Signing in...
//                     </div>
//                   ) : (
//                     <>
//                       Sign In
//                       <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" />
//                     </>
//                   )}
//                 </Button>
//               </motion.form>
//             )}
//           </AnimatePresence>

//           <p className="text-center text-sm text-muted-foreground mt-6">
//             Don't have an account?{" "}
//             <Link to="/signup" className="text-accent font-semibold hover:underline">
//               Sign Up
//             </Link>
//           </p>
//         </div>
//       </motion.div>
//     </div>
//   );
// };

// export default Login;


// import { useState } from "react";
// import { motion, AnimatePresence } from "framer-motion";
// import { Mail, Lock, ArrowRight, Stethoscope, User, Eye, EyeOff } from "lucide-react";
// import { Button } from "@/components/ui/button";
// import { Link, useNavigate } from "react-router-dom"; 
// import { login } from "@/services/authService"; 

// const Login = () => {
//   const navigate = useNavigate();
//   const [role, setRole] = useState<"patient" | "doctor">("patient");
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [showPassword, setShowPassword] = useState(false);
//   const [loading, setLoading] = useState(false);
//   const [error, setError] = useState("");
//   const [success, setSuccess] = useState(false);

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setError("");
    
//     if (!email || !password) {
//       setError("Please fill in all fields");
//       return;
//     }
    
//     setLoading(true);

//     try {
//       // 1. Trigger the logic in authService.ts
//       const data = await login({ email, password });
      
//       // 2. VERIFICATION: Check the key standardized in your service
//       const checkId = localStorage.getItem("userId");
      
//       // DEBUG: If this shows 'undefined', your authService didn't find the key
//       console.log("LOGIN_CLIENT_DEBUG: Verifying stored ID:", checkId);

//       if (!checkId || checkId === "undefined" || checkId === "null") {
//           throw new Error("System failed to link your profile ID. Check your backend response keys.");
//       }

//       setLoading(false);
//       setSuccess(true);

//       // 3. Role-based navigation using standardized backend strings
//       setTimeout(() => {
//         const userRole = data.role?.toUpperCase();
//         if (userRole === "ADMIN") {
//           navigate("/admin/dashboard");
//         } else if (userRole === "DOCTOR") {
//           navigate("/doctor/dashboard");
//         } else {
//           navigate("/patient/dashboard");
//         }
//       }, 1500);
      
//     } catch (err: any) {
//       setLoading(false);
//       // Handles 401 Unauthorized, 404, or internal logic errors
//       const errorMessage = err.response?.data?.message || err.message || "Invalid credentials.";
//       setError(errorMessage);
//       console.error("LOGIN_ERROR_DETAILS:", err);
//     }
//   };

//   return (
//     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
//       {/* Background Blobs */}
//       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
//       <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

//       <motion.div
//         initial={{ opacity: 0, scale: 0.95, y: 20 }}
//         animate={{ opacity: 1, scale: 1, y: 0 }}
//         transition={{ duration: 0.6, ease: "easeOut" }}
//         className="w-full max-w-md"
//       >
//         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
//           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
//             <span className="text-accent-foreground font-bold">M</span>
//           </div>
//           <span className="font-display text-2xl font-bold text-foreground">
//             Medi<span className="text-gradient-accent">bot</span>
//           </span>
//         </Link>

//         <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
//           <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Welcome Back</h2>
//           <p className="text-muted-foreground text-center text-sm mb-6">Sign in to continue your journey</p>

//           {/* Role Toggle */}
//           <div className="flex glass rounded-2xl p-1 mb-6">
//             {(["patient", "doctor"] as const).map((r) => (
//               <button
//                 key={r}
//                 type="button" 
//                 onClick={() => setRole(r)}
//                 className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all duration-300 ${
//                   role === r
//                     ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent"
//                     : "text-muted-foreground hover:text-foreground"
//                 }`}
//               >
//                 {r === "patient" ? <User size={16} /> : <Stethoscope size={16} />}
//                 {r === "patient" ? "Patient" : "Doctor"}
//               </button>
//             ))}
//           </div>

//           <AnimatePresence mode="wait">
//             {success ? (
//               <motion.div
//                 key="success"
//                 initial={{ opacity: 0, scale: 0.8 }}
//                 animate={{ opacity: 1, scale: 1 }}
//                 className="text-center py-8"
//               >
//                 <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
//                   <ArrowRight size={32} className="text-success" />
//                 </div>
//                 <h3 className="font-display text-xl font-bold text-foreground mb-2">Login Successful!</h3>
//                 <p className="text-muted-foreground text-sm">Redirecting to your dashboard...</p>
//               </motion.div>
//             ) : (
//               <motion.form
//                 key="form"
//                 onSubmit={handleSubmit}
//                 initial={{ opacity: 0 }}
//                 animate={{ opacity: 1 }}
//                 exit={{ opacity: 0 }}
//                 className="space-y-4"
//               >
//                 <div>
//                   <label className="text-sm font-medium text-foreground mb-1.5 block">Email</label>
//                   <div className="relative">
//                     <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                     <input
//                       type="email"
//                       value={email}
//                       onChange={(e) => setEmail(e.target.value)}
//                       placeholder="your@email.com"
//                       className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
//                       required
//                     />
//                   </div>
//                 </div>

//                 <div>
//                   <label className="text-sm font-medium text-foreground mb-1.5 block">Password</label>
//                   <div className="relative">
//                     <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                     <input
//                       type={showPassword ? "text" : "password"}
//                       value={password}
//                       onChange={(e) => setPassword(e.target.value)}
//                       placeholder="••••••••"
//                       className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
//                       required
//                     />
//                     <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
//                       {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
//                     </button>
//                   </div>
//                 </div>

//                 {error && (
//                   <motion.p
//                     initial={{ opacity: 0, x: -10 }}
//                     animate={{ opacity: 1, x: [0, -5, 5, -5, 0] }}
//                     transition={{ duration: 0.4 }}
//                     className="text-destructive text-sm text-center"
//                   >
//                     {error}
//                   </motion.p>
//                 )}

//                 <Button
//                   type="submit"
//                   disabled={loading}
//                   className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group"
//                 >
//                   {loading ? (
//                     <div className="flex items-center gap-2">
//                       <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
//                       Signing in...
//                     </div>
//                   ) : (
//                     <>
//                       Sign In
//                       <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" />
//                     </>
//                   )}
//                 </Button>
//               </motion.form>
//             )}
//           </AnimatePresence>

//           <p className="text-center text-sm text-muted-foreground mt-6">
//             Don't have an account?{" "}
//             <Link to="/signup" className="text-accent font-semibold hover:underline">
//               Sign Up
//             </Link>
//           </p>
//         </div>
//       </motion.div>
//     </div>
//   );
// };

// export default Login;




import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mail, Lock, ArrowRight, Stethoscope, User, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link, useNavigate } from "react-router-dom"; 
import { login } from "@/services/authService"; 

const Login = () => {
  const navigate = useNavigate();
  const [role, setRole] = useState<"patient" | "doctor">("patient");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    
    if (!email || !password) {
      setError("Please fill in all fields");
      return;
    }
    
    setLoading(true);

    try {
      // 1. Service handles storage and standardization
      const data = await login({ email, password });
      
      // 2. Immediate verification check
      const checkId = localStorage.getItem("userId");
      
      if (!checkId || checkId === "undefined" || checkId === "null") {
          console.error("ID Verification Failed. Data received:", data);
          throw new Error("Login successful, but profile synchronization failed. Please clear cache and retry.");
      }

      setLoading(false);
      setSuccess(true);

      // 3. Navigation using backend role
      setTimeout(() => {
        const userRole = data.role?.toUpperCase();
        if (userRole === "ADMIN") navigate("/admin/dashboard");
        else if (userRole === "DOCTOR") navigate("/doctor/dashboard");
        else navigate("/patient/dashboard");
      }, 1500);
      
    } catch (err: any) {
      setLoading(false);
      // Display the most helpful error message
      const message = err.response?.data?.message || err.message || "Invalid credentials.";
      setError(message);
    }
  };

  return (
    <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />
      <div className="absolute -bottom-40 -left-40 w-[400px] h-[400px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe pointer-events-none" style={{ animationDelay: "3s" }} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className="w-full max-w-md"
      >
        <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
            <span className="text-accent-foreground font-bold">M</span>
          </div>
          <span className="font-display text-2xl font-bold text-foreground">
            Medi<span className="text-gradient-accent">bot</span>
          </span>
        </Link>

        <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
          <h2 className="font-display text-2xl font-bold text-foreground text-center mb-2">Welcome Back</h2>
          <p className="text-muted-foreground text-center text-sm mb-6">Sign in to continue your journey</p>

          <div className="flex glass rounded-2xl p-1 mb-6">
            {(["patient", "doctor"] as const).map((r) => (
              <button
                key={r}
                type="button" 
                onClick={() => setRole(r)}
                className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all duration-300 ${
                  role === r
                    ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {r === "patient" ? <User size={16} /> : <Stethoscope size={16} />}
                {r === "patient" ? "Patient" : "Doctor"}
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {success ? (
              <motion.div
                key="success"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-center py-8"
              >
                <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto mb-4 animate-pulse-soft">
                  <ArrowRight size={32} className="text-success" />
                </div>
                <h3 className="font-display text-xl font-bold text-foreground mb-2">Login Successful!</h3>
                <p className="text-muted-foreground text-sm">Redirecting to your dashboard...</p>
              </motion.div>
            ) : (
              <motion.form
                key="form"
                onSubmit={handleSubmit}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="space-y-4"
              >
                <div>
                  <label className="text-sm font-medium text-foreground mb-1.5 block">Email</label>
                  <div className="relative">
                    <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="your@email.com"
                      className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="text-sm font-medium text-foreground mb-1.5 block">Password</label>
                  <div className="relative">
                    <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all"
                      required
                    />
                    <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>

                {error && (
                  <motion.p
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: [0, -5, 5, -5, 0] }}
                    transition={{ duration: 0.4 }}
                    className="text-destructive text-sm text-center"
                  >
                    {error}
                  </motion.p>
                )}

                <Button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300 group"
                >
                  {loading ? (
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
                      Signing in...
                    </div>
                  ) : (
                    <>
                      Sign In
                      <ArrowRight size={16} className="ml-2 transition-transform group-hover:translate-x-1" />
                    </>
                  )}
                </Button>
              </motion.form>
            )}
          </AnimatePresence>

          <p className="text-center text-sm text-muted-foreground mt-6">
            Don't have an account?{" "}
            <Link to="/signup" className="text-accent font-semibold hover:underline">
              Sign Up
            </Link>
          </p>
        </div>
      </motion.div>
    </div>
  );
};

export default Login;