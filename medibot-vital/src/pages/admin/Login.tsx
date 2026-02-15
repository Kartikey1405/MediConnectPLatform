// // import { useState } from "react";
// // import { motion } from "framer-motion";
// // import { Mail, Lock, Shield, ArrowRight, Eye, EyeOff } from "lucide-react";
// // import { Button } from "@/components/ui/button";
// // import { Link } from "react-router-dom";

// // const AdminLogin = () => {
// //   const [email, setEmail] = useState("");
// //   const [password, setPassword] = useState("");
// //   const [showPassword, setShowPassword] = useState(false);
// //   const [loading, setLoading] = useState(false);

// //   const handleSubmit = (e: React.FormEvent) => {
// //     e.preventDefault();
// //     setLoading(true);
// //     setTimeout(() => setLoading(false), 1500);
// //   };

// //   return (
// //     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
// //       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />

// //       <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.6 }} className="w-full max-w-md">
// //         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
// //           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent">
// //             <span className="text-accent-foreground font-bold">M</span>
// //           </div>
// //           <span className="font-display text-2xl font-bold text-foreground">Medi<span className="text-gradient-accent">bot</span></span>
// //         </Link>

// //         <div className="glass-strong rounded-3xl p-8 shadow-float-lg">
// //           <div className="flex items-center justify-center gap-2 mb-6">
// //             <Shield size={24} className="text-accent" />
// //             <h2 className="font-display text-2xl font-bold text-foreground">Admin Portal</h2>
// //           </div>
// //           <p className="text-muted-foreground text-center text-sm mb-6">Restricted access — authorized personnel only</p>

// //           <form onSubmit={handleSubmit} className="space-y-4">
// //             <div className="relative">
// //               <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// //               <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Admin Email"
// //                 className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50" />
// //             </div>
// //             <div className="relative">
// //               <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
// //               <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password"
// //                 className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/50 text-sm outline-none focus:ring-2 focus:ring-accent/50" />
// //               <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
// //                 {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
// //               </button>
// //             </div>
// //             <Button type="submit" disabled={loading}
// //               className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold py-6 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all group">
// //               {loading ? <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" /> :
// //                 <><Shield size={16} className="mr-2" /> Access Admin Panel <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" /></>}
// //             </Button>
// //           </form>
// //         </div>
// //       </motion.div>
// //     </div>
// //   );
// // };

// // export default AdminLogin;






// // 


// import { useState } from "react";
// import { motion } from "framer-motion";
// import { Mail, Lock, Shield, ArrowRight, Eye, EyeOff, Loader2 } from "lucide-react";
// import { Button } from "@/components/ui/button";
// import { Link, useNavigate } from "react-router-dom";
// // Use authService for Identity, adminService for Management
// import { authService } from "@/services/authService"; 
// import { toast } from "sonner";

// const AdminLogin = () => {
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [showPassword, setShowPassword] = useState(false);
//   const [loading, setLoading] = useState(false);
//   const navigate = useNavigate();

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setLoading(true);

//     try {
//       // 1. Authenticate through the central Auth Service
//       const response = await authService.login(email, password);

//       // 2. Role-Based Access Control (RBAC) check
//       // Ensure the backend returned the 'ADMIN' role
//       if (response.role === "ADMIN") {
//         toast.success("Identity Verified. Accessing Admin Dashboard...");
//         navigate("/admin/dashboard");
//       } else {
//         // Prevent unauthorized roles (Patient/Doctor) from accessing the portal
//         toast.error("Access Denied: Administrative privileges required.");
//         authService.logout(); 
//       }
//     } catch (error: any) {
//       const message = error.response?.data?.message || "Invalid credentials.";
//       toast.error(message);
//     } finally {
//       setLoading(false);
//     }
//   };

//   return (
//     <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
//       <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />

//       <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.6 }} className="w-full max-w-md">
//         <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
//           <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent">
//             <span className="text-accent-foreground font-bold">M</span>
//           </div>
//           <span className="font-display text-2xl font-bold text-foreground">Medi<span className="text-gradient-accent">bot</span></span>
//         </Link>

//         <div className="glass-strong rounded-3xl p-8 shadow-float-lg border border-white/10">
//           <div className="flex items-center justify-center gap-2 mb-2">
//             <Shield size={24} className="text-accent" />
//             <h2 className="font-display text-2xl font-bold text-foreground">Admin Portal</h2>
//           </div>
//           <p className="text-muted-foreground text-center text-xs mb-8">Secure Gateway for Authorized Personnel</p>

//           <form onSubmit={handleSubmit} className="space-y-5">
//             <div className="space-y-2">
//               <label className="text-xs font-semibold text-muted-foreground ml-1">Admin Email</label>
//               <div className="relative">
//                 <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                 <input 
//                   type="email" 
//                   value={email} 
//                   required
//                   onChange={(e) => setEmail(e.target.value)} 
//                   placeholder="admin@medibot.com"
//                   className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/30 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all" 
//                 />
//               </div>
//             </div>

//             <div className="space-y-2">
//               <label className="text-xs font-semibold text-muted-foreground ml-1">Security Token (Password)</label>
//               <div className="relative">
//                 <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
//                 <input 
//                   type={showPassword ? "text" : "password"} 
//                   value={password} 
//                   required
//                   onChange={(e) => setPassword(e.target.value)} 
//                   placeholder="••••••••"
//                   className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/30 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all" 
//                 />
//                 <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
//                   {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
//                 </button>
//               </div>
//             </div>

//             <Button type="submit" disabled={loading}
//               className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-bold py-7 rounded-2xl shadow-glow-accent hover:scale-[1.01] active:scale-[0.98] transition-all group">
//               {loading ? <Loader2 className="animate-spin" size={20} /> :
//                 <><Shield size={18} className="mr-2" /> Open Admin Portal <ArrowRight size={18} className="ml-2 group-hover:translate-x-1 transition-transform" /></>}
//             </Button>
//           </form>
//         </div>
//       </motion.div>
//     </div>
//   );
// };

// export default AdminLogin;



import { useState } from "react";
import { motion } from "framer-motion";
import { Mail, Lock, Shield, ArrowRight, Eye, EyeOff, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link, useNavigate } from "react-router-dom";
import { authService } from "@/services/authService"; 
import { toast } from "sonner";

const AdminLogin = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      // FIX: Wrap credentials in a single object { email, password }
      // This solves the "Expected 1 arguments, but got 2" error
      const response = await authService.login({ email, password });

      // 2. Role-Based Access Control (RBAC) check
      if (response.role === "ADMIN") {
        toast.success("Identity Verified. Accessing Admin Dashboard...");
        navigate("/admin/dashboard");
      } else {
        // Prevent unauthorized roles (Patient/Doctor) from accessing the portal
        toast.error("Access Denied: Administrative privileges required.");
        authService.logout(); 
      }
    } catch (error: any) {
      const message = error.response?.data?.message || "Invalid credentials.";
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen mesh-gradient flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute -top-40 -right-40 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe pointer-events-none" />

      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.6 }} className="w-full max-w-md">
        <Link to="/" className="flex items-center justify-center gap-2 mb-8 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent">
            <span className="text-accent-foreground font-bold">M</span>
          </div>
          <span className="font-display text-2xl font-bold text-foreground">Medi<span className="text-gradient-accent">bot</span></span>
        </Link>

        <div className="glass-strong rounded-3xl p-8 shadow-float-lg border border-white/10">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Shield size={24} className="text-accent" />
            <h2 className="font-display text-2xl font-bold text-foreground">Admin Portal</h2>
          </div>
          <p className="text-muted-foreground text-center text-xs mb-8">Secure Gateway for Authorized Personnel</p>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <label className="text-xs font-semibold text-muted-foreground ml-1">Admin Email</label>
              <div className="relative">
                <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input 
                  type="email" 
                  value={email} 
                  required
                  onChange={(e) => setEmail(e.target.value)} 
                  placeholder="admin@medibot.com"
                  className="w-full pl-11 pr-4 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/30 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all" 
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-semibold text-muted-foreground ml-1">Password</label>
              <div className="relative">
                <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input 
                  type={showPassword ? "text" : "password"} 
                  value={password} 
                  required
                  onChange={(e) => setPassword(e.target.value)} 
                  placeholder="••••••••"
                  className="w-full pl-11 pr-11 py-3 rounded-xl glass text-foreground placeholder:text-muted-foreground/30 text-sm outline-none focus:ring-2 focus:ring-accent/50 transition-all" 
                />
                <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <Button type="submit" disabled={loading}
              className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-bold py-7 rounded-2xl shadow-glow-accent hover:scale-[1.01] active:scale-[0.98] transition-all group">
              {loading ? <Loader2 className="animate-spin" size={20} /> :
                <><Shield size={18} className="mr-2" /> Open Admin Portal <ArrowRight size={18} className="ml-2 group-hover:translate-x-1 transition-transform" /></>}
            </Button>
          </form>
        </div>
      </motion.div>
    </div>
  );
};

export default AdminLogin;