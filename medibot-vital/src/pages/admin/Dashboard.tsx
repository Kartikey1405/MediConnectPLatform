// // // // import { useState } from "react";
// // // // import { motion } from "framer-motion";
// // // // import { Building2, Users, Stethoscope, DollarSign, Search, Plus, Edit, Trash2, TrendingUp } from "lucide-react";
// // // // import DashboardLayout from "@/components/DashboardLayout";
// // // // import GlassCard from "@/components/GlassCard";

// // // // const stats = [
// // // //   { label: "Hospitals", value: "24", icon: Building2, color: "text-accent" },
// // // //   { label: "Doctors", value: "186", icon: Stethoscope, color: "text-success" },
// // // //   { label: "Patients", value: "12,840", icon: Users, color: "text-warning" },
// // // //   { label: "Revenue", value: "$48.5K", icon: DollarSign, color: "text-primary" },
// // // // ];

// // // // const doctors = [
// // // //   { id: 1, name: "Dr. Sarah Chen", specialization: "Cardiologist", hospital: "City General", status: "active" },
// // // //   { id: 2, name: "Dr. James Wilson", specialization: "General Physician", hospital: "St. Mary's", status: "active" },
// // // //   { id: 3, name: "Dr. Priya Sharma", specialization: "Dermatologist", hospital: "Unity Healthcare", status: "active" },
// // // //   { id: 4, name: "Dr. Michael Park", specialization: "Neurologist", hospital: "Metro Emergency", status: "inactive" },
// // // //   { id: 5, name: "Dr. Emily Ross", specialization: "Pediatrician", hospital: "Green Valley", status: "active" },
// // // // ];

// // // // const hospitals = [
// // // //   { id: 1, name: "City General Hospital", departments: 12, doctors: 45, status: "active" },
// // // //   { id: 2, name: "St. Mary's Medical Center", departments: 8, doctors: 32, status: "active" },
// // // //   { id: 3, name: "Unity Healthcare Complex", departments: 10, doctors: 38, status: "active" },
// // // //   { id: 4, name: "Green Valley Clinic", departments: 5, doctors: 15, status: "active" },
// // // //   { id: 5, name: "Metro Emergency Hospital", departments: 14, doctors: 52, status: "active" },
// // // // ];

// // // // type Tab = "doctors" | "hospitals";

// // // // const AdminDashboard = () => {
// // // //   const [tab, setTab] = useState<Tab>("doctors");
// // // //   const [search, setSearch] = useState("");

// // // //   return (
// // // //     <DashboardLayout role="admin">
// // // //       <div className="max-w-6xl mx-auto space-y-8">
// // // //         <div>
// // // //           <h1 className="font-display text-3xl font-bold text-foreground">Admin Dashboard</h1>
// // // //           <p className="text-muted-foreground mt-1">Platform management & analytics</p>
// // // //         </div>

// // // //         {/* Stats */}
// // // //         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
// // // //           {stats.map((stat, i) => (
// // // //             <GlassCard key={stat.label} delay={i * 0.1} className="p-5">
// // // //               <div className="flex items-center justify-between mb-3">
// // // //                 <stat.icon size={20} className={stat.color} />
// // // //                 <TrendingUp size={12} className="text-success" />
// // // //               </div>
// // // //               <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
// // // //               <div className="text-xs text-muted-foreground">{stat.label}</div>
// // // //             </GlassCard>
// // // //           ))}
// // // //         </div>

// // // //         {/* Tab Controls */}
// // // //         <div className="flex items-center justify-between flex-wrap gap-4">
// // // //           <div className="flex glass rounded-2xl p-1">
// // // //             {(["doctors", "hospitals"] as const).map((t) => (
// // // //               <button key={t} onClick={() => setTab(t)}
// // // //                 className={`px-6 py-2 rounded-xl text-sm font-semibold transition-all ${
// // // //                   tab === t ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent" : "text-muted-foreground hover:text-foreground"
// // // //                 }`}>
// // // //                 {t === "doctors" ? "Doctors" : "Hospitals"}
// // // //               </button>
// // // //             ))}
// // // //           </div>
// // // //           <div className="flex items-center gap-3">
// // // //             <div className="relative">
// // // //               <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
// // // //               <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search..."
// // // //                 className="pl-9 pr-4 py-2 rounded-xl glass text-sm text-foreground placeholder:text-muted-foreground/50 outline-none focus:ring-2 focus:ring-accent/50 w-48" />
// // // //             </div>
// // // //             <button className="glass rounded-xl px-4 py-2 text-sm font-medium text-accent hover:shadow-glow-accent transition-all flex items-center gap-1">
// // // //               <Plus size={14} /> Add
// // // //             </button>
// // // //           </div>
// // // //         </div>

// // // //         {/* Table */}
// // // //         <GlassCard className="overflow-hidden" tilt={false}>
// // // //           <div className="overflow-x-auto">
// // // //             {tab === "doctors" ? (
// // // //               <table className="w-full">
// // // //                 <thead>
// // // //                   <tr className="border-b border-border/30">
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Name</th>
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden sm:table-cell">Specialization</th>
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden md:table-cell">Hospital</th>
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
// // // //                     <th className="text-right p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
// // // //                   </tr>
// // // //                 </thead>
// // // //                 <tbody>
// // // //                   {doctors.filter(d => d.name.toLowerCase().includes(search.toLowerCase())).map((doc, i) => (
// // // //                     <motion.tr key={doc.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
// // // //                       className="border-b border-border/20 hover:bg-accent/5 transition-colors">
// // // //                       <td className="p-4 text-sm font-medium text-foreground">{doc.name}</td>
// // // //                       <td className="p-4 text-sm text-muted-foreground hidden sm:table-cell">{doc.specialization}</td>
// // // //                       <td className="p-4 text-sm text-muted-foreground hidden md:table-cell">{doc.hospital}</td>
// // // //                       <td className="p-4"><span className={`text-xs px-2 py-1 rounded-full ${doc.status === "active" ? "bg-success/10 text-success" : "bg-destructive/10 text-destructive"}`}>{doc.status}</span></td>
// // // //                       <td className="p-4 text-right space-x-2">
// // // //                         <button className="text-muted-foreground hover:text-accent transition-colors"><Edit size={14} /></button>
// // // //                         <button className="text-muted-foreground hover:text-destructive transition-colors"><Trash2 size={14} /></button>
// // // //                       </td>
// // // //                     </motion.tr>
// // // //                   ))}
// // // //                 </tbody>
// // // //               </table>
// // // //             ) : (
// // // //               <table className="w-full">
// // // //                 <thead>
// // // //                   <tr className="border-b border-border/30">
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Hospital</th>
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden sm:table-cell">Departments</th>
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden md:table-cell">Doctors</th>
// // // //                     <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
// // // //                     <th className="text-right p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
// // // //                   </tr>
// // // //                 </thead>
// // // //                 <tbody>
// // // //                   {hospitals.filter(h => h.name.toLowerCase().includes(search.toLowerCase())).map((h, i) => (
// // // //                     <motion.tr key={h.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
// // // //                       className="border-b border-border/20 hover:bg-accent/5 transition-colors">
// // // //                       <td className="p-4 text-sm font-medium text-foreground">{h.name}</td>
// // // //                       <td className="p-4 text-sm text-muted-foreground hidden sm:table-cell">{h.departments}</td>
// // // //                       <td className="p-4 text-sm text-muted-foreground hidden md:table-cell">{h.doctors}</td>
// // // //                       <td className="p-4"><span className="text-xs px-2 py-1 rounded-full bg-success/10 text-success">{h.status}</span></td>
// // // //                       <td className="p-4 text-right space-x-2">
// // // //                         <button className="text-muted-foreground hover:text-accent transition-colors"><Edit size={14} /></button>
// // // //                         <button className="text-muted-foreground hover:text-destructive transition-colors"><Trash2 size={14} /></button>
// // // //                       </td>
// // // //                     </motion.tr>
// // // //                   ))}
// // // //                 </tbody>
// // // //               </table>
// // // //             )}
// // // //           </div>
// // // //         </GlassCard>
// // // //       </div>
// // // //     </DashboardLayout>
// // // //   );
// // // // };

// // // // export default AdminDashboard;








// // // import { useState, useEffect } from "react";
// // // import { motion } from "framer-motion";
// // // import { 
// // //   Building2, Users, Stethoscope, DollarSign, Search, 
// // //   Plus, Edit, Trash2, TrendingUp, CheckCircle, 
// // //   Clock, ShieldCheck, Loader2 
// // // } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import GlassCard from "@/components/GlassCard";
// // // import api from "@/lib/api"; 
// // // import { toast } from "sonner";

// // // type Tab = "doctors" | "hospitals";

// // // const AdminDashboard = () => {
// // //   const [tab, setTab] = useState<Tab>("doctors");
// // //   const [search, setSearch] = useState("");
// // //   const [doctors, setDoctors] = useState<any[]>([]);
// // //   const [hospitals, setHospitals] = useState<any[]>([]);
// // //   const [loading, setLoading] = useState(true);

// // //   // 1. Fetch Real Data from Backend
// // //   const loadPlatformData = async () => {
// // //     try {
// // //       setLoading(true);
// // //       // Calls your Admin controllers directly
// // //       const [docsRes, hospsRes] = await Promise.all([
// // //         api.get("/admin/doctors"),
// // //         api.get("/admin/hospitals")
// // //       ]);
// // //       setDoctors(docsRes.data);
// // //       setHospitals(hospsRes.data);
// // //     } catch (err) {
// // //       console.error("Admin Load Error:", err);
// // //       toast.error("Critical: Failed to sync platform data with backend.");
// // //     } finally {
// // //       setLoading(false);
// // //     }
// // //   };

// // //   useEffect(() => {
// // //     loadPlatformData();
// // //   }, []);

// // //   // 2. Real-time Doctor Verification
// // //   const handleVerifyDoctor = async (doctorId: string) => {
// // //     try {
// // //       await api.patch(`/admin/doctors/${doctorId}/verify`);
// // //       toast.success("Medical professional verified successfully!");
// // //       loadPlatformData(); // Refresh both lists to ensure data integrity
// // //     } catch (err) {
// // //       toast.error("Verification failed. Please check backend logs.");
// // //     }
// // //   };

// // //   // 3. Derived Statistics from Real Data
// // //   const stats = [
// // //     { label: "Partner Hospitals", value: hospitals.length.toString(), icon: Building2, color: "text-accent" },
// // //     { label: "Medical Professionals", value: doctors.length.toString(), icon: Stethoscope, color: "text-success" },
// // //     { label: "Verified Staff", value: doctors.filter(d => d.verified).length.toString(), icon: ShieldCheck, color: "text-primary" },
// // //     { label: "Revenue", value: "$48.5K", icon: DollarSign, color: "text-warning" }, // Keep static until Payment integration
// // //   ];

// // //   if (loading) return (
// // //     <div className="min-h-screen flex items-center justify-center bg-background">
// // //       <Loader2 className="animate-spin text-accent h-12 w-12" />
// // //     </div>
// // //   );

// // //   return (
// // //     <DashboardLayout role="admin">
// // //       <div className="max-w-6xl mx-auto space-y-8">
// // //         <div className="flex justify-between items-end">
// // //           <div>
// // //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-2">
// // //               <ShieldCheck className="text-accent" /> Admin Panel
// // //             </h1>
// // //             <p className="text-muted-foreground mt-1">Platform management & staff verification</p>
// // //           </div>
// // //           <button className="glass rounded-xl px-6 py-3 text-sm font-bold text-accent hover:shadow-glow-accent transition-all flex items-center gap-2">
// // //             <Plus size={16} /> Register Facility
// // //           </button>
// // //         </div>

// // //         {/* Stats Grid */}
// // //         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
// // //           {stats.map((stat, i) => (
// // //             <GlassCard key={stat.label} delay={i * 0.1} className="p-5">
// // //               <div className="flex items-center justify-between mb-3">
// // //                 <stat.icon size={20} className={stat.color} />
// // //                 <TrendingUp size={12} className="text-success" />
// // //               </div>
// // //               <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
// // //               <div className="text-xs text-muted-foreground">{stat.label}</div>
// // //             </GlassCard>
// // //           ))}
// // //         </div>

// // //         {/* Tab Controls */}
// // //         <div className="flex items-center justify-between flex-wrap gap-4">
// // //           <div className="flex glass rounded-2xl p-1">
// // //             {(["doctors", "hospitals"] as const).map((t) => (
// // //               <button key={t} onClick={() => setTab(t)}
// // //                 className={`px-8 py-2.5 rounded-xl text-sm font-bold transition-all ${
// // //                   tab === t ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent" : "text-muted-foreground hover:text-foreground"
// // //                 }`}>
// // //                 {t.toUpperCase()}
// // //               </button>
// // //             ))}
// // //           </div>
// // //           <div className="relative">
// // //             <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
// // //             <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter records..."
// // //               className="pl-9 pr-4 py-2.5 rounded-xl glass text-sm text-foreground outline-none focus:ring-2 focus:ring-accent/50 w-64" />
// // //           </div>
// // //         </div>

// // //         {/* Dynamic Management Tables */}
// // //         <GlassCard className="overflow-hidden" tilt={false}>
// // //           <div className="overflow-x-auto">
// // //             {tab === "doctors" ? (
// // //               <table className="w-full">
// // //                 <thead>
// // //                   <tr className="border-b border-white/5 bg-white/5">
// // //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Name & Specialty</th>
// // //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Hospital</th>
// // //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Status</th>
// // //                     <th className="text-right p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Actions</th>
// // //                   </tr>
// // //                 </thead>
// // //                 <tbody>
// // //                   {doctors.filter(d => d.user?.firstName.toLowerCase().includes(search.toLowerCase())).map((doc, i) => (
// // //                     <motion.tr key={doc.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
// // //                       className="border-b border-white/5 hover:bg-white/5 transition-colors">
// // //                       <td className="p-5">
// // //                         <div className="text-sm font-bold text-foreground">Dr. {doc.user?.firstName} {doc.user?.lastName}</div>
// // //                         <div className="text-[10px] text-muted-foreground">{doc.specialization}</div>
// // //                       </td>
// // //                       <td className="p-5 text-xs text-muted-foreground font-medium">{doc.hospital?.name || "Independent"}</td>
// // //                       <td className="p-5">
// // //                         <span className={`text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-tighter ${
// // //                           doc.verified ? "bg-success/20 text-success" : "bg-warning/20 text-warning"
// // //                         }`}>
// // //                           {doc.verified ? "Verified" : "Pending Approval"}
// // //                         </span>
// // //                       </td>
// // //                       <td className="p-5 text-right space-x-3">
// // //                         {!doc.verified && (
// // //                           <button onClick={() => handleVerifyDoctor(doc.id)} className="text-accent hover:underline text-xs font-bold">Verify Professional</button>
// // //                         )}
// // //                         <button className="text-muted-foreground hover:text-destructive transition-colors"><Trash2 size={14} /></button>
// // //                       </td>
// // //                     </motion.tr>
// // //                   ))}
// // //                 </tbody>
// // //               </table>
// // //             ) : (
// // //               <table className="w-full">
// // //                 <thead>
// // //                   <tr className="border-b border-white/5 bg-white/5">
// // //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Facility Name</th>
// // //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Active Units</th>
// // //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Contact</th>
// // //                     <th className="text-right p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Actions</th>
// // //                   </tr>
// // //                 </thead>
// // //                 <tbody>
// // //                   {hospitals.filter(h => h.name.toLowerCase().includes(search.toLowerCase())).map((h, i) => (
// // //                     <motion.tr key={h.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
// // //                       className="border-b border-white/5 hover:bg-white/5 transition-colors">
// // //                       <td className="p-5 text-sm font-bold text-foreground">{h.name}</td>
// // //                       <td className="p-5 text-xs text-muted-foreground font-medium">{h.departments?.length || 0} Departments</td>
// // //                       <td className="p-5 text-xs text-muted-foreground">{h.contactNumber}</td>
// // //                       <td className="p-5 text-right space-x-3">
// // //                         <button className="text-muted-foreground hover:text-accent transition-colors"><Edit size={14} /></button>
// // //                         <button className="text-muted-foreground hover:text-destructive transition-colors"><Trash2 size={14} /></button>
// // //                       </td>
// // //                     </motion.tr>
// // //                   ))}
// // //                 </tbody>
// // //               </table>
// // //             )}
// // //           </div>
// // //         </GlassCard>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default AdminDashboard;



















// // import { useState, useEffect } from "react";
// // import { motion } from "framer-motion";
// // import { 
// //   Building2, Users, Stethoscope, DollarSign, Search, 
// //   Plus, Edit, Trash2, TrendingUp, ShieldCheck, Loader2 
// // } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import GlassCard from "@/components/GlassCard";
// // import api from "@/lib/api"; 
// // import { toast } from "sonner";

// // type Tab = "doctors" | "hospitals";

// // const AdminDashboard = () => {
// //   const [tab, setTab] = useState<Tab>("doctors");
// //   const [search, setSearch] = useState("");
// //   const [doctors, setDoctors] = useState<any[]>([]);
// //   const [hospitals, setHospitals] = useState<any[]>([]);
// //   const [loading, setLoading] = useState(true);

// //   // 1. Fetch Real Data from Backend
// //   const loadPlatformData = async () => {
// //     try {
// //       setLoading(true);
// //       const [docsRes, hospsRes] = await Promise.all([
// //         api.get("/admin/doctors"),
// //         api.get("/admin/hospitals")
// //       ]);
// //       setDoctors(docsRes.data);
// //       setHospitals(hospsRes.data);
// //     } catch (err) {
// //       console.error("Admin Load Error:", err);
// //       toast.error("Failed to sync platform data.");
// //     } finally {
// //       setLoading(false);
// //     }
// //   };

// //   useEffect(() => {
// //     loadPlatformData();
// //   }, []);

// //   // 2. Verification Action
// //   const handleVerifyDoctor = async (doctorId: string) => {
// //     try {
// //       await api.patch(`/admin/doctors/${doctorId}/verify`);
// //       toast.success("Professional verified!");
// //       loadPlatformData(); // Reload to update table status
// //     } catch (err) {
// //       toast.error("Verification failed.");
// //     }
// //   };

// //   // 3. Stats Calculation
// //   const stats = [
// //     { label: "Partner Hospitals", value: hospitals.length.toString(), icon: Building2, color: "text-accent" },
// //     { label: "Staff Members", value: doctors.length.toString(), icon: Stethoscope, color: "text-success" },
// //     { label: "Verified Staff", value: doctors.filter(d => d.verified || d.isVerified).length.toString(), icon: ShieldCheck, color: "text-primary" },
// //     { label: "Platform Revenue", value: "$48.5K", icon: DollarSign, color: "text-warning" },
// //   ];

// //   if (loading) return (
// //     <div className="min-h-screen flex items-center justify-center bg-background">
// //       <Loader2 className="animate-spin text-accent h-12 w-12" />
// //     </div>
// //   );

// //   return (
// //     <DashboardLayout role="admin">
// //       <div className="max-w-6xl mx-auto space-y-8">
// //         <div className="flex justify-between items-end">
// //           <div>
// //             <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-2">
// //               <ShieldCheck className="text-accent" /> Admin Dashboard
// //             </h1>
// //             <p className="text-muted-foreground mt-1">Platform management and verification portal</p>
// //           </div>
// //           {/* Action to be linked to a Modal/Form */}
// //           <button className="glass rounded-xl px-6 py-3 text-sm font-bold text-accent hover:shadow-glow-accent transition-all flex items-center gap-2">
// //             <Plus size={16} /> New Record
// //           </button>
// //         </div>

// //         {/* Stats Grid */}
// //         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
// //           {stats.map((stat, i) => (
// //             <GlassCard key={stat.label} delay={i * 0.1} className="p-5">
// //               <div className="flex items-center justify-between mb-3">
// //                 <stat.icon size={20} className={stat.color} />
// //                 <TrendingUp size={12} className="text-success" />
// //               </div>
// //               <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
// //               <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{stat.label}</div>
// //             </GlassCard>
// //           ))}
// //         </div>

// //         {/* Filters */}
// //         <div className="flex items-center justify-between flex-wrap gap-4">
// //           <div className="flex glass rounded-2xl p-1">
// //             {(["doctors", "hospitals"] as const).map((t) => (
// //               <button key={t} onClick={() => setTab(t)}
// //                 className={`px-8 py-2 rounded-xl text-sm font-bold transition-all ${
// //                   tab === t ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent" : "text-muted-foreground hover:text-foreground"
// //                 }`}>
// //                 {t.charAt(0).toUpperCase() + t.slice(1)}
// //               </button>
// //             ))}
// //           </div>
// //           <div className="relative">
// //             <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
// //             <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder={`Filter ${tab}...`}
// //               className="pl-9 pr-4 py-2 rounded-xl glass text-sm text-foreground outline-none focus:ring-2 focus:ring-accent/50 w-64" />
// //           </div>
// //         </div>

// //         {/* Management Table */}
// //         <GlassCard className="overflow-hidden p-0" tilt={false}>
// //           <div className="overflow-x-auto">
// //             {tab === "doctors" ? (
// //               <table className="w-full">
// //                 <thead>
// //                   <tr className="border-b border-white/5 bg-white/5">
// //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Medical Staff</th>
// //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Specialization</th>
// //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Facility</th>
// //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Status</th>
// //                     <th className="text-right p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Actions</th>
// //                   </tr>
// //                 </thead>
// //                 <tbody>
// //                   {doctors.filter(d => (d.fullName || d.user?.firstName)?.toLowerCase().includes(search.toLowerCase())).map((doc, i) => (
// //                     <motion.tr key={doc.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
// //                       className="border-b border-white/5 hover:bg-white/5 transition-colors">
// //                       <td className="p-5 text-sm font-bold text-foreground">
// //                         Dr. {doc.fullName || `${doc.user?.firstName} ${doc.user?.lastName}`}
// //                       </td>
// //                       <td className="p-5 text-xs text-muted-foreground">{doc.specialization}</td>
// //                       <td className="p-5 text-xs text-muted-foreground">{doc.hospitalName || doc.hospital?.name || "Private Practice"}</td>
// //                       <td className="p-5">
// //                         <span className={`text-[10px] font-bold px-3 py-1 rounded-full uppercase ${
// //                           (doc.verified || doc.isVerified) ? "bg-success/10 text-success" : "bg-warning/10 text-warning"
// //                         }`}>
// //                           {(doc.verified || doc.isVerified) ? "Authorized" : "Pending"}
// //                         </span>
// //                       </td>
// //                       <td className="p-5 text-right space-x-3">
// //                         {!(doc.verified || doc.isVerified) && (
// //                           <button onClick={() => handleVerifyDoctor(doc.id)} className="text-accent hover:underline text-xs font-bold">Verify</button>
// //                         )}
// //                         <button className="text-muted-foreground hover:text-destructive transition-colors"><Trash2 size={14} /></button>
// //                       </td>
// //                     </motion.tr>
// //                   ))}
// //                 </tbody>
// //               </table>
// //             ) : (
// //               <table className="w-full">
// //                 <thead>
// //                   <tr className="border-b border-white/5 bg-white/5">
// //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Hospital</th>
// //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Address</th>
// //                     <th className="text-left p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Units</th>
// //                     <th className="text-right p-5 text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Actions</th>
// //                   </tr>
// //                 </thead>
// //                 <tbody>
// //                   {hospitals.filter(h => h.name.toLowerCase().includes(search.toLowerCase())).map((h, i) => (
// //                     <motion.tr key={h.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
// //                       className="border-b border-white/5 hover:bg-white/5 transition-colors">
// //                       <td className="p-5 text-sm font-bold text-foreground">{h.name}</td>
// //                       <td className="p-5 text-[10px] text-muted-foreground max-w-[200px] truncate">{h.address}</td>
// //                       <td className="p-5 text-xs text-muted-foreground">{h.departments?.length || 0} Specialties</td>
// //                       <td className="p-5 text-right space-x-3">
// //                         <button className="text-muted-foreground hover:text-accent transition-colors"><Edit size={14} /></button>
// //                         <button className="text-muted-foreground hover:text-destructive transition-colors"><Trash2 size={14} /></button>
// //                       </td>
// //                     </motion.tr>
// //                   ))}
// //                 </tbody>
// //               </table>
// //             )}
// //           </div>
// //         </GlassCard>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default AdminDashboard;

















// import { useState, useEffect } from "react";
// import { motion, AnimatePresence } from "framer-motion";
// import { 
//   Building2, Users, Stethoscope, DollarSign, Search, 
//   Plus, Edit, Trash2, TrendingUp, ShieldCheck, Loader2, X 
// } from "lucide-react";
// import DashboardLayout from "@/components/DashboardLayout";
// import GlassCard from "@/components/GlassCard";
// import api from "@/lib/api"; 
// import { toast } from "sonner";
// import { Button } from "@/components/ui/button";

// type Tab = "doctors" | "hospitals";

// const AdminDashboard = () => {
//   const [tab, setTab] = useState<Tab>("doctors");
//   const [search, setSearch] = useState("");
//   const [doctors, setDoctors] = useState<any[]>([]);
//   const [hospitals, setHospitals] = useState<any[]>([]);
//   const [loading, setLoading] = useState(true);

//   // Modal States
//   const [isHospitalModalOpen, setIsHospitalModalOpen] = useState(false);
//   const [isDoctorModalOpen, setIsDoctorModalOpen] = useState(false);

//   // Form States (Matching your DTOs)
//   const [hospitalForm, setHospitalForm] = useState({ name: "", address: "", latitude: 0, longitude: 0, contactNumber: "" });
//   const [doctorForm, setDoctorForm] = useState({ userId: "", hospitalId: "", departmentId: "", specialization: "", consultationFee: 0, bio: "" });

//   const loadPlatformData = async () => {
//     try {
//       setLoading(true);
//       const [docsRes, hospsRes] = await Promise.all([
//         api.get("/admin/doctors"),
//         api.get("/admin/hospitals")
//       ]);
//       setDoctors(docsRes.data);
//       setHospitals(hospsRes.data);
//     } catch (err) {
//       toast.error("Failed to sync platform data.");
//     } finally {
//       setLoading(false);
//     }
//   };

//   useEffect(() => { loadPlatformData(); }, []);

//   // --- SUBMIT HANDLERS ---

//   const handleAddHospital = async (e: React.FormEvent) => {
//     e.preventDefault();
//     try {
//       await api.post("/admin/hospitals", hospitalForm);
//       toast.success("Hospital facility registered!");
//       setIsHospitalModalOpen(false);
//       loadPlatformData();
//     } catch (err) { toast.error("Check coordinates and contact format."); }
//   };

//   const handleAddDoctor = async (e: React.FormEvent) => {
//     e.preventDefault();
//     try {
//       await api.post("/admin/doctors/register", doctorForm);
//       toast.success("Doctor onboarded successfully!");
//       setIsDoctorModalOpen(false);
//       loadPlatformData();
//     } catch (err) { toast.error("Verify UUIDs for User/Hospital/Dept."); }
//   };

//   const handleVerifyDoctor = async (id: string) => {
//     await api.patch(`/admin/doctors/${id}/verify`);
//     toast.success("Doctor verified!");
//     loadPlatformData();
//   };

//   const stats = [
//     { label: "Facilities", value: hospitals.length.toString(), icon: Building2, color: "text-accent" },
//     { label: "Specialists", value: doctors.length.toString(), icon: Stethoscope, color: "text-success" },
//     { label: "Verified", value: doctors.filter(d => d.verified || d.isVerified).length.toString(), icon: ShieldCheck, color: "text-primary" },
//     { label: "Patients", value: "1,240", icon: Users, color: "text-warning" },
//   ];

//   if (loading) return <div className="min-h-screen flex items-center justify-center"><Loader2 className="animate-spin text-accent" /></div>;

//   return (
//     <DashboardLayout role="admin">
//       <div className="max-w-6xl mx-auto space-y-8">
//         <div className="flex justify-between items-end">
//           <div>
//             <h1 className="font-display text-3xl font-bold text-foreground">Admin Dashboard</h1>
//             <p className="text-muted-foreground mt-1">Platform verification & management</p>
//           </div>
//           <button 
//             onClick={() => tab === "hospitals" ? setIsHospitalModalOpen(true) : setIsDoctorModalOpen(true)}
//             className="glass rounded-xl px-6 py-3 text-sm font-bold text-accent hover:shadow-glow-accent transition-all flex items-center gap-2"
//           >
//             <Plus size={16} /> Add {tab === "hospitals" ? "Hospital" : "Doctor"}
//           </button>
//         </div>

//         {/* Stats Grid */}
//         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
//           {stats.map((stat, i) => (
//             <GlassCard key={stat.label} delay={i * 0.1} className="p-5">
//               <div className="flex items-center justify-between mb-3"><stat.icon size={20} className={stat.color} /><TrendingUp size={12} className="text-success" /></div>
//               <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
//               <div className="text-xs text-muted-foreground">{stat.label}</div>
//             </GlassCard>
//           ))}
//         </div>

//         {/* Controls */}
//         <div className="flex items-center justify-between flex-wrap gap-4">
//           <div className="flex glass rounded-2xl p-1">
//             {(["doctors", "hospitals"] as const).map((t) => (
//               <button key={t} onClick={() => setTab(t)} className={`px-6 py-2 rounded-xl text-sm font-semibold transition-all ${tab === t ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent" : "text-muted-foreground hover:text-foreground"}`}>
//                 {t.toUpperCase()}
//               </button>
//             ))}
//           </div>
//           <div className="relative">
//             <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
//             <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter records..." className="pl-9 pr-4 py-2 rounded-xl glass text-sm outline-none focus:ring-2 focus:ring-accent/50 w-48" />
//           </div>
//         </div>

//         {/* Table Render Logic */}
//         <GlassCard className="overflow-hidden" tilt={false}>
//           <div className="overflow-x-auto">
//             <table className="w-full">
//               <thead>
//                 <tr className="border-b border-border/30">
//                   <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase">{tab === "doctors" ? "Doctor Name" : "Hospital"}</th>
//                   <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase">{tab === "doctors" ? "Specialty" : "Departments"}</th>
//                   <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase">Status</th>
//                   <th className="text-right p-4 text-xs font-semibold text-muted-foreground uppercase">Actions</th>
//                 </tr>
//               </thead>
//               <tbody>
//                 {(tab === "doctors" ? doctors : hospitals).filter(item => (item.fullName || item.name || "").toLowerCase().includes(search.toLowerCase())).map((item, i) => (
//                   <motion.tr key={item.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-b border-border/20 hover:bg-accent/5 transition-colors">
//                     <td className="p-4 text-sm font-medium text-foreground">{item.fullName || item.name || `${item.user?.firstName} ${item.user?.lastName}`}</td>
//                     <td className="p-4 text-sm text-muted-foreground">{item.specialization || `${item.departments?.length || 0} Units`}</td>
//                     <td className="p-4">
//                       <span className={`text-xs px-2 py-1 rounded-full ${(item.verified || item.isVerified || tab === "hospitals") ? "bg-success/10 text-success" : "bg-warning/10 text-warning"}`}>
//                         {(item.verified || item.isVerified || tab === "hospitals") ? "active" : "pending"}
//                       </span>
//                     </td>
//                     <td className="p-4 text-right space-x-2">
//                       {tab === "doctors" && !(item.verified || item.isVerified) && (
//                         <button onClick={() => handleVerifyDoctor(item.id)} className="text-accent hover:underline text-xs font-bold">Verify</button>
//                       )}
//                       <button className="text-muted-foreground hover:text-destructive"><Trash2 size={14} /></button>
//                     </td>
//                   </motion.tr>
//                 ))}
//               </tbody>
//             </table>
//           </div>
//         </GlassCard>

//         {/* --- ADD HOSPITAL MODAL --- */}
//         <AnimatePresence>
//           {isHospitalModalOpen && (
//             <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
//               <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }} className="w-full max-w-lg">
//                 <GlassCard className="p-8">
//                   <div className="flex justify-between items-center mb-6">
//                     <h2 className="text-xl font-bold flex items-center gap-2"><Building2 className="text-accent" /> Register Hospital</h2>
//                     <button onClick={() => setIsHospitalModalOpen(false)}><X size={20} /></button>
//                   </div>
//                   <form onSubmit={handleAddHospital} className="space-y-4">
//                     <input type="text" placeholder="Hospital Name" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, name: e.target.value})} />
//                     <textarea placeholder="Full Address" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, address: e.target.value})} />
//                     <div className="grid grid-cols-2 gap-4">
//                       <input type="number" step="any" placeholder="Latitude" required className="p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, latitude: parseFloat(e.target.value)})} />
//                       <input type="number" step="any" placeholder="Longitude" required className="p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, longitude: parseFloat(e.target.value)})} />
//                     </div>
//                     <input type="text" placeholder="Contact Number (e.g. +91...)" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, contactNumber: e.target.value})} />
//                     <Button type="submit" className="w-full bg-accent text-accent-foreground py-6">Register Facility</Button>
//                   </form>
//                 </GlassCard>
//               </motion.div>
//             </div>
//           )}
//         </AnimatePresence>

//         {/* --- ADD DOCTOR MODAL --- */}
//         <AnimatePresence>
//           {isDoctorModalOpen && (
//             <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
//               <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }} className="w-full max-w-lg">
//                 <GlassCard className="p-8">
//                   <div className="flex justify-between items-center mb-6">
//                     <h2 className="text-xl font-bold flex items-center gap-2"><Stethoscope className="text-accent" /> Onboard Doctor</h2>
//                     <button onClick={() => setIsDoctorModalOpen(false)}><X size={20} /></button>
//                   </div>
//                   <form onSubmit={handleAddDoctor} className="space-y-4">
//                     <input type="text" placeholder="User UUID" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, userId: e.target.value})} />
//                     <div className="grid grid-cols-2 gap-4">
//                       <input type="text" placeholder="Hospital UUID" required className="p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, hospitalId: e.target.value})} />
//                       <input type="text" placeholder="Dept UUID" required className="p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, departmentId: e.target.value})} />
//                     </div>
//                     <input type="text" placeholder="Specialization" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, specialization: e.target.value})} />
//                     <input type="number" placeholder="Consultation Fee" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, consultationFee: parseFloat(e.target.value)})} />
//                     <textarea placeholder="Professional Bio" className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, bio: e.target.value})} />
//                     <Button type="submit" className="w-full bg-accent text-accent-foreground py-6">Authorize Staff</Button>
//                   </form>
//                 </GlassCard>
//               </motion.div>
//             </div>
//           )}
//         </AnimatePresence>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default AdminDashboard;











import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Building2, Users, Stethoscope, DollarSign, Search, 
  Plus, Edit, Trash2, TrendingUp, ShieldCheck, Loader2, X 
} from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import api from "@/lib/api"; 
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

type Tab = "doctors" | "hospitals";

const AdminDashboard = () => {
  const [tab, setTab] = useState<Tab>("doctors");
  const [search, setSearch] = useState("");
  // INITIALIZATION: Always start with empty arrays to prevent .filter() crashes
  const [doctors, setDoctors] = useState<any[]>([]);
  const [hospitals, setHospitals] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Modal States
  const [isHospitalModalOpen, setIsHospitalModalOpen] = useState(false);
  const [isDoctorModalOpen, setIsDoctorModalOpen] = useState(false);

  // Form States (Matching your Request DTOs)
  const [hospitalForm, setHospitalForm] = useState({ name: "", address: "", latitude: 0, longitude: 0, contactNumber: "" });
  const [doctorForm, setDoctorForm] = useState({ userId: "", hospitalId: "", departmentId: "", specialization: "", consultationFee: 0, bio: "" });

  const loadPlatformData = async () => {
    try {
      setLoading(true);
      const [docsRes, hospsRes] = await Promise.all([
        api.get("/admin/doctors"),
        api.get("/admin/hospitals")
      ]);

      // DEFENSIVE SYNC: Ensures we only set state if data is a valid array
      setDoctors(Array.isArray(docsRes.data) ? docsRes.data : []);
      setHospitals(Array.isArray(hospsRes.data) ? hospsRes.data : []);
    } catch (err) {
      console.error("Dashboard Load Error:", err);
      toast.error("Failed to sync platform data. Backend recursion or connection error.");
      setDoctors([]); // Fallback to empty to clear crash state
      setHospitals([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadPlatformData(); }, []);

  // --- HANDLERS ---

  const handleAddHospital = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/admin/hospitals", hospitalForm);
      toast.success("Facility registered successfully!");
      setIsHospitalModalOpen(false);
      loadPlatformData();
    } catch (err) { toast.error("Check coordinates and contact format."); }
  };

  const handleAddDoctor = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/admin/doctors/register", doctorForm);
      toast.success("Doctor onboarded!");
      setIsDoctorModalOpen(false);
      loadPlatformData();
    } catch (err) { toast.error("Verify UUIDs for User/Hospital/Dept."); }
  };

  const handleVerifyDoctor = async (id: string) => {
    try {
      await api.patch(`/admin/doctors/${id}/verify`);
      toast.success("Doctor credentials authorized!");
      loadPlatformData();
    } catch (err) { toast.error("Verification failed."); }
  };

  const handleDeleteHospital = async (id: string) => {
    if (!window.confirm("Permanently remove this facility?")) return;
    try {
      await api.delete(`/admin/hospitals/${id}`);
      toast.success("Hospital record removed.");
      loadPlatformData();
    } catch (err) { toast.error("Delete failed. Ensure no doctors are linked."); }
  };

  // Safe Stats Calculation
  const stats = [
    { label: "Facilities", value: hospitals.length.toString(), icon: Building2, color: "text-accent" },
    { label: "Specialists", value: doctors.length.toString(), icon: Stethoscope, color: "text-success" },
    { label: "Verified", value: doctors.filter(d => d.verified || d.isVerified).length.toString(), icon: ShieldCheck, color: "text-primary" },
    { label: "Platform Patients", value: "1,240", icon: Users, color: "text-warning" },
  ];

  if (loading) return <div className="min-h-screen flex items-center justify-center"><Loader2 className="animate-spin text-accent h-12 w-12" /></div>;

  return (
    <DashboardLayout role="admin">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex justify-between items-end">
          <div>
            <h1 className="font-display text-3xl font-bold text-foreground">Admin Dashboard</h1>
            <p className="text-muted-foreground mt-1">Managed platform oversight and verification</p>
          </div>
          <button 
            onClick={() => tab === "hospitals" ? setIsHospitalModalOpen(true) : setIsDoctorModalOpen(true)}
            className="glass rounded-xl px-6 py-3 text-sm font-bold text-accent hover:shadow-glow-accent transition-all flex items-center gap-2"
          >
            <Plus size={16} /> Add {tab === "hospitals" ? "Hospital" : "Doctor"}
          </button>
        </div>

        {/* Dynamic Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {stats.map((stat, i) => (
            <GlassCard key={stat.label} delay={i * 0.1} className="p-5">
              <div className="flex items-center justify-between mb-3"><stat.icon size={20} className={stat.color} /><TrendingUp size={12} className="text-success" /></div>
              <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
              <div className="text-xs text-muted-foreground">{stat.label}</div>
            </GlassCard>
          ))}
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex glass rounded-2xl p-1">
            {(["doctors", "hospitals"] as const).map((t) => (
              <button key={t} onClick={() => setTab(t)} className={`px-8 py-2 rounded-xl text-sm font-bold transition-all ${tab === t ? "bg-gradient-to-r from-primary to-accent text-accent-foreground shadow-glow-accent" : "text-muted-foreground hover:text-foreground"}`}>
                {t.toUpperCase()}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder={`Filter ${tab}...`} className="pl-9 pr-4 py-2.5 rounded-xl glass text-sm outline-none focus:ring-2 focus:ring-accent/50 w-64" />
          </div>
        </div>

        {/* Integrated Data Table */}
        <GlassCard className="overflow-hidden p-0" tilt={false}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border/30 bg-white/5">
                  <th className="text-left p-4 text-xs font-bold text-muted-foreground uppercase">{tab === "doctors" ? "Medical Staff" : "Facility Name"}</th>
                  <th className="text-left p-4 text-xs font-bold text-muted-foreground uppercase">{tab === "doctors" ? "Specialty" : "Active Units"}</th>
                  <th className="text-left p-4 text-xs font-bold text-muted-foreground uppercase">Status</th>
                  <th className="text-right p-4 text-xs font-bold text-muted-foreground uppercase">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(tab === "doctors" ? doctors : hospitals)
                  .filter(item => (item.fullName || item.name || "").toLowerCase().includes(search.toLowerCase()))
                  .map((item, i) => (
                  <motion.tr key={item.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-b border-border/20 hover:bg-accent/5 transition-colors">
                    <td className="p-4">
                      <div className="text-sm font-bold">
                        {tab === "doctors" ? `Dr. ${item.fullName || `${item.user?.firstName || 'Unknown'} ${item.user?.lastName || ''}`}` : item.name}
                      </div>
                      {tab === "hospitals" && <div className="text-[10px] text-muted-foreground">{item.address}</div>}
                    </td>
                    <td className="p-4 text-sm text-muted-foreground">
                      {item.specialization || `${item.departments?.length || 0} Specialties`}
                    </td>
                    <td className="p-4">
                      <span className={`text-[10px] font-bold px-3 py-1 rounded-full uppercase ${(item.verified || item.isVerified || tab === "hospitals") ? "bg-success/10 text-success" : "bg-warning/10 text-warning"}`}>
                        {(item.verified || item.isVerified || tab === "hospitals") ? "Authorized" : "Pending"}
                      </span>
                    </td>
                    <td className="p-4 text-right space-x-3">
                      {tab === "doctors" && !(item.verified || item.isVerified) && (
                        <button onClick={() => handleVerifyDoctor(item.id)} className="text-accent hover:underline text-xs font-bold">Verify</button>
                      )}
                      <button className="text-muted-foreground hover:text-accent"><Edit size={14} /></button>
                      <button onClick={() => tab === "hospitals" && handleDeleteHospital(item.id)} className="text-muted-foreground hover:text-destructive"><Trash2 size={14} /></button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </GlassCard>

        {/* --- ADD HOSPITAL MODAL --- */}
        <AnimatePresence>
          {isHospitalModalOpen && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
              <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }} className="w-full max-w-lg">
                <GlassCard className="p-8">
                  <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-bold flex items-center gap-2"><Building2 className="text-accent" /> Register Hospital</h2>
                    <button onClick={() => setIsHospitalModalOpen(false)}><X size={20} /></button>
                  </div>
                  <form onSubmit={handleAddHospital} className="space-y-4">
                    <input type="text" placeholder="Hospital Name" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, name: e.target.value})} />
                    <textarea placeholder="Full Address" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, address: e.target.value})} />
                    <div className="grid grid-cols-2 gap-4">
                      <input type="number" step="any" placeholder="Latitude" required className="p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, latitude: parseFloat(e.target.value)})} />
                      <input type="number" step="any" placeholder="Longitude" required className="p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, longitude: parseFloat(e.target.value)})} />
                    </div>
                    <input type="text" placeholder="Contact (+91...)" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setHospitalForm({...hospitalForm, contactNumber: e.target.value})} />
                    <Button type="submit" className="w-full bg-accent text-accent-foreground py-6">Authorize Facility</Button>
                  </form>
                </GlassCard>
              </motion.div>
            </div>
          )}
        </AnimatePresence>

        {/* --- ADD DOCTOR MODAL --- */}
        <AnimatePresence>
          {isDoctorModalOpen && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
              <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }} className="w-full max-w-lg">
                <GlassCard className="p-8">
                  <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-bold flex items-center gap-2"><Stethoscope className="text-accent" /> Onboard Staff</h2>
                    <button onClick={() => setIsDoctorModalOpen(false)}><X size={20} /></button>
                  </div>
                  <form onSubmit={handleAddDoctor} className="space-y-4">
                    <input type="text" placeholder="User UUID" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, userId: e.target.value})} />
                    <div className="grid grid-cols-2 gap-4">
                      <input type="text" placeholder="Hospital UUID" required className="p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, hospitalId: e.target.value})} />
                      <input type="text" placeholder="Dept UUID" required className="p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, departmentId: e.target.value})} />
                    </div>
                    <input type="text" placeholder="Specialization" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, specialization: e.target.value})} />
                    <input type="number" placeholder="Fee ($)" required className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, consultationFee: parseFloat(e.target.value)})} />
                    <textarea placeholder="Bio" className="w-full p-3 glass rounded-xl text-sm" onChange={e => setDoctorForm({...doctorForm, bio: e.target.value})} />
                    <Button type="submit" className="w-full bg-accent text-accent-foreground py-6">Create Professional Record</Button>
                  </form>
                </GlassCard>
              </motion.div>
            </div>
          )}
        </AnimatePresence>
      </div>
    </DashboardLayout>
  );
};

export default AdminDashboard;