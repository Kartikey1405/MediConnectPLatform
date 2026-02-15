// // // import { motion } from "framer-motion";
// // // import { Activity, Calendar, FileText, MessageSquare, TrendingUp, Heart } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import GlassCard from "@/components/GlassCard";

// // // const stats = [
// // //   { label: "Health Score", value: "92%", icon: Heart, color: "text-success" },
// // //   { label: "Consultations", value: "12", icon: Calendar, color: "text-accent" },
// // //   { label: "Reports", value: "8", icon: FileText, color: "text-warning" },
// // //   { label: "Triage Chats", value: "24", icon: MessageSquare, color: "text-primary" },
// // // ];

// // // const recentActivity = [
// // //   { title: "Cardiology Consultation", date: "Feb 10, 2026", type: "consultation" },
// // //   { title: "Blood Test Report Uploaded", date: "Feb 8, 2026", type: "report" },
// // //   { title: "AI Triage: Headache", date: "Feb 6, 2026", type: "triage" },
// // //   { title: "General Checkup", date: "Feb 2, 2026", type: "consultation" },
// // // ];

// // // const PatientDashboard = () => {
// // //   return (
// // //     <DashboardLayout role="patient">
// // //       <div className="max-w-6xl mx-auto space-y-8">
// // //         <div>
// // //           <h1 className="font-display text-3xl font-bold text-foreground">Welcome back, Alex</h1>
// // //           <p className="text-muted-foreground mt-1">Here's your health overview</p>
// // //         </div>

// // //         {/* Stats Grid */}
// // //         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
// // //           {stats.map((stat, i) => (
// // //             <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
// // //               <div className="flex items-center justify-between mb-3">
// // //                 <stat.icon size={22} className={stat.color} />
// // //                 <TrendingUp size={14} className="text-success" />
// // //               </div>
// // //               <motion.div
// // //                 initial={{ opacity: 0 }}
// // //                 animate={{ opacity: 1 }}
// // //                 transition={{ delay: 0.5 + i * 0.1 }}
// // //               >
// // //                 <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
// // //                 <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
// // //               </motion.div>
// // //             </GlassCard>
// // //           ))}
// // //         </div>

// // //         {/* Quick Actions + Recent */}
// // //         <div className="grid lg:grid-cols-2 gap-6">
// // //           <GlassCard className="p-6" delay={0.3}>
// // //             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// // //               <Activity size={18} className="text-accent" />
// // //               Quick Actions
// // //             </h3>
// // //             <div className="grid grid-cols-2 gap-3">
// // //               {[
// // //                 { label: "Start Triage", href: "/patient/triage" },
// // //                 { label: "Book Appointment", href: "/patient/book" },
// // //                 { label: "View Records", href: "/patient/records" },
// // //                 { label: "Find Hospitals", href: "/patient/hospitals" },
// // //               ].map((action) => (
// // //                 <a
// // //                   key={action.label}
// // //                   href={action.href}
// // //                   className="glass rounded-xl px-4 py-3 text-sm font-medium text-foreground hover:shadow-glow-accent hover:scale-[1.02] transition-all duration-300 text-center"
// // //                 >
// // //                   {action.label}
// // //                 </a>
// // //               ))}
// // //             </div>
// // //           </GlassCard>

// // //           <GlassCard className="p-6" delay={0.4}>
// // //             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// // //               <Clock size={18} className="text-accent" />
// // //               Recent Activity
// // //             </h3>
// // //             <div className="space-y-3">
// // //               {recentActivity.map((item, i) => (
// // //                 <motion.div
// // //                   key={i}
// // //                   initial={{ opacity: 0, x: -10 }}
// // //                   animate={{ opacity: 1, x: 0 }}
// // //                   transition={{ delay: 0.6 + i * 0.1 }}
// // //                   className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
// // //                 >
// // //                   <div>
// // //                     <p className="text-sm font-medium text-foreground">{item.title}</p>
// // //                     <p className="text-xs text-muted-foreground">{item.date}</p>
// // //                   </div>
// // //                   <span className={`text-xs px-2 py-1 rounded-full ${
// // //                     item.type === "consultation" ? "bg-accent/10 text-accent" :
// // //                     item.type === "report" ? "bg-warning/10 text-warning" :
// // //                     "bg-primary/10 text-primary"
// // //                   }`}>
// // //                     {item.type}
// // //                   </span>
// // //                 </motion.div>
// // //               ))}
// // //             </div>
// // //           </GlassCard>
// // //         </div>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // const Clock = ({ size, className }: { size: number; className?: string }) => (
// // //   <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
// // // );

// // // export default PatientDashboard;
// // // import { useState, useEffect } from "react";
// // // import { motion } from "framer-motion";
// // // import { Activity, Calendar, FileText, MessageSquare, TrendingUp, Heart, Loader2 } from "lucide-react";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import GlassCard from "@/components/GlassCard";
// // // import { getPatientActivity } from "@/services/patientService";

// // // const PatientDashboard = () => {
// // //   const [activities, setActivities] = useState([]);
// // //   const [loading, setLoading] = useState(true);
  
// // //   // Pulling the data we saved during login
// // //   const firstName = localStorage.getItem('firstName') || "Patient";
// // //   const userId = localStorage.getItem('userId');

// // //   useEffect(() => {
// // //     const loadDashboardData = async () => {
// // //       if (!userId) return;
// // //       try {
// // //         const data = await getPatientActivity(userId);
// // //         setActivities(data); // Real bookings from Spring Boot
// // //       } catch (error) {
// // //         console.error("Failed to load activities", error);
// // //       } finally {
// // //         setLoading(false);
// // //       }
// // //     };
// // //     loadDashboardData();
// // //   }, [userId]);

// // //   // Derived Stats (Real logic based on your Backend data)
// // //   const stats = [
// // //     { label: "Health Score", value: "92%", icon: Heart, color: "text-success" },
// // //     { label: "Consultations", value: activities.length.toString(), icon: Calendar, color: "text-accent" },
// // //     { label: "Reports", value: "0", icon: FileText, color: "text-warning" }, // To be integrated with a Records module
// // //     { label: "Triage Chats", value: "0", icon: MessageSquare, color: "text-primary" }, // To be integrated with Triage module
// // //   ];

// // //   return (
// // //     <DashboardLayout role="patient">
// // //       <div className="max-w-6xl mx-auto space-y-8">
// // //         <div>
// // //           <h1 className="font-display text-3xl font-bold text-foreground">
// // //             Welcome back, {firstName}
// // //           </h1>
// // //           <p className="text-muted-foreground mt-1">Here's your health overview</p>
// // //         </div>

// // //         {/* Stats Grid */}
// // //         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
// // //           {stats.map((stat, i) => (
// // //             <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
// // //               <div className="flex items-center justify-between mb-3">
// // //                 <stat.icon size={22} className={stat.color} />
// // //                 <TrendingUp size={14} className="text-success" />
// // //               </div>
// // //               <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
// // //               <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
// // //             </GlassCard>
// // //           ))}
// // //         </div>

// // //         <div className="grid lg:grid-cols-2 gap-6">
// // //           {/* Quick Actions */}
// // //           <GlassCard className="p-6" delay={0.3}>
// // //             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// // //               <Activity size={18} className="text-accent" /> Quick Actions
// // //             </h3>
// // //             <div className="grid grid-cols-2 gap-3">
// // //               {[
// // //                 { label: "Start Triage", href: "/patient/triage" },
// // //                 { label: "Book Appointment", href: "/patient/book" },
// // //                 { label: "View Records", href: "/patient/records" },
// // //                 { label: "Find Hospitals", href: "/patient/hospitals" },
// // //               ].map((action) => (
// // //                 <a key={action.label} href={action.href} className="glass rounded-xl px-4 py-3 text-sm font-medium text-foreground hover:shadow-glow-accent hover:scale-[1.02] transition-all duration-300 text-center">
// // //                   {action.label}
// // //                 </a>
// // //               ))}
// // //             </div>
// // //           </GlassCard>

// // //           {/* Real Recent Activity */}
// // //           <GlassCard className="p-6" delay={0.4}>
// // //             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// // //               <Clock size={18} className="text-accent" /> Recent Activity
// // //             </h3>
// // //             <div className="space-y-3">
// // //               {loading ? (
// // //                 <div className="flex justify-center py-8"><Loader2 className="animate-spin text-accent" /></div>
// // //               ) : activities.length > 0 ? (
// // //                 activities.slice(0, 4).map((item: any, i) => (
// // //                   <div key={i} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
// // //                     <div>
// // //                       <p className="text-sm font-medium text-foreground">{item.doctorName}</p>
// // //                       <p className="text-xs text-muted-foreground">{new Date(item.appointmentTime).toLocaleDateString()}</p>
// // //                     </div>
// // //                     <span className="text-xs px-2 py-1 rounded-full bg-accent/10 text-accent">
// // //                       {item.status}
// // //                     </span>
// // //                   </div>
// // //                 ))
// // //               ) : (
// // //                 <p className="text-sm text-muted-foreground text-center py-8">No recent activity found.</p>
// // //               )}
// // //             </div>
// // //           </GlassCard>
// // //         </div>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // const Clock = ({ size, className }: { size: number; className?: string }) => (
// // //   <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
// // // );

// // // export default PatientDashboard;







// // import { useState, useEffect } from "react";
// // import { motion } from "framer-motion";
// // import { Activity, Calendar, FileText, MessageSquare, TrendingUp, Heart, Clock, Loader2 } from "lucide-react";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import GlassCard from "@/components/GlassCard";
// // import { patientService } from "@/services/patientService";

// // const PatientDashboard = () => {
// //   const [profile, setProfile] = useState<any>(null);
// //   const [bookings, setBookings] = useState([]);
// //   const [recordsCount, setRecordsCount] = useState(0);
// //   const [loading, setLoading] = useState(true);

// //   useEffect(() => {
// //     const loadData = async () => {
// //       try {
// //         const user = await patientService.getProfile();
// //         setProfile(user); // Identity
        
// //         const [userBookings, userRecords] = await Promise.all([
// //           patientService.getBookings(user.id), // Bookings
// //           patientService.getHistory(user.id)   // Records
// //         ]);
        
// //         setBookings(userBookings);
// //         setRecordsCount(userRecords.length);
// //       } catch (err) {
// //         console.error("Dashboard Sync Failed:", err);
// //       } finally {
// //         setLoading(false);
// //       }
// //     };
// //     loadData();
// //   }, []);

// //   const stats = [
// //     { label: "Health Score", value: "92%", icon: Heart, color: "text-success" },
// //     { label: "Consultations", value: bookings.length.toString(), icon: Calendar, color: "text-accent" },
// //     { label: "Reports", value: recordsCount.toString(), icon: FileText, color: "text-warning" },
// //     { label: "Triage Chats", value: "Live", icon: MessageSquare, color: "text-primary" },
// //   ];

// //   if (loading) return (
// //     <div className="min-h-screen flex items-center justify-center bg-background">
// //       <Loader2 className="animate-spin text-accent h-12 w-12" />
// //     </div>
// //   );

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-6xl mx-auto space-y-8">
// //         <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
// //           <h1 className="font-display text-3xl font-bold text-foreground">
// //             Welcome back, {profile?.firstName || "Alex"}
// //           </h1>
// //           <p className="text-muted-foreground mt-1">Managed via your Medibot ID: {profile?.id.substring(0,8)}...</p>
// //         </motion.div>

// //         {/* Stats Grid */}
// //         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
// //           {stats.map((stat, i) => (
// //             <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
// //               <div className="flex items-center justify-between mb-3">
// //                 <stat.icon size={22} className={stat.color} />
// //                 <TrendingUp size={14} className="text-success" />
// //               </div>
// //               <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
// //               <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
// //             </GlassCard>
// //           ))}
// //         </div>

// //         <div className="grid lg:grid-cols-2 gap-6">
// //           {/* Quick Actions */}
// //           <GlassCard className="p-6" delay={0.3}>
// //             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// //               <Activity size={18} className="text-accent" /> Quick Actions
// //             </h3>
// //             <div className="grid grid-cols-2 gap-3">
// //               {[
// //                 { label: "Start Triage", href: "/patient/triage" },
// //                 { label: "Book Appointment", href: "/patient/book" },
// //                 { label: "View Records", href: "/patient/records" },
// //                 { label: "Find Hospitals", href: "/patient/hospitals" },
// //               ].map((action) => (
// //                 <a key={action.label} href={action.href} className="glass rounded-xl px-4 py-3 text-sm font-medium text-foreground hover:shadow-glow-accent hover:scale-[1.02] transition-all duration-300 text-center">
// //                   {action.label}
// //                 </a>
// //               ))}
// //             </div>
// //           </GlassCard>

// //           {/* Real Recent Activity from Booking Module */}
// //           <GlassCard className="p-6" delay={0.4}>
// //             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
// //               <Clock size={18} className="text-accent" /> Recent Bookings
// //             </h3>
// //             <div className="space-y-3">
// //               {bookings.length > 0 ? bookings.slice(0, 4).map((item: any, i) => (
// //                 <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + (i * 0.1) }} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
// //                   <div>
// //                     <p className="text-sm font-medium text-foreground">Dr. {item.doctorName}</p>
// //                     <p className="text-xs text-muted-foreground">{new Date(item.appointmentTime).toLocaleString()}</p>
// //                   </div>
// //                   <span className={`text-xs px-2 py-1 rounded-full ${item.status === 'CONFIRMED' ? 'bg-success/10 text-success' : 'bg-accent/10 text-accent'}`}>
// //                     {item.status}
// //                   </span>
// //                 </motion.div>
// //               )) : (
// //                 <p className="text-center text-muted-foreground text-sm py-10">No recent consultations found.</p>
// //               )}
// //             </div>
// //           </GlassCard>
// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default PatientDashboard;




































// import { useState, useEffect } from "react";
// import { motion } from "framer-motion";
// import { Activity, Calendar, FileText, MessageSquare, TrendingUp, Heart, Clock, Loader2, Video, ArrowRight } from "lucide-react";
// import DashboardLayout from "@/components/DashboardLayout";
// import GlassCard from "@/components/GlassCard";
// import { patientService } from "@/services/patientService";

// const PatientDashboard = () => {
//   const [profile, setProfile] = useState<any>(null);
//   const [bookings, setBookings] = useState<any[]>([]);
//   const [recordsCount, setRecordsCount] = useState(0);
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     const loadData = async () => {
//       try {
//         const user = await patientService.getProfile();
//         setProfile(user); 
        
//         // Parallel fetching for high performance on deployment
//         const [userBookings, userRecords] = await Promise.all([
//           patientService.getBookings(user.id), 
//           patientService.getHistory(user.id)   
//         ]);
        
//         setBookings(Array.isArray(userBookings) ? userBookings : []);
//         setRecordsCount(Array.isArray(userRecords) ? userRecords.length : 0);
//       } catch (err) {
//         console.error("Dashboard Sync Failed:", err);
//       } finally {
//         setLoading(false);
//       }
//     };
//     loadData();
//   }, []);

//   // Filter: Upcoming vs Past based on current time
//   const upcomingAppointments = bookings.filter(b => 
//     b.status === "CONFIRMED" && new Date(b.appointmentTime) > new Date()
//   );

//   const stats = [
//     { label: "Health Score", value: "92%", icon: Heart, color: "text-success" },
//     { label: "Consultations", value: bookings.length.toString(), icon: Calendar, color: "text-accent" },
//     { label: "Reports", value: recordsCount.toString(), icon: FileText, color: "text-warning" },
//     { label: "Medibot ID", value: profile?.id.substring(0,6).toUpperCase() || "...", icon: Activity, color: "text-primary" },
//   ];

//   if (loading) return (
//     <div className="min-h-screen flex items-center justify-center bg-background">
//       <Loader2 className="animate-spin text-accent h-12 w-12" />
//     </div>
//   );

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-6xl mx-auto space-y-8">
//         <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
//           <h1 className="font-display text-3xl font-bold text-foreground">
//             Welcome back, {profile?.firstName || "Alex"}
//           </h1>
//           <p className="text-muted-foreground mt-1">Real-time health insights for your profile.</p>
//         </motion.div>

//         {/* Stats Section */}
//         <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
//           {stats.map((stat, i) => (
//             <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
//               <div className="flex items-center justify-between mb-3">
//                 <stat.icon size={22} className={stat.color} />
//                 <TrendingUp size={14} className="text-success" />
//               </div>
//               <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
//               <div className="text-[10px] uppercase tracking-wider text-muted-foreground mt-1">{stat.label}</div>
//             </GlassCard>
//           ))}
//         </div>

//         {/* UPCOMING APPOINTMENTS: Active Handshake with Booking DTO */}
//         {upcomingAppointments.length > 0 && (
//           <GlassCard className="p-6 border-accent/30 bg-accent/5" delay={0.2}>
//             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
//               <Calendar size={18} className="text-accent" /> Upcoming Consultations
//             </h3>
//             <div className="grid md:grid-cols-2 gap-4">
//               {upcomingAppointments.map((apt: any) => (
//                 <div key={apt.bookingId} className="glass rounded-2xl p-4 flex items-center justify-between hover:shadow-glow-accent transition-all">
//                   <div className="flex items-center gap-3">
//                     <div className="w-10 h-10 rounded-full bg-accent/20 flex items-center justify-center text-accent font-bold">
//                       {apt.doctorName.charAt(0)}
//                     </div>
//                     <div>
//                       <p className="text-sm font-bold text-foreground">{apt.doctorName}</p>
//                       <p className="text-xs text-muted-foreground">
//                         {new Date(apt.appointmentTime).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
//                       </p>
//                     </div>
//                   </div>
//                   {apt.meetingLink && (
//                     <a 
//                       href={apt.meetingLink} 
//                       target="_blank" 
//                       rel="noopener noreferrer"
//                       className="bg-accent text-accent-foreground p-2.5 rounded-xl hover:scale-110 transition-all shadow-glow-accent"
//                     >
//                       <Video size={18} />
//                     </a>
//                   )}
//                 </div>
//               ))}
//             </div>
//           </GlassCard>
//         )}

//         <div className="grid lg:grid-cols-2 gap-6">
//           {/* Action Hub */}
//           <GlassCard className="p-6" delay={0.3}>
//             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
//               <Activity size={18} className="text-accent" /> Medical Services
//             </h3>
//             <div className="grid grid-cols-2 gap-3">
//               {[
//                 { label: "Book Specialist", href: "/patient/book" },
//                 { label: "AI Triage Chat", href: "/patient/triage" },
//                 { label: "Health Records", href: "/patient/records" },
//                 { label: "Hospital Map", href: "/patient/hospitals" },
//               ].map((action) => (
//                 <a key={action.label} href={action.href} className="glass rounded-xl px-4 py-4 text-sm font-bold text-foreground hover:shadow-glow-accent hover:scale-[1.02] transition-all text-center">
//                   {action.label}
//                 </a>
//               ))}
//             </div>
//           </GlassCard>

//           {/* Timeline: History view from Booking Module */}
//           <GlassCard className="p-6" delay={0.4}>
//             <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
//               <Clock size={18} className="text-accent" /> History Timeline
//             </h3>
//             <div className="space-y-4">
//               {bookings.length > 0 ? bookings.slice(0, 4).map((item: any, i) => (
//                 <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + (i * 0.1) }} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
//                   <div className="flex gap-3 items-start">
//                     <div className="mt-1.5 w-2 h-2 rounded-full bg-accent" />
//                     <div>
//                       <p className="text-sm font-medium text-foreground">Visit: {item.doctorName}</p>
//                       <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{new Date(item.appointmentTime).toDateString()}</p>
//                     </div>
//                   </div>
//                   <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${item.status === 'CONFIRMED' ? 'bg-success/10 text-success' : 'bg-white/5 text-muted-foreground'}`}>
//                     {item.status}
//                   </span>
//                 </motion.div>
//               )) : (
//                 <p className="text-center text-muted-foreground text-sm py-10 italic">No medical history found.</p>
//               )}
//             </div>
//           </GlassCard>
//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default PatientDashboard;






import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Activity, Calendar, FileText, MessageSquare, TrendingUp, Heart, Clock, Loader2, Video, ArrowRight, AlertCircle, X } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import { patientService } from "@/services/patientService";
import api from "@/lib/api"; // Ensure you use your centralized API instance
import { useNavigate } from "react-router-dom";

const PatientDashboard = () => {
  const navigate = useNavigate();
  const [profile, setProfile] = useState<any>(null);
  const [bookings, setBookings] = useState<any[]>([]);
  const [recordsCount, setRecordsCount] = useState(0);
  const [loading, setLoading] = useState(true);
  
  // LIVE ALERT STATE
  const [activeSession, setActiveSession] = useState<any>(null);

  useEffect(() => {
    const loadData = async () => {
      try {
        const user = await patientService.getProfile();
        setProfile(user); 
        
        const [userBookings, userRecords] = await Promise.all([
          patientService.getBookings(user.id), 
          patientService.getHistory(user.id)   
        ]);
        
        setBookings(Array.isArray(userBookings) ? userBookings : []);
        setRecordsCount(Array.isArray(userRecords) ? userRecords.length : 0);
      } catch (err) {
        console.error("Dashboard Sync Failed:", err);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  // POLLING FOR HANDSHAKE: Checks if any confirmed appointment has a doctor waiting
  useEffect(() => {
    if (!profile?.id) return;

    const checkForActiveDoctor = async () => {
      // Find the most recent confirmed booking
      const upcoming = bookings.find(b => b.status === "CONFIRMED");
      if (!upcoming) return;

      try {
        // DISCOVERY CALL: Hits your new /api/consultations/active/{bookingId} endpoint
        const res = await api.get(`/consultations/active/${upcoming.bookingId}`);
        if (res.data) {
          setActiveSession({
            bookingId: upcoming.bookingId,
            doctorName: upcoming.doctorName,
            roomId: res.data
          });
        }
      } catch (e) {
        setActiveSession(null); // Doctor hasn't joined yet
      }
    };

    const interval = setInterval(checkForActiveDoctor, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, [bookings, profile]);

  const upcomingAppointments = bookings.filter(b => 
    b.status === "CONFIRMED" && new Date(b.appointmentTime) > new Date()
  );

  const stats = [
    { label: "Health Score", value: "92%", icon: Heart, color: "text-success" },
    { label: "Consultations", value: bookings.length.toString(), icon: Calendar, color: "text-accent" },
    { label: "Reports", value: recordsCount.toString(), icon: FileText, color: "text-warning" },
    { label: "Medibot ID", value: profile?.id.substring(0,6).toUpperCase() || "...", icon: Activity, color: "text-primary" },
  ];

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <Loader2 className="animate-spin text-accent h-12 w-12" />
    </div>
  );

  return (
    <DashboardLayout role="patient">
      <div className="max-w-6xl mx-auto space-y-6">
        
        {/* LIVE HANDSHAKE ALERT: Only appears when Dr. Elena is in Jitsi */}
        <AnimatePresence>
          {activeSession && (
            <motion.div 
              initial={{ height: 0, opacity: 0 }} 
              animate={{ height: "auto", opacity: 1 }} 
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="bg-accent/10 border border-accent/30 rounded-3xl p-5 flex flex-col md:flex-row items-center justify-between gap-4 shadow-float-lg backdrop-blur-md">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-accent flex items-center justify-center animate-pulse">
                    <Video className="text-white" size={24} />
                  </div>
                  <div>
                    <h2 className="text-foreground font-bold flex items-center gap-2">
                      Live Session Ready!
                      <span className="flex h-2 w-2 rounded-full bg-destructive animate-ping" />
                    </h2>
                    <p className="text-xs text-muted-foreground">Dr. {activeSession.doctorName} is waiting for you in the clinical room.</p>
                  </div>
                </div>
                <button 
                  onClick={() => navigate(`/patient/consultation/${activeSession.bookingId}`)}
                  className="bg-accent text-white px-8 py-3 rounded-2xl font-bold text-sm flex items-center gap-2 hover:scale-105 transition-all shadow-glow-accent"
                >
                  Join Meeting <ArrowRight size={16} />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="font-display text-3xl font-bold text-foreground">
            Welcome back, {profile?.firstName || "Alex"}
          </h1>
          <p className="text-muted-foreground mt-1 text-sm uppercase tracking-widest font-medium">Global Patient Identity: {profile?.id.substring(0,8)}...</p>
        </motion.div>

        {/* Stats Section */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {stats.map((stat, i) => (
            <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
              <div className="flex items-center justify-between mb-3">
                <stat.icon size={22} className={stat.color} />
                <TrendingUp size={14} className="text-success" />
              </div>
              <div className="font-display text-2xl font-bold text-foreground">{stat.value}</div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground mt-1">{stat.label}</div>
            </GlassCard>
          ))}
        </div>

        {/* Main Content Grid */}
        <div className="grid lg:grid-cols-2 gap-6">
          <GlassCard className="p-6" delay={0.3}>
            <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
              <Activity size={18} className="text-accent" /> Clinical Hub
            </h3>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Book Specialist", href: "/patient/book" },
                { label: "AI Triage Chat", href: "/patient/triage" },
                { label: "Health Records", href: "/patient/records" },
                { label: "Hospital Map", href: "/patient/hospitals" },
              ].map((action) => (
                <a key={action.label} href={action.href} className="glass rounded-xl px-4 py-4 text-sm font-bold text-foreground hover:shadow-glow-accent hover:scale-[1.02] transition-all text-center">
                  {action.label}
                </a>
              ))}
            </div>
          </GlassCard>

          <GlassCard className="p-6" delay={0.4}>
            <h3 className="font-display text-lg font-bold text-foreground mb-4 flex items-center gap-2">
              <Clock size={18} className="text-accent" /> History Timeline
            </h3>
            <div className="space-y-4">
              {bookings.length > 0 ? bookings.slice(0, 4).map((item: any, i) => (
                <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + (i * 0.1) }} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
                  <div className="flex gap-3 items-start">
                    <div className="mt-1.5 w-2 h-2 rounded-full bg-accent" />
                    <div>
                      <p className="text-sm font-medium text-foreground">Visit: {item.doctorName}</p>
                      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{new Date(item.appointmentTime).toDateString()}</p>
                    </div>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${item.status === 'CONFIRMED' ? 'bg-success/10 text-success' : 'bg-white/5 text-muted-foreground'}`}>
                    {item.status}
                  </span>
                </motion.div>
              )) : (
                <p className="text-center text-muted-foreground text-sm py-10 italic">Your medical timeline is empty.</p>
              )}
            </div>
          </GlassCard>
        </div>

      </div>
    </DashboardLayout>
  );
};

export default PatientDashboard;