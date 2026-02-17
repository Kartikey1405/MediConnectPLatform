
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
