import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Users, Calendar, Video, TrendingUp, Clock, Loader2, UserCheck, ArrowRight } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import api from "@/lib/api";
import { toast } from "sonner";
import { useNavigate } from "react-router-dom";

const DoctorDashboard = () => {
  const navigate = useNavigate();
  const [appointments, setAppointments] = useState<any[]>([]);
  const [userProfile, setUserProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        setLoading(true);
        
        // 1. Retrieve the identity data stored by authService
        const user = JSON.parse(localStorage.getItem("user") || "{}");
        const doctorId = localStorage.getItem("doctorId");
        setUserProfile(user);

        if (!doctorId) {
          toast.error("Clinical identity not found. Please log in again.");
          navigate("/login");
          return;
        }

        // 2. Fetch the queue using the correct DOCTOR ID
        // This avoids hitting the /api/admin paths that caused 403 Forbidden errors.
        const bookingsRes = await api.get(`/bookings/doctor/${doctorId}`);
        setAppointments(Array.isArray(bookingsRes.data) ? bookingsRes.data : []);
        
      } catch (err) {
        console.error("Dashboard Sync Failed:", err);
      } finally {
        setLoading(false);
      }
    };
    loadDashboard();
  }, [navigate]);

  // --- ACTION: START CONSULTATION ---
  const handleStartSession = async (bookingId: string) => {
    try {
      // Handshake with backend to mark the session as 'Active' in DB
      await api.post(`/consultations/start/${bookingId}`);
      toast.success("Medical room initialized.");
      // Redirect to the consultation workspace
      navigate(`/doctor/consultation/${bookingId}`);
    } catch (err) {
      toast.error("Could not start session. Verify appointment status.");
    }
  };

  // Stats Derived from real BookingResponse DTO
  const stats = [
    { 
        label: "Total Sessions", 
        value: appointments.length.toString(), 
        icon: Users, color: "text-accent", trend: "Today" 
    },
    { 
        label: "Confirmed Calls", 
        value: appointments.filter(a => a.status === 'CONFIRMED').length.toString(), 
        icon: Video, color: "text-success", trend: "Live" 
    },
    { 
        label: "Completed", 
        value: appointments.filter(a => a.status === 'COMPLETED').length.toString(), 
        icon: UserCheck, color: "text-primary", trend: "History" 
    },
  ];

  if (loading) return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background">
      <Loader2 className="animate-spin text-accent h-10 w-10 mb-4" />
      <p className="text-muted-foreground animate-pulse font-medium">Syncing clinical workspace...</p>
    </div>
  );

  return (
    <DashboardLayout role="doctor">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="font-display text-3xl font-bold text-foreground">Doctor Workspace</h1>
            <p className="text-muted-foreground mt-1">
              Welcome back, Dr. {userProfile?.firstName || "Specialist"}
            </p>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 glass rounded-2xl text-[10px] font-bold text-success uppercase tracking-widest">
            <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" /> Clinical Sync Active
          </div>
        </div>

        {/* Real-Time Stats Grid */}
        <div className="grid md:grid-cols-3 gap-4">
          {stats.map((stat, i) => (
            <GlassCard key={stat.label} delay={i * 0.1} className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center">
                  <stat.icon size={24} className={stat.color} />
                </div>
                <span className="text-[10px] font-black uppercase tracking-wider text-muted-foreground opacity-40">{stat.trend}</span>
              </div>
              <div className="font-display text-3xl font-bold text-foreground">{stat.value}</div>
              <div className="text-xs text-muted-foreground mt-1 font-medium">{stat.label}</div>
            </GlassCard>
          ))}
        </div>

        {/* Real Clinical Queue mapped from BookingResponse DTO */}
        <GlassCard className="p-8" delay={0.3}>
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-display text-lg font-bold text-foreground flex items-center gap-2">
              <Clock size={18} className="text-accent" /> Clinical Queue
            </h3>
            <button onClick={() => navigate("/doctor/appointments")} className="text-xs font-bold text-accent hover:underline">View Full Schedule</button>
          </div>
          
          <div className="space-y-4">
            {appointments.length > 0 ? appointments.slice(0, 5).map((apt, i) => (
              <motion.div
                key={apt.bookingId}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.5 + i * 0.08 }}
                className="glass rounded-2xl p-5 flex items-center justify-between hover:shadow-glow-accent transition-all border-white/5"
              >
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center text-sm font-bold text-accent border border-accent/20">
                    {apt.patientName?.charAt(0) || "P"}
                  </div>
                  <div>
                    <p className="font-bold text-foreground text-sm">{apt.patientName || "Verified Patient"}</p>
                    <p className="text-[10px] text-muted-foreground flex items-center gap-1 mt-0.5 font-medium uppercase tracking-tighter">
                        <Calendar size={10} className="text-accent" /> 
                        {new Date(apt.appointmentTime).toLocaleDateString()} at {new Date(apt.appointmentTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center gap-4">
                    <span className={`text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-tighter ${
                        apt.status === 'CONFIRMED' ? 'bg-success/10 text-success' : 'bg-white/5 text-muted-foreground'
                    }`}>
                        {apt.status}
                    </span>
                    {apt.status === 'CONFIRMED' && (
                        <button 
                            onClick={() => handleStartSession(apt.bookingId)}
                            className="text-xs px-6 py-2.5 rounded-xl bg-accent text-accent-foreground font-bold hover:scale-105 transition-all shadow-glow-accent active:scale-95 flex items-center gap-2"
                        >
                            Start Call <ArrowRight size={14} />
                        </button>
                    )}
                </div>
              </motion.div>
            )) : (
              <div className="text-center py-20 bg-white/5 rounded-3xl border border-dashed border-white/10">
                 <UserCheck size={40} className="mx-auto text-muted-foreground/20 mb-3" />
                 <p className="text-muted-foreground text-sm italic font-medium">No clinical sessions on the radar for today.</p>
              </div>
            )}
          </div>
        </GlassCard>
      </div>
    </DashboardLayout>
  );
};

export default DoctorDashboard;
