

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
// FIX: Kept UserCheck here as an import from Lucide
import { Calendar, Clock, Loader2, UserCheck, ArrowRight, Filter } from "lucide-react"; 
import { useNavigate } from "react-router-dom";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";
import { toast } from "sonner";

const DoctorAppointments = () => {
  const navigate = useNavigate();
  const [appointments, setAppointments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAppointments = async () => {
      try {
        setLoading(true);
        // 1. CRITICAL: Identify the doctor using the specific Specialist ID
        const doctorId = localStorage.getItem("doctorId") || localStorage.getItem("userId");
        
        if (!doctorId) {
          toast.error("Session expired. Please log in again.");
          navigate("/login");
          return;
        }

        // 2. Fetch schedule from http://localhost:8080/api/bookings/doctor/{id}
        const res = await api.get(`/bookings/doctor/${doctorId}`);
        setAppointments(Array.isArray(res.data) ? res.data : []);
      } catch (err) {
        console.error("Schedule sync failure:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchAppointments();
  }, [navigate]);

  return (
    <DashboardLayout role="doctor">
      <div className="max-w-5xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
              <Calendar size={28} className="text-accent" /> Appointments
            </h1>
            <p className="text-muted-foreground mt-1">Manage your upcoming patient sessions</p>
          </div>
          <button className="glass rounded-xl px-4 py-2 text-sm font-bold text-foreground hover:shadow-glow-accent transition-all flex items-center gap-2">
            <Filter size={14} /> Today
          </button>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-32 space-y-4">
             <Loader2 className="animate-spin text-accent" size={40} />
             <p className="text-sm text-muted-foreground italic">Synchronizing patient data...</p>
          </div>
        ) : (
          <div className="space-y-3">
            {appointments.length > 0 ? appointments.map((apt, i) => (
              <motion.div
                key={apt.bookingId}
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="glass rounded-2xl p-5 hover:shadow-glow-accent transition-all group border-white/5"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center text-accent font-bold">
                      {apt.patientName?.charAt(0) || "P"}
                    </div>
                    <div>
                      {/* Uses patientName from updated BookingResponse DTO */}
                      <h3 className="font-display font-bold text-foreground">{apt.patientName || "Verified Patient"}</h3>
                      <p className="text-[10px] uppercase tracking-widest text-muted-foreground">Video Consultation</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6">
                    <div className="text-xs text-muted-foreground font-medium">
                      <div className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-lg">
                        <Clock size={12} className="text-accent"/> 
                        {new Date(apt.appointmentTime).toLocaleString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}
                      </div>
                    </div>
                    
                    <button 
                      onClick={() => navigate(`/doctor/consultation/${apt.bookingId}`)}
                      className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-accent text-accent-foreground text-xs font-bold hover:scale-105 transition-all shadow-glow-accent active:scale-95"
                    >
                      Start Session <ArrowRight size={14} />
                    </button>
                  </div>
                </div>
              </motion.div>
            )) : (
              <div className="text-center py-20 glass rounded-3xl border-dashed border-2 border-white/10">
                 {/* FIX: Renamed local call to EmptyScheduleIcon to avoid conflict */}
                 <EmptyScheduleIcon size={48} className="mx-auto text-muted-foreground/20 mb-4" />
                 <p className="text-muted-foreground text-sm italic font-medium">Your schedule is currently clear.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

// FIX: Renamed this local component to solve the TS2440 error
const EmptyScheduleIcon = ({ size, className }: { size: number; className?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></svg>
);

export default DoctorAppointments;