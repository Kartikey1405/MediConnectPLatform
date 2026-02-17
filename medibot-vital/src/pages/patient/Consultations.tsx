


import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Calendar, Download, User, Clock, FileText, Loader2, ClipboardList, ShieldCheck, Pill } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";

const Consultations = () => {
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        const userId = localStorage.getItem("userId");
        if (!userId) throw new Error("Session expired.");

        const res = await api.get(`/consultations/patient/${userId}`);
        setHistory(Array.isArray(res.data) ? res.data : []);
      } catch (err) {
        console.error("Clinical History Sync Failure:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  if (loading) return (
    <DashboardLayout role="patient">
      <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-4">
        <Loader2 className="animate-spin text-accent" size={40} />
        <p className="text-muted-foreground animate-pulse font-medium">Decrypting medical vault...</p>
      </div>
    </DashboardLayout>
  );

  return (
    <DashboardLayout role="patient">
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="flex justify-between items-end border-b border-white/5 pb-6">
          <div>
            <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
              <FileText size={28} className="text-accent" /> Medical Records
            </h1>
            <p className="text-muted-foreground mt-1 text-sm font-medium">Verified summaries and prescriptions</p>
          </div>
          <div className="hidden md:flex items-center gap-2 text-[10px] font-bold text-success bg-success/5 px-3 py-1.5 rounded-lg border border-success/10 uppercase tracking-widest">
            <ShieldCheck size={12} /> HIPAA Encrypted
          </div>
        </div>

        <div className="space-y-6">
          {history.length > 0 ? history.map((c, i) => (
            <motion.div key={c.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
              <div className="glass rounded-3xl p-6 shadow-float hover:shadow-float-lg transition-all border-white/5 group">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                  <div className="flex items-center gap-4">
                    <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center border border-accent/20">
                      <User size={26} className="text-accent" />
                    </div>
                    <div>
                      <h3 className="font-display font-bold text-foreground text-lg">
                        Dr. {c.booking?.slot?.doctor?.user?.firstName} {c.booking?.slot?.doctor?.user?.lastName}
                      </h3>
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                        {c.booking?.slot?.doctor?.specialization}
                      </p>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground font-bold flex gap-3">
                    <span className="bg-white/5 px-3 py-1.5 rounded-lg border border-white/5 flex items-center gap-2">
                      <Calendar size={14} className="text-accent" /> {new Date(c.startTime).toLocaleDateString()}
                    </span>
                  </div>
                </div>

                <div className="bg-background/40 rounded-2xl p-5 mb-4 border border-white/5">
                    <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-accent">
                      <ClipboardList size={12} /> Physician's Summary
                    </div>
                    <p className="text-sm text-foreground/80 leading-relaxed italic">
                      "{c.doctorNotes || "General consultation completed. Summary pending finalization."}"
                    </p>
                </div>

                {/* PRESCRIPTION SECTION */}
                {c.prescriptions && c.prescriptions.length > 0 && (
                  <div className="bg-accent/5 rounded-2xl p-5 mb-6 border border-accent/10">
                    <div className="flex items-center gap-2 mb-3 text-[10px] uppercase tracking-widest font-black text-success">
                      <Pill size={12} /> Prescribed Medications
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {c.prescriptions.map((p: any) => (
                        <div key={p.id} className="glass-strong p-3 rounded-xl text-xs flex justify-between items-center border border-white/5">
                          <div>
                            <span className="font-bold text-foreground block">{p.medicineName}</span>
                            <span className="text-[10px] text-muted-foreground italic">{p.instructions || "No instructions provided"}</span>
                          </div>
                          <span className="bg-accent/10 text-accent px-2 py-1 rounded-md font-bold">{p.dosage}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between mt-4">
                  <span className="text-[10px] font-black uppercase px-4 py-1.5 rounded-full bg-success/10 text-success border border-success/20">
                    Verified Session
                  </span>
                  <button className="flex items-center gap-2 text-xs text-accent font-bold hover:underline">
                    <Download size={14} /> Download PDF
                  </button>
                </div>
              </div>
            </motion.div>
          )) : (
            <div className="text-center py-24 glass rounded-[40px] border-dashed border-2 border-white/5">
                <FileText size={56} className="mx-auto text-muted-foreground/10 mb-6" />
                <p className="text-sm text-muted-foreground italic">Your medical history is empty.</p>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Consultations;