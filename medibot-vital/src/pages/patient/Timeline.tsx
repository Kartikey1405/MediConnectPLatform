


import { motion, AnimatePresence } from "framer-motion";
import { Clock, MessageSquare, FileText, Calendar, ChevronDown, Sparkles, User, AlertCircle, Loader2 } from "lucide-react";
import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api"; // FIX: Use centralized api instance for interceptors

// Interface to handle the combined data structure
interface TimelineEvent {
  id: string;
  type: "triage" | "consultation";
  title: string;
  date: string;
  summary: string;
  details?: string;
  icon: any;
  color: string;
}

const Timeline = () => {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHealthJourney = async () => {
      try {
        setLoading(true);
        // FIX: Consistent ID retrieval matching AuthService.ts
        const patientId = localStorage.getItem("userId");

        if (!patientId || patientId === "undefined") {
          console.warn("No valid Patient ID found in storage. Redirecting or showing empty state.");
          setLoading(false);
          return;
        }

        // Simpler simultaneous fetch using the authenticated 'api' instance
        // FIX: Interceptors handle the Bearer token automatically now
        const [triageRes, recordRes] = await Promise.all([
          api.get(`/triage/history/patient/${patientId}`),
          api.get(`/records/patient/${patientId}`)
        ]);

        // 1. Map AI Triage Records (from TriageHistoryController)
        const triageEvents: TimelineEvent[] = triageRes.data.map((t: any) => ({
          id: t.id,
          type: "triage",
          title: `AI Triage: ${t.predictedDisease}`,
          date: t.createdAt, // Standard timestamp from backend
          summary: `Symptoms: ${t.symptomsInput}`,
          details: t.aiAdvice,
          icon: Sparkles,
          color: "bg-accent"
        }));

        // 2. Map Doctor Consultations (from MedicalRecordController)
        const consultationEvents: TimelineEvent[] = recordRes.data
          .filter((r: any) => !r.fileUrl) // Filter out pure file reports for a cleaner timeline
          .map((r: any) => ({
            id: r.id,
            type: "consultation",
            title: `Consultation: Dr. ${r.doctorName || 'Specialist'}`,
            date: r.date || r.createdAt,
            summary: r.diagnosis || 'General Checkup',
            details: r.symptoms ? `Patient reported: ${r.symptoms}` : undefined,
            icon: User,
            color: "bg-primary"
          }));

        // 3. Combine and Sort by Date (Newest first)
        const combined = [...triageEvents, ...consultationEvents].sort(
          (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
        );

        setEvents(combined);
      } catch (error: any) {
        console.error("Failed to load timeline history:", error);
        // If 403, we know the session is invalid
        if (error.response?.status === 403) {
          console.error("Auth mismatch. Session might be stale.");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchHealthJourney();
  }, []);

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', { 
        day: 'numeric', 
        month: 'short', 
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (e) {
      return dateString;
    }
  };

  return (
    <DashboardLayout role="patient">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
            <Clock size={28} className="text-accent" />
            Health Timeline
          </h1>
          <p className="text-muted-foreground mt-1">Your complete journey: AI analysis & clinical visits</p>
        </div>

        <div className="relative">
          {/* Vertical Timeline Thread */}
          <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-accent via-primary/50 to-transparent" />

          <div className="space-y-6">
            {loading ? (
              <div className="flex flex-col items-center py-20 text-muted-foreground gap-3">
                <Loader2 className="animate-spin text-accent" size={32} />
                <p className="italic">Syncing your health history...</p>
              </div>
            ) : events.length === 0 ? (
              <div className="pl-16 py-10">
                <div className="glass rounded-2xl p-8 text-center border-dashed border-2">
                  <AlertCircle className="mx-auto mb-2 opacity-20" size={40} />
                  <p className="text-muted-foreground font-medium">Your timeline is empty.</p>
                  <p className="text-xs text-muted-foreground/60">AI Triage chats and Doctor visits will appear here.</p>
                </div>
              </div>
            ) : (
              events.map((item, i) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, x: -20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: i * 0.05 }}
                  className="relative pl-16"
                >
                  {/* Timeline Node */}
                  <div className={`absolute left-4 top-4 w-5 h-5 rounded-full border-4 border-background z-10 ${item.color} shadow-lg`} />
                  
                  {/* Timeline Card */}
                  <div
                    className="glass rounded-2xl p-5 shadow-float hover:shadow-float-lg transition-all duration-300 cursor-pointer group"
                    onClick={() => setExpanded(expanded === item.id ? null : item.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-4">
                        <div className={`p-2.5 rounded-xl ${item.type === 'triage' ? 'bg-accent/10 text-accent' : 'bg-primary/10 text-primary'}`}>
                          <item.icon size={20} />
                        </div>
                        <div>
                          <h3 className="font-display font-bold text-foreground text-sm group-hover:text-accent transition-colors">
                            {item.title}
                          </h3>
                          <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-widest">
                            {formatDate(item.date)}
                          </p>
                        </div>
                      </div>
                      <motion.div animate={{ rotate: expanded === item.id ? 180 : 0 }}>
                        <ChevronDown size={18} className="text-muted-foreground" />
                      </motion.div>
                    </div>

                    <div className="mt-2 pl-14">
                       <p className="text-xs text-muted-foreground line-clamp-1 italic">
                        {item.summary}
                      </p>
                    </div>

                    <AnimatePresence>
                      {expanded === item.id && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          className="mt-4 pt-4 border-t border-border/50 overflow-hidden"
                        >
                          <div className="space-y-3">
                            <div className="bg-foreground/5 rounded-xl p-3">
                               <p className="text-[10px] font-bold text-accent uppercase mb-1">
                                 {item.type === 'triage' ? 'AI Recommendations' : 'Doctor Diagnosis'}
                               </p>
                               <p className="text-sm text-foreground leading-relaxed whitespace-pre-wrap">
                                 {item.details || item.summary}
                               </p>
                            </div>
                            {item.type === 'triage' && (
                              <p className="text-[10px] text-muted-foreground italic">
                                * This analysis was performed by Medibot AI and is for informational purposes.
                              </p>
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </motion.div>
              ))
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Timeline;