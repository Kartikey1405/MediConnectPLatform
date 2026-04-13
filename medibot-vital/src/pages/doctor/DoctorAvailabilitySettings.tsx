import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Clock, Save, Plus, Trash2, Loader2, CalendarX, CalendarCheck,
  ChevronLeft, ChevronRight
} from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import api from "@/lib/api";
import { toast } from "sonner";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = [
  "January","February","March","April","May","June",
  "July","August","September","October","November","December"
];

const DoctorAvailabilitySettings = () => {
  const doctorId = localStorage.getItem("doctorId") || localStorage.getItem("userId");

  // Template state (the 3 session windows)
  const [templates, setTemplates] = useState([
    { label: "Morning Session",   startTime: "09:30", endTime: "11:00" },
    { label: "Afternoon Session", startTime: "13:00", endTime: "14:30" },
    { label: "Evening Session",   startTime: "16:00", endTime: "17:30" },
  ]);
  const [savingTemplates, setSavingTemplates] = useState(false);

  // Calendar state for marking unavailable dates
  const [calendarMonth, setCalendarMonth] = useState(new Date());
  const [unavailableDates, setUnavailableDates] = useState<Set<string>>(new Set());
  const [savingAvailability, setSavingAvailability] = useState(false);

  // Load existing templates
  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.get(`/doctor/templates?doctorId=${doctorId}`);
        if (Array.isArray(res.data) && res.data.length > 0) {
          setTemplates(res.data.map((t: any) => ({
            label: t.label,
            startTime: t.startTime,
            endTime: t.endTime,
          })));
        }
      } catch { /* keep defaults */ }
    };
    if (doctorId) load();
  }, [doctorId]);

  const handleSaveTemplates = async () => {
    try {
      setSavingTemplates(true);
      await api.post(`/doctor/templates?doctorId=${doctorId}`, templates);
      toast.success("Session windows saved successfully!");
    } catch {
      toast.error("Failed to save session windows.");
    } finally {
      setSavingTemplates(false);
    }
  };

  const toggleDate = (dateStr: string) => {
    setUnavailableDates((prev) => {
      const next = new Set(prev);
      if (next.has(dateStr)) next.delete(dateStr);
      else next.add(dateStr);
      return next;
    });
  };

  const handleSaveAvailability = async () => {
    try {
      setSavingAvailability(true);
      await api.post(
        `/doctor/availability/unavailable?doctorId=${doctorId}`,
        Array.from(unavailableDates)
      );
      toast.success("Availability calendar updated!");
    } catch {
      toast.error("Failed to update availability.");
    } finally {
      setSavingAvailability(false);
    }
  };

  const getDaysInMonth = () => {
    const year = calendarMonth.getFullYear();
    const month = calendarMonth.getMonth();
    const firstDay = new Date(year, month, 1).getDay();
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const cells = [];
    for (let i = 0; i < firstDay; i++) cells.push(null);
    for (let d = 1; d <= daysInMonth; d++) {
      const dateStr = `${year}-${String(month + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const isPast = new Date(dateStr) < new Date(new Date().toDateString());
      cells.push({ day: d, dateStr, isPast });
    }
    return cells;
  };

  return (
    <DashboardLayout role="doctor">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
            <Clock size={28} className="text-accent" /> Schedule Settings
          </h1>
          <p className="text-muted-foreground mt-1">Configure your session windows and availability</p>
        </div>

        {/* Session Templates */}
        <GlassCard className="p-6">
          <h2 className="font-bold text-lg text-foreground mb-1">Daily Session Windows</h2>
          <p className="text-sm text-muted-foreground mb-6">
            These 3 sessions will appear as bookable slots on every available day.
          </p>

          <div className="space-y-4">
            {templates.map((t, i) => (
              <motion.div key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="glass rounded-2xl p-4 flex flex-col sm:flex-row gap-4 items-start sm:items-center">
                <input
                  value={t.label}
                  onChange={(e) => {
                    const n = [...templates]; n[i].label = e.target.value; setTemplates(n);
                  }}
                  placeholder="Session Name"
                  className="bg-transparent border-b border-white/20 outline-none text-sm font-bold text-accent flex-1 pb-1"
                />
                <div className="flex items-center gap-3">
                  <div className="flex flex-col gap-1">
                    <label className="text-[10px] text-muted-foreground uppercase">Start</label>
                    <input
                      type="time"
                      value={t.startTime}
                      onChange={(e) => { const n = [...templates]; n[i].startTime = e.target.value; setTemplates(n); }}
                      className="bg-transparent border border-white/20 rounded-lg px-3 py-1.5 text-sm outline-none focus:border-accent transition-colors"
                    />
                  </div>
                  <span className="text-muted-foreground text-sm mt-4">→</span>
                  <div className="flex flex-col gap-1">
                    <label className="text-[10px] text-muted-foreground uppercase">End</label>
                    <input
                      type="time"
                      value={t.endTime}
                      onChange={(e) => { const n = [...templates]; n[i].endTime = e.target.value; setTemplates(n); }}
                      className="bg-transparent border border-white/20 rounded-lg px-3 py-1.5 text-sm outline-none focus:border-accent transition-colors"
                    />
                  </div>
                  {templates.length > 1 && (
                    <button onClick={() => setTemplates(templates.filter((_, idx) => idx !== i))}
                      className="text-destructive/50 hover:text-destructive transition-colors mt-4">
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
              </motion.div>
            ))}
          </div>

          <div className="flex items-center gap-3 mt-4">
            {templates.length < 5 && (
              <button
                onClick={() => setTemplates([...templates, { label: "", startTime: "09:00", endTime: "10:30" }])}
                className="flex items-center gap-2 text-sm text-accent hover:opacity-80 transition-all"
              >
                <Plus size={16} /> Add Session
              </button>
            )}
            <button
              onClick={handleSaveTemplates}
              disabled={savingTemplates}
              className="ml-auto flex items-center gap-2 bg-accent text-accent-foreground px-6 py-2.5 rounded-xl font-bold text-sm shadow-glow-accent hover:opacity-90 transition-all disabled:opacity-50"
            >
              {savingTemplates ? <Loader2 className="animate-spin" size={16} /> : <Save size={16} />}
              Save Windows
            </button>
          </div>
        </GlassCard>

        {/* Availability Calendar */}
        <GlassCard className="p-6">
          <h2 className="font-bold text-lg text-foreground mb-1">Mark Days Off</h2>
          <p className="text-sm text-muted-foreground mb-6">
            Click any future date to toggle it as unavailable. Patients won't see those days.
          </p>

          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-foreground">
              {MONTHS[calendarMonth.getMonth()]} {calendarMonth.getFullYear()}
            </h3>
            <div className="flex gap-2">
              <button
                onClick={() => setCalendarMonth(new Date(calendarMonth.getFullYear(), calendarMonth.getMonth() - 1))}
                className="glass rounded-xl p-2 hover:bg-white/10"
                disabled={calendarMonth <= new Date(new Date().getFullYear(), new Date().getMonth())}
              >
                <ChevronLeft size={16} />
              </button>
              <button
                onClick={() => setCalendarMonth(new Date(calendarMonth.getFullYear(), calendarMonth.getMonth() + 1))}
                className="glass rounded-xl p-2 hover:bg-white/10"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-7 mb-2">
            {DAYS.map((d) => (
              <div key={d} className="text-center text-[10px] font-bold text-muted-foreground uppercase py-2">{d}</div>
            ))}
          </div>

          <div className="grid grid-cols-7 gap-1">
            {getDaysInMonth().map((cell, idx) => {
              if (!cell) return <div key={`e-${idx}`} />;
              const isOff = unavailableDates.has(cell.dateStr);
              return (
                <button
                  key={cell.dateStr}
                  onClick={() => !cell.isPast && toggleDate(cell.dateStr)}
                  disabled={cell.isPast}
                  title={isOff ? "Click to make available" : "Click to mark as day off"}
                  className={`
                    aspect-square rounded-xl flex items-center justify-center text-sm font-bold transition-all
                    ${cell.isPast ? "text-muted-foreground/20 cursor-not-allowed" : ""}
                    ${isOff && !cell.isPast ? "bg-destructive/20 text-destructive ring-1 ring-destructive/30" : ""}
                    ${!isOff && !cell.isPast ? "hover:bg-white/10 text-foreground" : ""}
                  `}
                >
                  {cell.day}
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-6 mt-4 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1.5"><CalendarCheck size={12} className="text-accent" /> Available</span>
            <span className="flex items-center gap-1.5"><CalendarX size={12} className="text-destructive" /> Day Off</span>
          </div>

          <button
            onClick={handleSaveAvailability}
            disabled={savingAvailability || unavailableDates.size === 0}
            className="mt-6 flex items-center gap-2 bg-accent text-accent-foreground px-6 py-2.5 rounded-xl font-bold text-sm shadow-glow-accent hover:opacity-90 transition-all disabled:opacity-40"
          >
            {savingAvailability ? <Loader2 className="animate-spin" size={16} /> : <Save size={16} />}
            Save Availability
          </button>
        </GlassCard>
      </div>
    </DashboardLayout>
  );
};

export default DoctorAvailabilitySettings;