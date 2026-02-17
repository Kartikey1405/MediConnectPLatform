


import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FileText, Upload, Download, Trash2, File, AlertCircle, Loader2, CheckCircle, ExternalLink, User, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import api from "@/lib/api"; // FIX: Use the customized api instance for automatic JWT attachment

const MedicalRecords = () => {
  const [dragOver, setDragOver] = useState(false);
  const [records, setRecords] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  // 1. Fetch all records (Consultations + Uploaded Files)
  const fetchRecords = async () => {
    try {
      const patientId = localStorage.getItem("userId");
      const token = localStorage.getItem("accessToken");

      if (!patientId || !token || patientId === "undefined") {
        console.warn("Session missing. Please log in.");
        setLoading(false);
        return;
      }

      // FIX: Use 'api' instance to automatically include Bearer token
      const response = await api.get(`/records/patient/${patientId}`);
      setRecords(response.data);
    } catch (error) {
      console.error("Failed to fetch records:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  // 2. Handle Physical Report Upload to Cloudinary
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement> | any) => {
    const file = e.target.files?.[0] || e.dataTransfer?.files[0];
    if (!file) return;

    const patientId = localStorage.getItem("userId");
    
    // Preparation for Multipart/Form-Data upload
    const formData = new FormData();
    formData.append("file", file);
    formData.append("title", file.name);

    setUploading(true);
    try {
      // Matches Backend: @PostMapping("/upload/{patientId}")
      await api.post(`/records/upload/${patientId}`, formData, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      
      // Refresh list to show the new Cloudinary link
      fetchRecords();
    } catch (error) {
      console.error("Upload failed:", error);
      alert("Failed to upload report. Ensure file is under 10MB and you are logged in.");
    } finally {
      setUploading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', { 
      day: 'numeric', 
      month: 'short', 
      year: 'numeric' 
    });
  };

  return (
    <DashboardLayout role="patient">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
            <FileText size={28} className="text-accent" />
            Medical Vault
          </h1>
          <p className="text-muted-foreground mt-1">Manage your consultations and laboratory reports</p>
        </div>

        {/* Upload Zone */}
        <GlassCard className="p-8" tilt={false}>
          <input 
            type="file" 
            id="file-input" 
            className="hidden" 
            onChange={handleFileUpload}
            accept=".pdf,.png,.jpg,.jpeg"
          />
          <label
            htmlFor="file-input"
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFileUpload(e); }}
            className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 cursor-pointer block ${
              dragOver ? "border-accent bg-accent/5 scale-[1.01]" : "border-border/50 hover:bg-foreground/5"
            }`}
          >
            {uploading ? (
              <Loader2 size={48} className="mx-auto text-accent animate-spin mb-4" />
            ) : (
              <Upload size={48} className="mx-auto text-muted-foreground mb-4" />
            )}
            <p className="font-display font-bold text-foreground mb-1">
              {uploading ? "Uploading to Cloudinary..." : "Click or Drag to Upload Lab Report"}
            </p>
            <p className="text-xs text-muted-foreground">Supported: PDF, PNG, JPG (Max 10MB)</p>
          </label>
        </GlassCard>

        {/* Dynamic Records List */}
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-widest text-muted-foreground px-1">Your Records History</h2>
          
          {loading ? (
            <div className="py-10 text-center italic text-muted-foreground flex flex-col items-center gap-3">
              <Loader2 className="animate-spin text-accent" />
              Syncing with healthcare database...
            </div>
          ) : records.length === 0 ? (
            <div className="glass rounded-2xl p-12 text-center">
              <AlertCircle size={40} className="mx-auto mb-3 opacity-10" />
              <p className="text-muted-foreground">No records found. Upload a report or consult a doctor.</p>
            </div>
          ) : (
            <div className="grid gap-3">
              {records.map((record, i) => {
                const isFileUpload = !!record.fileUrl;
                return (
                  <motion.div
                    key={record.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="glass rounded-2xl p-4 flex items-center justify-between group hover:border-accent/30 transition-all shadow-float hover:shadow-float-lg"
                  >
                    <div className="flex items-center gap-4">
                      <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${isFileUpload ? "bg-accent/10 text-accent" : "bg-primary/10 text-primary"}`}>
                        {isFileUpload ? <File size={22} /> : <User size={22} />}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                           <p className="font-bold text-sm text-foreground">{record.title || "Clinical Visit"}</p>
                           <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-bold uppercase ${isFileUpload ? 'bg-accent/20 text-accent' : 'bg-primary/20 text-primary'}`}>
                              {isFileUpload ? 'Report' : 'Consultation'}
                           </span>
                        </div>
                        <p className="text-[10px] text-muted-foreground uppercase">
                          {formatDate(record.date || record.createdAt)} • {record.doctorName}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {isFileUpload ? (
                        <a 
                          href={record.fileUrl} 
                          target="_blank" 
                          rel="noreferrer"
                          className="p-2.5 glass rounded-xl text-accent hover:bg-accent/10 transition-all flex items-center gap-2 text-xs font-semibold"
                          title="View Document"
                        >
                          <ExternalLink size={16} />
                          View
                        </a>
                      ) : (
                        <button className="p-2.5 glass rounded-xl text-primary hover:bg-primary/10 transition-all flex items-center gap-2 text-xs font-semibold">
                          <FileText size={16} />
                          Details
                        </button>
                      )}
                      <button className="p-2.5 glass rounded-xl text-destructive hover:bg-destructive/10 transition-all">
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default MedicalRecords;