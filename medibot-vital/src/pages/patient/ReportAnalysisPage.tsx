import { useState, useRef, DragEvent, ChangeEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Upload, FileImage, Loader2, AlertTriangle,
  CheckCircle, Activity, Lightbulb, ShieldAlert, Info
} from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";
import api from "@/lib/api";
import { toast } from "sonner";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AnalysisResult {
  id: string;
  imageUrl: string;
  findings: string;
  possibleCondition: string;
  recommendations: string;
  riskLevel: "LOW" | "MODERATE" | "HIGH" | "UNKNOWN";
}

// ─── Risk Level Config ────────────────────────────────────────────────────────

const RISK_CONFIG = {
  LOW: {
    label: "Low Risk",
    bg: "bg-success/10",
    border: "border-success/30",
    text: "text-success",
    icon: CheckCircle,
  },
  MODERATE: {
    label: "Moderate Risk",
    bg: "bg-warning/10",
    border: "border-warning/30",
    text: "text-warning",
    icon: AlertTriangle,
  },
  HIGH: {
    label: "High Risk",
    bg: "bg-destructive/10",
    border: "border-destructive/30",
    text: "text-destructive",
    icon: ShieldAlert,
  },
  UNKNOWN: {
    label: "Risk Unclassified",
    bg: "bg-muted/10",
    border: "border-muted/30",
    text: "text-muted-foreground",
    icon: Info,
  },
} as const;

// ─── Recommendation parser ────────────────────────────────────────────────────
// Splits numbered list "1. Step one. 2. Step two." into array items

const parseRecommendations = (raw: string): string[] => {
  // Remove trailing alert line if appended by service
  const base = raw.split("\n\nAlert:")[0].trim();
  // Try numbered list split
  const numbered = base.split(/\d+\.\s+/).filter(Boolean);
  if (numbered.length > 1) return numbered.map((s) => s.trim());
  // Fallback: period-split
  return base.split(". ").filter((s) => s.length > 4).map((s) => s.trim());
};

// ─── Component ────────────────────────────────────────────────────────────────

const ReportAnalysisPage = () => {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── File handling ───────────────────────────────────────────────────────────

  const handleFile = (selected: File) => {
    const allowed = ["image/jpeg", "image/png", "image/webp", "image/gif", "application/pdf"];
    if (!allowed.includes(selected.type)) {
      toast.error("Please upload an image file (JPG, PNG, WEBP) or PDF.");
      return;
    }
    if (selected.size > 10 * 1024 * 1024) {
      toast.error("File must be under 10 MB.");
      return;
    }
    setFile(selected);
    setResult(null);
    // Generate preview for images only
    if (selected.type.startsWith("image/")) {
      const reader = new FileReader();
      reader.onload = (e) => setPreview(e.target?.result as string);
      reader.readAsDataURL(selected);
    } else {
      setPreview(null);
    }
  };

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (selected) handleFile(selected);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) handleFile(dropped);
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  // ── Analysis call ───────────────────────────────────────────────────────────

  const handleAnalyze = async () => {
    if (!file) return;
    setLoading(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await api.post("/report-insight/analyze", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      setResult(res.data);
      toast.success("Analysis complete!");
    } catch (err: any) {
      const msg =
        err.response?.data?.message ||
        err.response?.data ||
        "Analysis failed. Please try again.";
      toast.error(String(msg));
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setPreview(null);
    setResult(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  const riskConfig = result ? RISK_CONFIG[result.riskLevel] ?? RISK_CONFIG.UNKNOWN : null;
  const recommendations = result ? parseRecommendations(result.recommendations) : [];

  return (
    <DashboardLayout role="patient">
      <div className="max-w-3xl mx-auto space-y-8">

        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
            <Activity size={28} className="text-accent" />
            AI Report Analyzer
          </h1>
          <p className="text-muted-foreground mt-1">
            Upload an X-ray, scan, or lab report for an AI-generated clinical summary.
          </p>
        </motion.div>

        {/* Upload Card */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <GlassCard className="p-6" tilt={false}>
            {/* Drop Zone */}
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => !file && fileInputRef.current?.click()}
              className={`
                relative rounded-2xl border-2 border-dashed transition-all duration-200 cursor-pointer
                flex flex-col items-center justify-center text-center
                ${isDragging ? "border-accent bg-accent/5 scale-[1.01]" : "border-white/10 hover:border-accent/40 hover:bg-white/5"}
                ${file ? "py-6" : "py-12"}
              `}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*,.pdf"
                className="hidden"
                onChange={handleInputChange}
              />

              <AnimatePresence mode="wait">
                {!file ? (
                  <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    className="flex flex-col items-center gap-3">
                    <div className="w-16 h-16 rounded-2xl bg-accent/10 flex items-center justify-center">
                      <Upload size={28} className="text-accent" />
                    </div>
                    <div>
                      <p className="font-bold text-foreground">Drag & drop your report here</p>
                      <p className="text-sm text-muted-foreground mt-1">or click to browse files</p>
                    </div>
                    <p className="text-[11px] text-muted-foreground/60 uppercase tracking-widest">
                      JPG · PNG · WEBP · PDF · Max 10MB
                    </p>
                  </motion.div>
                ) : (
                  <motion.div key="preview" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
                    className="flex items-center gap-5 px-4 w-full">
                    {preview ? (
                      <img src={preview} alt="Preview" className="w-24 h-24 object-cover rounded-xl border border-white/10 shrink-0" />
                    ) : (
                      <div className="w-24 h-24 rounded-xl bg-accent/10 flex items-center justify-center shrink-0">
                        <FileImage size={32} className="text-accent" />
                      </div>
                    )}
                    <div className="text-left flex-1 min-w-0">
                      <p className="font-bold text-foreground truncate">{file.name}</p>
                      <p className="text-sm text-muted-foreground mt-1">
                        {(file.size / 1024 / 1024).toFixed(2)} MB · Ready to analyze
                      </p>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleReset(); }}
                        className="text-xs text-destructive/70 hover:text-destructive mt-2 transition-colors"
                      >
                        Remove file
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Analyze Button */}
            <button
              onClick={handleAnalyze}
              disabled={!file || loading}
              className="mt-5 w-full bg-gradient-to-r from-primary to-accent text-white py-4 rounded-2xl font-bold text-sm shadow-glow-accent hover:scale-[1.01] active:scale-[0.99] transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:scale-100 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="animate-spin" size={18} />
                  Analyzing report...
                </>
              ) : (
                <>
                  <Activity size={18} />
                  Analyze Report
                </>
              )}
            </button>
          </GlassCard>
        </motion.div>

        {/* Loading State */}
        <AnimatePresence>
          {loading && (
            <motion.div
              key="loading"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <GlassCard className="p-8 text-center" tilt={false}>
                <div className="w-16 h-16 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-4">
                  <Loader2 size={32} className="text-accent animate-spin" />
                </div>
                <p className="font-bold text-foreground">Processing your report...</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Our AI is generating a structured clinical summary.
                </p>
                <div className="flex justify-center gap-1 mt-5">
                  {[0, 1, 2].map((i) => (
                    <motion.div
                      key={i}
                      className="w-2 h-2 rounded-full bg-accent"
                      animate={{ opacity: [0.3, 1, 0.3] }}
                      transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.3 }}
                    />
                  ))}
                </div>
              </GlassCard>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Result Card */}
        <AnimatePresence>
          {result && !loading && riskConfig && (
            <motion.div
              key="result"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              {/* Risk Banner */}
              <div className={`rounded-2xl border p-4 flex items-center gap-3 ${riskConfig.bg} ${riskConfig.border}`}>
                <riskConfig.icon size={20} className={riskConfig.text} />
                <div>
                  <p className={`font-bold text-sm ${riskConfig.text}`}>{riskConfig.label}</p>
                  <p className="text-xs text-muted-foreground">
                    Based on AI analysis of your uploaded report
                  </p>
                </div>
              </div>

              {/* Uploaded Image */}
              {result.imageUrl && (
                <GlassCard className="p-4 flex items-center gap-4" tilt={false}>
                  <img
                    src={result.imageUrl}
                    alt="Analyzed report"
                    className="w-20 h-20 object-cover rounded-xl border border-white/10"
                    onError={(e) => (e.currentTarget.style.display = "none")}
                  />
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-widest font-bold">Report Stored</p>
                    <p className="text-sm text-foreground/70 mt-1 truncate max-w-xs">{result.imageUrl}</p>
                  </div>
                </GlassCard>
              )}

              {/* Findings */}
              <GlassCard className="p-6" tilt={false}>
                <h3 className="font-bold text-accent flex items-center gap-2 mb-3 text-sm uppercase tracking-wider">
                  <Activity size={16} /> Clinical Findings
                </h3>
                <p className="text-foreground/80 text-sm leading-relaxed">{result.findings}</p>
              </GlassCard>

              {/* Possible Condition */}
              <GlassCard className="p-6" tilt={false}>
                <h3 className="font-bold text-accent flex items-center gap-2 mb-3 text-sm uppercase tracking-wider">
                  <Info size={16} /> Possible Interpretation
                </h3>
                <p className="text-foreground/80 text-sm leading-relaxed italic">
                  {result.possibleCondition}
                </p>
                <p className="text-[10px] text-muted-foreground/50 mt-2 uppercase tracking-widest">
                  This is an interpretation, not a confirmed diagnosis.
                </p>
              </GlassCard>

              {/* Recommendations */}
              <GlassCard className="p-6" tilt={false}>
                <h3 className="font-bold text-accent flex items-center gap-2 mb-4 text-sm uppercase tracking-wider">
                  <Lightbulb size={16} /> Recommended Next Steps
                </h3>
                <ul className="space-y-3">
                  {recommendations.map((rec, i) => (
                    <motion.li
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.1 }}
                      className="flex items-start gap-3 text-sm text-foreground/80"
                    >
                      <span className="w-6 h-6 rounded-full bg-accent/10 text-accent font-bold text-[11px] flex items-center justify-center shrink-0 mt-0.5">
                        {i + 1}
                      </span>
                      {rec}
                    </motion.li>
                  ))}
                </ul>
              </GlassCard>

              {/* Disclaimer */}
              <div className="rounded-2xl border border-white/5 bg-white/3 p-4 flex items-start gap-3">
                <AlertTriangle size={16} className="text-warning shrink-0 mt-0.5" />
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  <span className="font-bold text-warning uppercase tracking-wide">Disclaimer: </span>
                  This analysis is AI-generated and is strictly for informational purposes only. 
                  It does not constitute a medical diagnosis or replace professional medical advice. 
                  Always consult a qualified healthcare professional for clinical decisions.
                </p>
              </div>

              {/* Analyze Another */}
              <button
                onClick={handleReset}
                className="w-full glass rounded-2xl py-3.5 text-sm font-bold text-muted-foreground hover:text-foreground hover:bg-white/5 transition-all"
              >
                Analyze Another Report
              </button>
            </motion.div>
          )}
        </AnimatePresence>

      </div>
    </DashboardLayout>
  );
};

export default ReportAnalysisPage;