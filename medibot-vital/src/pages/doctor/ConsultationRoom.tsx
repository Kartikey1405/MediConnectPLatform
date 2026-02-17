


import { useState, useEffect } from "react"; 
import { useParams, useNavigate } from "react-router-dom";
import { JitsiMeeting } from "@jitsi/react-sdk";
import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck, Pill, Plus, Trash2, Save } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";

const DoctorConsultationRoom = () => {
  const { bookingId } = useParams(); 
  const navigate = useNavigate();
  
  const [consultation, setConsultation] = useState<any>(null);
  const [roomId, setRoomId] = useState<string>(""); 
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState("");
  const [isEnding, setIsEnding] = useState(false);
  
  const [activeTab, setActiveTab] = useState<"notes" | "prescriptions">("notes");
  const [prescriptions, setPrescriptions] = useState([{
    medicineName: '', dosage: '', frequency: '', duration: '', instructions: ''
  }]);

  // 1. HANDSHAKE: Authoritative Room ID Creation
  useEffect(() => {
    const initSession = async () => {
      if (!bookingId) {
        toast.error("No clinical context found. Returning to queue.");
        navigate("/doctor/dashboard");
        return;
      }

      try {
        setLoading(true);
        // Start the session context
        const res = await api.post(`/consultations/start/${bookingId}`);
        const consultationData = res.data;
        setConsultation(consultationData);

        const generatedRoomName = `Medibot-Secure-Room-${bookingId}`;
        
        // Broadcast the Room ID to the database so Kartik can find you
        await api.patch(`/consultations/${consultationData.id}/room`, generatedRoomName, {
          headers: { 'Content-Type': 'text/plain' } 
        });
        
        setRoomId(generatedRoomName);
      } catch (err: any) {
        // Fallback for page refreshes
        if (err.response?.status === 500 || err.response?.status === 400) {
          setRoomId(`Medibot-Secure-Room-${bookingId}`);
        } else {
          toast.error("Clinical handshake failed.");
          navigate("/doctor/dashboard");
        }
      } finally {
        setLoading(false);
      }
    };
    initSession();
  }, [bookingId, navigate]);

  // 2. PRESCRIPTION HANDLER
  const handleSavePrescriptions = async () => {
    if (!consultation?.id) return;
    try {
      // POST the array of medicines to the new endpoint
      await api.post(`/consultations/${consultation.id}/prescriptions`, prescriptions);
      toast.success("Prescriptions synced to Patient Vault");
    } catch (err) {
      toast.error("Failed to sync prescriptions.");
    }
  };

  // 3. WRAP-UP HANDLER (FIXED: Payload matches ConsultationEndRequest DTO)
  const handleEndCall = async () => {
    const activeId = consultation?.id || bookingId;
    if (!activeId) return;

    try {
      setIsEnding(true);
      // FIX: Wrap 'notes' in an object to match the backend @RequestBody DTO 
      await api.patch(`/consultations/end/${activeId}`, { notes: notes }); 
      
      toast.success("Consultation finalized and archived.");
      navigate("/doctor/dashboard"); 
    } catch (err) {
      console.error("End call error:", err);
      toast.error("Sync failed. Copy your notes manually before leaving.");
    } finally {
      setIsEnding(false);
    }
  };

  if (loading) return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background">
      <Loader2 className="animate-spin text-accent mb-4" size={44} />
      <p className="text-muted-foreground animate-pulse font-medium">Securing clinical tunnel...</p>
    </div>
  );

  return (
    <DashboardLayout role="doctor">
      <div className="max-w-7xl mx-auto space-y-4 flex flex-col h-[calc(100vh-8rem)]">
        
        {/* Physician Header */}
        <div className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/10 shadow-float">
          <div>
            <h1 className="font-display text-xl font-bold flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-destructive animate-ping" />
              Patient: {consultation?.booking?.patientName || "Verified User"}
            </h1>
            <p className="text-[10px] text-muted-foreground flex items-center gap-1 uppercase tracking-widest font-black">
              <ShieldCheck size={10} className="text-success" /> HIPAA SECURE CHANNEL
            </p>
          </div>
          
          <button 
            onClick={handleEndCall} 
            disabled={isEnding} 
            className="bg-destructive hover:bg-destructive/90 text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold transition-all active:scale-95 disabled:opacity-50 shadow-lg"
          >
            {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
            Finish & Save
          </button>
        </div>

        <div className="grid lg:grid-cols-[1fr_400px] gap-4 flex-1 min-h-0">
          
          {/* JITSI VIEWPORT */}
          <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5 relative">
            {roomId && (
              <JitsiMeeting
                domain="meet.jit.si"
                roomName={roomId} 
                configOverwrite={{ 
                  startWithAudioMuted: true, startWithVideoMuted: true,
                  prejoinPageEnabled: false, disableDeepLinking: true 
                }}
                getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; iframeRef.style.width = '100%'; }}
              />
            )}
          </div>

          {/* Clinical Workspace Sidebar */}
          <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
            <div className="flex border-b border-white/10">
              <button onClick={() => setActiveTab("notes")} className={`flex-1 py-4 text-xs font-bold uppercase flex items-center justify-center gap-2 transition-all ${activeTab === 'notes' ? 'text-accent bg-white/5 border-b-2 border-accent' : 'text-muted-foreground opacity-50'}`}>
                <FileText size={14} /> Notes
              </button>
              <button onClick={() => setActiveTab("prescriptions")} className={`flex-1 py-4 text-xs font-bold uppercase flex items-center justify-center gap-2 transition-all ${activeTab === 'prescriptions' ? 'text-accent bg-white/5 border-b-2 border-accent' : 'text-muted-foreground opacity-50'}`}>
                <Pill size={14} /> Prescribe
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
              {activeTab === "notes" ? (
                <textarea 
                  value={notes} 
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Document findings and advice here..."
                  className="w-full h-full bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 font-medium"
                />
              ) : (
                <div className="space-y-4">
                  {prescriptions.map((p, i) => (
                    <div key={i} className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-3 relative group">
                      <input 
                        placeholder="Medicine Name" 
                        value={p.medicineName}
                        onChange={(e) => {
                          const newP = [...prescriptions];
                          newP[i].medicineName = e.target.value;
                          setPrescriptions(newP);
                        }}
                        className="w-full bg-transparent border-b border-white/10 outline-none text-sm font-bold text-accent pb-1" 
                      />
                      <div className="grid grid-cols-2 gap-2">
                        <input placeholder="Dosage" value={p.dosage} onChange={(e) => { const newP = [...prescriptions]; newP[i].dosage = e.target.value; setPrescriptions(newP); }} className="bg-transparent border-b border-white/10 outline-none text-[10px] text-foreground/70" />
                        <input placeholder="Frequency" value={p.frequency} onChange={(e) => { const newP = [...prescriptions]; newP[i].frequency = e.target.value; setPrescriptions(newP); }} className="bg-transparent border-b border-white/10 outline-none text-[10px] text-foreground/70" />
                      </div>
                      <button onClick={() => setPrescriptions(prescriptions.filter((_, idx) => idx !== i))} className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-destructive/20 text-destructive flex items-center justify-center opacity-0 group-hover:opacity-100 transition-all"><Trash2 size={12}/></button>
                    </div>
                  ))}
                  <button onClick={() => setPrescriptions([...prescriptions, { medicineName: '', dosage: '', frequency: '', duration: '', instructions: '' }])} className="w-full py-3 rounded-xl border border-dashed border-white/20 text-muted-foreground hover:text-accent transition-all text-[10px] uppercase font-bold flex items-center justify-center gap-2">
                    <Plus size={14} /> Add Medicine
                  </button>
                  <button onClick={handleSavePrescriptions} className="w-full py-3 rounded-xl bg-accent/20 text-accent font-bold text-xs flex items-center justify-center gap-2 hover:bg-accent/30 transition-all">
                    <Save size={14} /> Sync to Vault
                  </button>
                </div>
              )}
            </div>
            
            <div className="p-4 bg-black/20 border-t border-white/5 text-[10px] text-muted-foreground font-bold uppercase flex items-center gap-2">
              <ClipboardCheck size={14} className="text-success" /> Synced ID: {String(bookingId).substring(0,8)}
            </div>
          </div>

        </div>
      </div>
    </DashboardLayout>
  );
};

export default DoctorConsultationRoom;
