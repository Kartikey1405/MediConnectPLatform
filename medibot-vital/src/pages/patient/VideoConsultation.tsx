import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { JitsiMeeting } from "@jitsi/react-sdk";
import { Phone, FileText, Loader2, ShieldCheck, ClipboardCheck, User } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import api from "@/lib/api";
import { toast } from "sonner";

const VideoConsultation = () => {
  const { bookingId } = useParams(); 
  const navigate = useNavigate();
  
  const [consultation, setConsultation] = useState<any>(null);
  const [activeRoomId, setActiveRoomId] = useState<string>(""); 
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState("");
  const [isEnding, setIsEnding] = useState(false);

  useEffect(() => {
    let pollInterval: NodeJS.Timeout;

    const initHandshake = async () => {
      try {
        const sessionRes = await api.post(`/consultations/start/${bookingId}`);
        setConsultation(sessionRes.data);

        const discoverRoom = async () => {
          try {
            const roomRes = await api.get(`/consultations/active/${bookingId}`);
            if (roomRes.data) {
              setActiveRoomId(roomRes.data);
              setLoading(false);
              clearInterval(pollInterval);
            }
          } catch (err) {
            console.log("Discovery: Waiting for Dr. Elena...");
          }
        };

        pollInterval = setInterval(discoverRoom, 3000);
        discoverRoom();

      } catch (err) {
        toast.error("Handshake failed. Verify appointment status.");
        navigate("/patient/dashboard");
      }
    };

    initHandshake();
    return () => clearInterval(pollInterval);
  }, [bookingId, navigate]);

  const handleEndCall = async () => {
    if (!consultation?.id) return;
    try {
      setIsEnding(true);
      // FIXED: Wrap 'notes' in an object to match the ConsultationEndRequest DTO
      await api.patch(`/consultations/end/${consultation.id}`, { notes: notes }); 
      
      toast.success("Consultation archived.");
      navigate("/patient/consultations"); 
    } catch (err) {
      toast.error("Unable to save session. Redirecting...");
      navigate("/patient/dashboard");
    } finally {
      setIsEnding(false);
    }
  };

  if (loading) return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background">
      <Loader2 className="animate-spin text-accent mb-4" size={44} />
      <h2 className="text-xl font-bold">Connecting to Physician...</h2>
      <p className="text-muted-foreground animate-pulse text-sm">Validating your encrypted clinical tunnel.</p>
    </div>
  );

  return (
    <DashboardLayout role="patient">
      <div className="max-w-7xl mx-auto space-y-6 h-[calc(100vh-8rem)] flex flex-col">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="font-display text-2xl font-bold flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-destructive animate-ping" />
              Live Consultation
            </h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-black">
              <ShieldCheck size={12} className="text-success" /> HIPAA SECURE
            </p>
          </div>
          <button onClick={handleEndCall} disabled={isEnding} className="bg-destructive text-white px-8 py-3 rounded-2xl flex items-center gap-2 font-bold shadow-lg shadow-destructive/20 active:scale-95 transition-all">
            {isEnding ? <Loader2 className="animate-spin" size={18} /> : <Phone size={18} className="rotate-[135deg]" />}
            Finish & Exit
          </button>
        </div>

        <div className="grid lg:grid-cols-[1fr_350px] gap-6 flex-1 min-h-0">
          <div className="glass rounded-3xl overflow-hidden bg-black/40 border-white/5">
            {activeRoomId && (
              <JitsiMeeting
                domain="meet.jit.si"
                roomName={activeRoomId}
                configOverwrite={{ startWithAudioMuted: true, startWithVideoMuted: true, prejoinPageEnabled: false }}
                getIFrameRef={(iframeRef) => { iframeRef.style.height = '100%'; iframeRef.style.width = '100%'; }}
              />
            )}
          </div>
          <div className="glass rounded-3xl flex flex-col overflow-hidden border-white/5 bg-white/5">
            <div className="p-5 border-b border-white/10 bg-white/5 flex items-center gap-2 text-accent font-bold text-sm uppercase tracking-wider">
              <FileText size={16} /> My Notes
            </div>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Type notes for your record..." className="flex-1 p-5 bg-transparent border-none outline-none text-sm leading-relaxed resize-none text-foreground/80 font-medium" />
            <div className="p-4 bg-black/20 border-t border-white/5 text-[10px] text-muted-foreground font-bold uppercase flex items-center gap-2">
              <ClipboardCheck size={14} className="text-success" /> Session Sync Active
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default VideoConsultation;
