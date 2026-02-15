// // // import { useState } from "react";
// // // import { motion } from "framer-motion";
// // // import { FileText, Upload, Download, Eye, Trash2, File } from "lucide-react";
// // // import { Button } from "@/components/ui/button";
// // // import DashboardLayout from "@/components/DashboardLayout";
// // // import GlassCard from "@/components/GlassCard";

// // // const mockRecords = [
// // //   { id: 1, name: "Blood Test Report - Feb 2026.pdf", date: "Feb 8, 2026", size: "1.2 MB", type: "pdf" },
// // //   { id: 2, name: "Chest X-Ray Results.pdf", date: "Jan 20, 2026", size: "3.4 MB", type: "pdf" },
// // //   { id: 3, name: "Prescription - Dr. Chen.pdf", date: "Feb 5, 2026", size: "0.5 MB", type: "pdf" },
// // //   { id: 4, name: "ECG Report.png", date: "Jan 10, 2026", size: "2.1 MB", type: "image" },
// // //   { id: 5, name: "MRI Scan Results.pdf", date: "Dec 15, 2025", size: "8.7 MB", type: "pdf" },
// // // ];

// // // const MedicalRecords = () => {
// // //   const [dragOver, setDragOver] = useState(false);

// // //   return (
// // //     <DashboardLayout role="patient">
// // //       <div className="max-w-4xl mx-auto space-y-8">
// // //         <div>
// // //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// // //             <FileText size={28} className="text-accent" />
// // //             Medical Records
// // //           </h1>
// // //           <p className="text-muted-foreground mt-1">Upload and manage your health documents</p>
// // //         </div>

// // //         {/* Upload Zone */}
// // //         <GlassCard className="p-8" tilt={false}>
// // //           <div
// // //             onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
// // //             onDragLeave={() => setDragOver(false)}
// // //             onDrop={(e) => { e.preventDefault(); setDragOver(false); }}
// // //             className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-300 ${
// // //               dragOver ? "border-accent bg-accent/5 scale-[1.01]" : "border-border/50"
// // //             }`}
// // //           >
// // //             <Upload size={40} className="mx-auto text-muted-foreground mb-4" />
// // //             <p className="font-display font-bold text-foreground mb-1">Drag & drop files here</p>
// // //             <p className="text-sm text-muted-foreground mb-4">or click to browse (PDF, PNG, JPG)</p>
// // //             <Button className="bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold px-6 shadow-glow-accent hover:scale-[1.02] transition-all">
// // //               Browse Files
// // //             </Button>
// // //           </div>
// // //         </GlassCard>

// // //         {/* Records List */}
// // //         <div className="space-y-3">
// // //           {mockRecords.map((record, i) => (
// // //             <motion.div
// // //               key={record.id}
// // //               initial={{ opacity: 0, y: 20 }}
// // //               whileInView={{ opacity: 1, y: 0 }}
// // //               viewport={{ once: true }}
// // //               transition={{ delay: i * 0.08 }}
// // //             >
// // //               <div className="glass rounded-2xl p-4 flex items-center gap-4 shadow-float hover:shadow-float-lg hover:scale-[1.01] transition-all duration-300 group">
// // //                 <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center flex-shrink-0">
// // //                   <File size={22} className="text-accent" />
// // //                 </div>
// // //                 <div className="flex-1 min-w-0">
// // //                   <p className="font-medium text-foreground text-sm truncate">{record.name}</p>
// // //                   <p className="text-xs text-muted-foreground">{record.date} · {record.size}</p>
// // //                 </div>
// // //                 <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
// // //                   <button className="w-8 h-8 rounded-lg glass flex items-center justify-center text-accent hover:bg-accent/10 transition-colors">
// // //                     <Eye size={14} />
// // //                   </button>
// // //                   <button className="w-8 h-8 rounded-lg glass flex items-center justify-center text-foreground hover:bg-secondary transition-colors">
// // //                     <Download size={14} />
// // //                   </button>
// // //                   <button className="w-8 h-8 rounded-lg glass flex items-center justify-center text-destructive hover:bg-destructive/10 transition-colors">
// // //                     <Trash2 size={14} />
// // //                   </button>
// // //                 </div>
// // //               </div>
// // //             </motion.div>
// // //           ))}
// // //         </div>
// // //       </div>
// // //     </DashboardLayout>
// // //   );
// // // };

// // // export default MedicalRecords;





// // import { useState, useEffect } from "react";
// // import { motion } from "framer-motion";
// // import { FileText, Upload, Download, Eye, Trash2, File, Sparkles, User, AlertCircle } from "lucide-react";
// // import { Button } from "@/components/ui/button";
// // import DashboardLayout from "@/components/DashboardLayout";
// // import GlassCard from "@/components/GlassCard";
// // import axios from "axios"; // Ensure axios is installed

// // const MedicalRecords = () => {
// //   const [dragOver, setDragOver] = useState(false);
// //   const [records, setRecords] = useState<any[]>([]);
// //   const [loading, setLoading] = useState(true);

// //   // 1. Fetch real data from the Backend on mount
// //   useEffect(() => {
// //     const fetchHistory = async () => {
// //       try {
// //         // Replace with your dynamic user ID logic (e.g., from AuthContext or LocalStorage)
// //         const patientId = localStorage.getItem("userId") || "your-uuid-here"; 
// //         const response = await axios.get(`http://localhost:8080/api/records/patient/${patientId}`);
// //         setRecords(response.data);
// //       } catch (error) {
// //         console.error("Failed to fetch medical history:", error);
// //       } finally {
// //         setLoading(false);
// //       }
// //     };

// //     fetchHistory();
// //   }, []);

// //   // Format the LocalDateTime from Java into a readable string
// //   const formatDate = (dateString: string) => {
// //     const date = new Date(dateString);
// //     return date.toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
// //   };

// //   return (
// //     <DashboardLayout role="patient">
// //       <div className="max-w-4xl mx-auto space-y-8">
// //         <div>
// //           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
// //             <FileText size={28} className="text-accent" />
// //             Medical History & Records
// //           </h1>
// //           <p className="text-muted-foreground mt-1">Review your AI reports and doctor consultations</p>
// //         </div>

// //         {/* Upload Zone */}
// //         <GlassCard className="p-8" tilt={false}>
// //           <div
// //             onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
// //             onDragLeave={() => setDragOver(false)}
// //             onDrop={(e) => { e.preventDefault(); setDragOver(false); }}
// //             className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-300 ${
// //               dragOver ? "border-accent bg-accent/5 scale-[1.01]" : "border-border/50"
// //             }`}
// //           >
// //             <Upload size={40} className="mx-auto text-muted-foreground mb-4" />
// //             <p className="font-display font-bold text-foreground mb-1">Upload Laboratory Reports</p>
// //             <p className="text-sm text-muted-foreground mb-4">Add external PDF or image files to your record</p>
// //             <Button className="bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold px-6 shadow-glow-accent">
// //               Browse Files
// //             </Button>
// //           </div>
// //         </GlassCard>

// //         {/* Dynamic Records List */}
// //         <div className="space-y-4">
// //           <h2 className="text-lg font-bold text-foreground px-1">Recent Activities</h2>
          
// //           {loading ? (
// //             <div className="text-center py-10 text-muted-foreground italic">Syncing with medical database...</div>
// //           ) : records.length === 0 ? (
// //             <div className="glass rounded-2xl p-10 text-center text-muted-foreground">
// //               <AlertCircle size={40} className="mx-auto mb-3 opacity-20" />
// //               <p>No records found. Use the AI Triage to create your first report!</p>
// //             </div>
// //           ) : (
// //             records.map((record, i) => {
// //               // LOGIC: If no doctor name, it's an AI Triage record
// //               const isAIRecord = !record.doctorName || record.doctorName.trim() === "null null";
              
// //               return (
// //                 <motion.div
// //                   key={record.id}
// //                   initial={{ opacity: 0, x: -20 }}
// //                   animate={{ opacity: 1, x: 0 }}
// //                   transition={{ delay: i * 0.05 }}
// //                 >
// //                   <div className={`glass rounded-2xl p-5 flex items-center gap-5 border-l-4 transition-all hover:scale-[1.01] group ${
// //                     isAIRecord ? "border-l-accent shadow-glow-accent/10" : "border-l-primary shadow-float"
// //                   }`}>
// //                     {/* Icon based on Type */}
// //                     <div className={`w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0 ${
// //                       isAIRecord ? "bg-accent/10" : "bg-primary/10"
// //                     }`}>
// //                       {isAIRecord ? (
// //                         <Sparkles size={24} className="text-accent" />
// //                       ) : (
// //                         <User size={24} className="text-primary" />
// //                       )}
// //                     </div>

// //                     <div className="flex-1 min-w-0">
// //                       <div className="flex items-center gap-2 mb-1">
// //                         <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full ${
// //                           isAIRecord ? "bg-accent/20 text-accent" : "bg-primary/20 text-primary"
// //                         }`}>
// //                           {isAIRecord ? "AI Triage Report" : "Doctor Consultation"}
// //                         </span>
// //                         <span className="text-xs text-muted-foreground">{formatDate(record.date)}</span>
// //                       </div>
                      
// //                       <h3 className="font-bold text-foreground truncate">
// //                         {record.diagnosis || "No Diagnosis Provided"}
// //                       </h3>
                      
// //                       <p className="text-xs text-muted-foreground italic truncate">
// //                         Symptoms: {record.symptoms || "N/A"}
// //                       </p>
                      
// //                       {!isAIRecord && (
// //                         <p className="text-xs font-medium text-primary mt-1">
// //                           Dr. {record.doctorName}
// //                         </p>
// //                       )}
// //                     </div>

// //                     {/* Action Buttons */}
// //                     <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
// //                       <button className="w-10 h-10 rounded-xl glass flex items-center justify-center text-accent hover:bg-accent/20 transition-all">
// //                         <Eye size={18} />
// //                       </button>
// //                       <button className="w-10 h-10 rounded-xl glass flex items-center justify-center text-destructive hover:bg-destructive/10 transition-all">
// //                         <Trash2 size={18} />
// //                       </button>
// //                     </div>
// //                   </div>
// //                 </motion.div>
// //               );
// //             })
// //           )}
// //         </div>
// //       </div>
// //     </DashboardLayout>
// //   );
// // };

// // export default MedicalRecords;



// import { useState, useEffect } from "react";
// import { motion, AnimatePresence } from "framer-motion";
// import { FileText, Upload, Download, Trash2, File, AlertCircle, Loader2, CheckCircle } from "lucide-react";
// import { Button } from "@/components/ui/button";
// import DashboardLayout from "@/components/DashboardLayout";
// import GlassCard from "@/components/GlassCard";
// import axios from "axios";

// const MedicalRecords = () => {
//   const [dragOver, setDragOver] = useState(false);
//   const [records, setRecords] = useState<any[]>([]);
//   const [loading, setLoading] = useState(true);
//   const [uploading, setUploading] = useState(false);

//   // 1. Fetch only physical records (those with fileUrls)
//   const fetchRecords = async () => {
//     try {
//       const token = localStorage.getItem("token");
//       const storedUser = localStorage.getItem("user");
//       const parsedUser = storedUser ? JSON.parse(storedUser) : null;
//       const patientId = localStorage.getItem("userId") || parsedUser?.id;

//       if (!patientId) return;

//       const response = await axios.get(`http://localhost:8080/api/records/patient/${patientId}`, {
//         headers: { Authorization: `Bearer ${token}` }
//       });

//       // Filter: In this view, we only care about reports that have a Cloudinary link
//       const fileReports = response.data.filter((r: any) => r.fileUrl != null);
//       setRecords(fileReports);
//     } catch (error) {
//       console.error("Failed to fetch records:", error);
//     } finally {
//       setLoading(false);
//     }
//   };

//   useEffect(() => {
//     fetchRecords();
//   }, []);

//   // 2. Handle Cloudinary Upload
//   const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
//     const file = e.target.files?.[0];
//     if (!file) return;

//     const token = localStorage.getItem("token");
//     const storedUser = localStorage.getItem("user");
//     const parsedUser = storedUser ? JSON.parse(storedUser) : null;
//     const patientId = localStorage.getItem("userId") || parsedUser?.id;

//     const formData = new FormData();
//     formData.append("file", file);
//     formData.append("title", file.name);

//     setUploading(true);
//     try {
//       await axios.post(`http://localhost:8080/api/records/upload/${patientId}`, formData, {
//         headers: { 
//           Authorization: `Bearer ${token}`,
//           "Content-Type": "multipart/form-data" 
//         }
//       });
//       // Refresh list after successful Cloudinary upload
//       fetchRecords();
//     } catch (error) {
//       console.error("Upload failed:", error);
//       alert("Failed to upload report. Please check file size and login status.");
//     } finally {
//       setUploading(false);
//     }
//   };

//   const formatDate = (dateString: string) => {
//     return new Date(dateString).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
//   };

//   return (
//     <DashboardLayout role="patient">
//       <div className="max-w-4xl mx-auto space-y-8">
//         <div>
//           <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
//             <FileText size={28} className="text-accent" />
//             Medical Vault
//           </h1>
//           <p className="text-muted-foreground mt-1">Upload and securely store your lab reports and health documents</p>
//         </div>

//         {/* Upload Zone pointing to Cloudinary backend */}
//         <GlassCard className="p-8" tilt={false}>
//           <input 
//             type="file" 
//             id="file-input" 
//             className="hidden" 
//             onChange={handleFileUpload}
//             accept=".pdf,.png,.jpg,.jpeg"
//           />
//           <label
//             htmlFor="file-input"
//             onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
//             onDragLeave={() => setDragOver(false)}
//             onDrop={(e) => { e.preventDefault(); setDragOver(false); }}
//             className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 cursor-pointer block ${
//               dragOver ? "border-accent bg-accent/5 scale-[1.01]" : "border-border/50 hover:bg-foreground/5"
//             }`}
//           >
//             {uploading ? (
//               <Loader2 size={48} className="mx-auto text-accent animate-spin mb-4" />
//             ) : (
//               <Upload size={48} className="mx-auto text-muted-foreground mb-4" />
//             )}
//             <p className="font-display font-bold text-foreground mb-1">
//               {uploading ? "Uploading to Cloudinary..." : "Click or Drag to Upload Report"}
//             </p>
//             <p className="text-xs text-muted-foreground">Supported: PDF, PNG, JPG (Max 10MB)</p>
//           </label>
//         </GlassCard>

//         {/* Dynamic List of Cloudinary-stored files */}
//         <div className="space-y-4">
//           <h2 className="text-sm font-bold uppercase tracking-widest text-muted-foreground px-1">Your Documents</h2>
          
//           {loading ? (
//             <div className="py-10 text-center italic text-muted-foreground">Fetching vault contents...</div>
//           ) : records.length === 0 ? (
//             <div className="glass rounded-2xl p-12 text-center">
//               <AlertCircle size={40} className="mx-auto mb-3 opacity-10" />
//               <p className="text-muted-foreground">Your vault is empty. Upload your first lab report above.</p>
//             </div>
//           ) : (
//             <div className="grid gap-3">
//               {records.map((record, i) => (
//                 <motion.div
//                   key={record.id}
//                   initial={{ opacity: 0, y: 10 }}
//                   animate={{ opacity: 1, y: 0 }}
//                   transition={{ delay: i * 0.05 }}
//                   className="glass rounded-2xl p-4 flex items-center justify-between group hover:border-accent/30 transition-colors"
//                 >
//                   <div className="flex items-center gap-4">
//                     <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center text-accent">
//                       <File size={24} />
//                     </div>
//                     <div>
//                       <p className="font-bold text-sm text-foreground">{record.title}</p>
//                       <p className="text-[10px] text-muted-foreground uppercase">{formatDate(record.date)} • {record.fileType?.split('/')[1] || 'Document'}</p>
//                     </div>
//                   </div>

//                   <div className="flex items-center gap-2">
//                     {/* Secure link to Cloudinary */}
//                     <a 
//                       href={record.fileUrl} 
//                       target="_blank" 
//                       rel="noreferrer"
//                       className="p-2.5 glass rounded-xl text-accent hover:bg-accent/10 transition-all"
//                       title="Download/View"
//                     >
//                       <Download size={18} />
//                     </a>
//                     <button className="p-2.5 glass rounded-xl text-destructive hover:bg-destructive/10 transition-all">
//                       <Trash2 size={18} />
//                     </button>
//                   </div>
//                 </motion.div>
//               ))}
//             </div>
//           )}
//         </div>
//       </div>
//     </DashboardLayout>
//   );
// };

// export default MedicalRecords;



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