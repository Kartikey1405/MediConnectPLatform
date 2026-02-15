import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  User, Clock, MessageSquare, Calendar, BookOpen, MapPin, LogOut, Menu, X,
  Stethoscope, LayoutDashboard, Video, Settings, Users, Building2
} from "lucide-react";
import { cn } from "@/lib/utils";

type Role = "patient" | "doctor" | "admin";

const patientLinks = [
  { label: "Profile", href: "/patient/dashboard", icon: User },
  { label: "Timeline", href: "/patient/timeline", icon: Clock },
  { label: "Triage Chat", href: "/patient/triage", icon: MessageSquare },
  { label: "Consultations", href: "/patient/consultations", icon: Calendar },
  { label: "Book Appointment", href: "/patient/book", icon: BookOpen },
  { label: "Medical Records", href: "/patient/records", icon: Stethoscope },
  { label: "Nearby Hospitals", href: "/patient/hospitals", icon: MapPin },
];

const doctorLinks = [
  { label: "Dashboard", href: "/doctor/dashboard", icon: LayoutDashboard },
  { label: "Appointments", href: "/doctor/appointments", icon: Calendar },
  { label: "Consultations", href: "/doctor/consultation", icon: Video },
];

const adminLinks = [
  { label: "Dashboard", href: "/admin/dashboard", icon: LayoutDashboard },
  { label: "Doctors", href: "/admin/dashboard", icon: Users },
  { label: "Hospitals", href: "/admin/dashboard", icon: Building2 },
  { label: "Settings", href: "/admin/dashboard", icon: Settings },
];

const DashboardLayout = ({ children, role = "patient" }: { children: React.ReactNode; role?: Role }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  const links = role === "patient" ? patientLinks : role === "doctor" ? doctorLinks : adminLinks;
  const roleName = role === "patient" ? "Patient" : role === "doctor" ? "Doctor" : "Admin";

  return (
    <div className="min-h-screen bg-background flex">
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex flex-col w-64 min-h-screen glass-dark fixed left-0 top-0 z-40">
        <div className="p-6 border-b border-sidebar-border/30">
          <Link to="/" className="flex items-center gap-2 group">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-glow-accent transition-transform duration-300 group-hover:scale-110">
              <span className="text-accent-foreground font-bold text-sm">M</span>
            </div>
            <span className="font-display text-xl font-bold text-primary-foreground tracking-tight">
              Medi<span className="text-accent">bot</span>
            </span>
          </Link>
          <p className="text-xs text-primary-foreground/50 mt-2">{roleName} Portal</p>
        </div>

        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
          {links.map((link) => {
            const active = location.pathname === link.href;
            return (
              <Link
                key={link.label}
                to={link.href}
                className={cn(
                  "flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-300",
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground shadow-glow-accent"
                    : "text-primary-foreground/70 hover:text-primary-foreground hover:bg-sidebar-accent/50"
                )}
              >
                <link.icon size={18} />
                <span>{link.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-sidebar-border/30">
          <button
            onClick={() => navigate("/login")}
            className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium text-primary-foreground/70 hover:text-destructive hover:bg-destructive/10 transition-all duration-300 w-full"
          >
            <LogOut size={18} />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      {/* Mobile Header */}
      <div className="md:hidden fixed top-0 left-0 right-0 z-50 glass py-3 px-4 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center">
            <span className="text-accent-foreground font-bold text-xs">M</span>
          </div>
          <span className="font-display text-lg font-bold text-foreground">Medibot</span>
        </Link>
        <button onClick={() => setSidebarOpen(!sidebarOpen)} className="p-2 rounded-xl hover:bg-secondary transition-colors">
          {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSidebarOpen(false)}
              className="md:hidden fixed inset-0 bg-foreground/20 backdrop-blur-sm z-40"
            />
            <motion.div
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: "spring", damping: 25, stiffness: 300 }}
              className="md:hidden fixed left-0 top-0 bottom-0 w-72 glass-dark z-50 flex flex-col"
            >
              <div className="p-6 border-b border-sidebar-border/30">
                <span className="font-display text-xl font-bold text-primary-foreground">Medibot</span>
                <p className="text-xs text-primary-foreground/50 mt-1">{roleName} Portal</p>
              </div>
              <nav className="flex-1 p-4 space-y-1">
                {links.map((link) => {
                  const active = location.pathname === link.href;
                  return (
                    <Link
                      key={link.label}
                      to={link.href}
                      onClick={() => setSidebarOpen(false)}
                      className={cn(
                        "flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-300",
                        active
                          ? "bg-sidebar-accent text-sidebar-accent-foreground"
                          : "text-primary-foreground/70 hover:text-primary-foreground hover:bg-sidebar-accent/50"
                      )}
                    >
                      <link.icon size={18} />
                      <span>{link.label}</span>
                    </Link>
                  );
                })}
              </nav>
              <div className="p-4 border-t border-sidebar-border/30">
                <button
                  onClick={() => navigate("/login")}
                  className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium text-primary-foreground/70 hover:text-destructive w-full"
                >
                  <LogOut size={18} />
                  <span>Logout</span>
                </button>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <main className="flex-1 md:ml-64 min-h-screen">
        <div className="pt-16 md:pt-0">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="p-4 md:p-8"
          >
            {children}
          </motion.div>
        </div>
      </main>
    </div>
  );
};

export default DashboardLayout;
