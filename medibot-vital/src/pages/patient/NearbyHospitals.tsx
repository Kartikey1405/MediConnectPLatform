import { motion } from "framer-motion";
import { MapPin, Star, Navigation, Phone, Clock } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import GlassCard from "@/components/GlassCard";

const hospitals = [
  { id: 1, name: "City General Hospital", distance: "1.2 km", rating: 4.8, address: "123 Medical Avenue, Downtown", phone: "+1 234 567 890", hours: "24/7 Emergency" },
  { id: 2, name: "St. Mary's Medical Center", distance: "2.5 km", rating: 4.6, address: "456 Health Street, Midtown", phone: "+1 234 567 891", hours: "24/7 Emergency" },
  { id: 3, name: "Unity Healthcare Complex", distance: "3.8 km", rating: 4.5, address: "789 Wellness Blvd, Uptown", phone: "+1 234 567 892", hours: "6 AM - 11 PM" },
  { id: 4, name: "Green Valley Clinic", distance: "4.1 km", rating: 4.3, address: "321 Care Lane, Suburbs", phone: "+1 234 567 893", hours: "8 AM - 8 PM" },
  { id: 5, name: "Metro Emergency Hospital", distance: "5.2 km", rating: 4.7, address: "654 Rescue Road, Eastside", phone: "+1 234 567 894", hours: "24/7 Emergency" },
];

const NearbyHospitals = () => {
  return (
    <DashboardLayout role="patient">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h1 className="font-display text-3xl font-bold text-foreground flex items-center gap-3">
            <MapPin size={28} className="text-accent" />
            Nearby Hospitals
          </h1>
          <p className="text-muted-foreground mt-1">Find healthcare facilities near you</p>
        </div>

        {/* Map Placeholder */}
        <GlassCard className="p-1 overflow-hidden" tilt={false}>
          <div className="w-full h-64 md:h-80 rounded-2xl bg-gradient-to-br from-primary/5 to-accent/5 flex items-center justify-center relative overflow-hidden">
            <div className="absolute inset-0 mesh-gradient opacity-50" />
            <div className="text-center z-10">
              <MapPin size={48} className="text-accent mx-auto mb-3 animate-float" />
              <p className="font-display font-bold text-foreground">Interactive Map</p>
              <p className="text-sm text-muted-foreground">Enable location to see nearby hospitals</p>
              <button className="mt-3 glass rounded-xl px-4 py-2 text-sm font-medium text-accent hover:shadow-glow-accent transition-all">
                Enable Location
              </button>
            </div>
          </div>
        </GlassCard>

        {/* Hospital Cards */}
        <div className="grid md:grid-cols-2 gap-4">
          {hospitals.map((h, i) => (
            <GlassCard key={h.id} delay={i * 0.08} className="p-5">
              <div className="flex items-start justify-between mb-3">
                <h3 className="font-display font-bold text-foreground text-sm">{h.name}</h3>
                <div className="flex items-center gap-1 text-warning text-xs font-semibold">
                  <Star size={12} fill="currentColor" /> {h.rating}
                </div>
              </div>
              <p className="text-xs text-muted-foreground mb-3">{h.address}</p>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground mb-3">
                <span className="flex items-center gap-1"><Navigation size={12} className="text-accent" />{h.distance}</span>
                <span className="flex items-center gap-1"><Phone size={12} />{h.phone}</span>
                <span className="flex items-center gap-1"><Clock size={12} />{h.hours}</span>
              </div>
              <button className="w-full glass rounded-xl py-2 text-sm font-medium text-accent hover:shadow-glow-accent hover:scale-[1.02] transition-all">
                Get Directions
              </button>
            </GlassCard>
          ))}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default NearbyHospitals;
