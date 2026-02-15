import { motion, useMotionValue, useTransform } from "framer-motion";
import { Brain, Video, FolderHeart, MapPin } from "lucide-react";

const services = [
  {
    icon: Brain,
    title: "AI Symptom Analysis",
    description: "Advanced AI-driven diagnostics that analyze your symptoms with medical-grade precision and provide actionable insights.",
  },
  {
    icon: Video,
    title: "Doctor Video Consultation",
    description: "Connect face-to-face with verified specialists from anywhere, with secure HD video and real-time medical records sharing.",
  },
  {
    icon: FolderHeart,
    title: "Medical Records Management",
    description: "Upload, organize, and access your complete health history. Securely stored and instantly shareable with your care team.",
  },
  {
    icon: MapPin,
    title: "Nearby Hospital Finder",
    description: "Locate hospitals, clinics, and emergency services near you with real-time availability and navigation.",
  },
];

const ServiceCard = ({ service, index }: { service: typeof services[0]; index: number }) => {
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  const rotateX = useTransform(mouseY, [-150, 150], [5, -5]);
  const rotateY = useTransform(mouseX, [-150, 150], [-5, 5]);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    mouseX.set(e.clientX - rect.left - rect.width / 2);
    mouseY.set(e.clientY - rect.top - rect.height / 2);
  };

  const handleMouseLeave = () => {
    mouseX.set(0);
    mouseY.set(0);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 40 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{ duration: 0.6, delay: index * 0.1, ease: "easeOut" }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{ rotateX, rotateY, transformStyle: "preserve-3d" }}
      className="group"
    >
      <div className="glass rounded-2xl p-8 h-full shadow-float transition-all duration-500 hover:shadow-float-lg hover:shadow-glow-accent cursor-default">
        <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center mb-6 group-hover:scale-110 group-hover:rotate-6 transition-all duration-500">
          <service.icon size={28} className="text-accent transition-transform duration-500 group-hover:scale-110" />
        </div>
        <h3 className="font-display text-xl font-bold text-foreground mb-3">{service.title}</h3>
        <p className="text-muted-foreground leading-relaxed text-sm">{service.description}</p>
      </div>
    </motion.div>
  );
};

const ServicesSection = () => {
  return (
    <section id="services" className="py-24 md:py-32 relative">
      <div className="container mx-auto px-4 md:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <span className="inline-block text-accent text-sm font-semibold tracking-wider uppercase mb-4">
            Our Services
          </span>
          <h2 className="font-display text-3xl sm:text-4xl lg:text-5xl font-bold text-foreground mb-4">
            Complete Healthcare <span className="text-gradient-accent">Ecosystem</span>
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
            Everything you need for modern healthcare, powered by AI and trusted by thousands.
          </p>
        </motion.div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {services.map((service, i) => (
            <ServiceCard key={service.title} service={service} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
};

export default ServicesSection;
