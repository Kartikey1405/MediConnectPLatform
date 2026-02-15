import { motion, useMotionValue, useTransform } from "framer-motion";
import { ArrowRight, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import medicalOrb from "@/assets/medical-orb.png";

const HeroSection = () => {
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  const orbRotateX = useTransform(mouseY, [-300, 300], [8, -8]);
  const orbRotateY = useTransform(mouseX, [-300, 300], [-8, 8]);

  const handleMouseMove = (e: React.MouseEvent) => {
    const rect = e.currentTarget.getBoundingClientRect();
    mouseX.set(e.clientX - rect.left - rect.width / 2);
    mouseY.set(e.clientY - rect.top - rect.height / 2);
  };

  return (
    <section
      id="home"
      onMouseMove={handleMouseMove}
      className="relative min-h-screen flex items-center overflow-hidden mesh-gradient"
    >
      {/* Ambient animated blobs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-[600px] h-[600px] rounded-full bg-gradient-to-br from-accent/10 to-success/5 blur-3xl animate-breathe" />
        <div className="absolute -bottom-40 -left-40 w-[500px] h-[500px] rounded-full bg-gradient-to-tr from-primary/10 to-accent/5 blur-3xl animate-breathe" style={{ animationDelay: "3s" }} />
      </div>

      <div className="container mx-auto px-4 md:px-8 pt-24 pb-16 relative z-10">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-8 items-center">
          {/* Text Content */}
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, ease: "easeOut" }}
              className="inline-flex items-center gap-2 glass rounded-full px-4 py-2 text-sm font-medium text-foreground"
            >
              <Activity size={16} className="text-accent" />
              <span>AI-Powered Healthcare Platform</span>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.1, ease: "easeOut" }}
              className="font-display text-4xl sm:text-5xl lg:text-6xl xl:text-7xl font-bold leading-[1.1] tracking-tight"
            >
              AI-Powered{" "}
              <span className="text-gradient-primary">Healthcare</span>,{" "}
              <br className="hidden sm:block" />
              When You Need{" "}
              <span className="text-gradient-accent">It Most.</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.2, ease: "easeOut" }}
              className="text-lg sm:text-xl text-muted-foreground max-w-lg leading-relaxed"
            >
              Analyze symptoms, consult verified doctors, and get care from
              anywhere — powered by next-generation AI diagnostics.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.3, ease: "easeOut" }}
              className="flex flex-col sm:flex-row gap-4"
            >
              <Button
                size="lg"
                className="bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold px-8 py-6 text-base shadow-glow-accent hover:shadow-glow-accent hover:scale-[1.03] transition-all duration-300 group"
              >
                Get Started
                <ArrowRight size={18} className="ml-2 transition-transform group-hover:translate-x-1" />
              </Button>
              <Button
                size="lg"
                variant="outline"
                className="font-semibold px-8 py-6 text-base border-border hover:bg-secondary hover:scale-[1.03] transition-all duration-300"
              >
                <Activity size={18} className="mr-2 text-accent" />
                Check Symptoms
              </Button>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.4, ease: "easeOut" }}
              className="flex gap-8 pt-4"
            >
              {[
                { value: "50K+", label: "Patients" },
                { value: "200+", label: "Doctors" },
                { value: "98%", label: "Accuracy" },
              ].map((stat) => (
                <div key={stat.label}>
                  <div className="text-2xl font-bold font-display text-foreground">{stat.value}</div>
                  <div className="text-sm text-muted-foreground">{stat.label}</div>
                </div>
              ))}
            </motion.div>
          </div>

          {/* Orb */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1, delay: 0.3, ease: "easeOut" }}
            style={{ rotateX: orbRotateX, rotateY: orbRotateY }}
            className="relative flex items-center justify-center perspective-1000"
          >
            <div className="relative">
              <img
                src={medicalOrb}
                alt="Medibot AI Orb"
                className="w-[320px] sm:w-[420px] lg:w-[500px] animate-float drop-shadow-2xl"
              />
              {/* Glow ring */}
              <div className="absolute inset-0 rounded-full bg-accent/10 blur-3xl animate-pulse-soft" />
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
