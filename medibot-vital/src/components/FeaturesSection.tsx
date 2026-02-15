import { motion } from "framer-motion";
import { Shield, Zap, Clock, Users, BarChart3, Lock } from "lucide-react";

const features = [
  { icon: Shield, title: "Medical-Grade Security", description: "HIPAA-compliant encryption protects all patient data end-to-end." },
  { icon: Zap, title: "Instant AI Triage", description: "Get preliminary diagnostics in seconds with our Gemini-powered engine." },
  { icon: Clock, title: "24/7 Availability", description: "Access care anytime. Our AI never sleeps, and doctors are always on call." },
  { icon: Users, title: "Verified Specialists", description: "Every doctor is credential-verified and rated by real patients." },
  { icon: BarChart3, title: "Health Analytics", description: "Track your health trends over time with intelligent visual reports." },
  { icon: Lock, title: "Privacy First", description: "Your data is yours. Full control over sharing and access permissions." },
];

const FeaturesSection = () => {
  return (
    <section id="features" className="py-24 md:py-32 relative overflow-hidden">
      {/* Subtle background */}
      <div className="absolute inset-0 mesh-gradient opacity-50" />

      <div className="container mx-auto px-4 md:px-8 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <span className="inline-block text-accent text-sm font-semibold tracking-wider uppercase mb-4">
            Why Medibot
          </span>
          <h2 className="font-display text-3xl sm:text-4xl lg:text-5xl font-bold text-foreground mb-4">
            Built for <span className="text-gradient-primary">Trust</span> &{" "}
            <span className="text-gradient-accent">Speed</span>
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
            Every feature is designed to make healthcare accessible, secure, and intelligent.
          </p>
        </motion.div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-30px" }}
              transition={{ duration: 0.5, delay: i * 0.08 }}
              className="group flex gap-5 p-6 rounded-2xl hover:bg-secondary/50 transition-all duration-300 cursor-default"
            >
              <div className="flex-shrink-0 w-12 h-12 rounded-xl bg-gradient-to-br from-accent/15 to-primary/15 flex items-center justify-center group-hover:scale-110 group-hover:shadow-glow-accent transition-all duration-300">
                <feature.icon size={22} className="text-accent" />
              </div>
              <div>
                <h3 className="font-display text-lg font-bold text-foreground mb-1">{feature.title}</h3>
                <p className="text-muted-foreground text-sm leading-relaxed">{feature.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
