import { useState } from "react";
import { motion } from "framer-motion";
import { Send, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";

const ContactSection = () => {
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    setTimeout(() => setSubmitted(false), 3000);
  };

  return (
    <section id="contact" className="py-24 md:py-32 relative overflow-hidden">
      <div className="absolute inset-0 mesh-gradient opacity-40" />

      <div className="container mx-auto px-4 md:px-8 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <span className="inline-block text-accent text-sm font-semibold tracking-wider uppercase mb-4">
            Get In Touch
          </span>
          <h2 className="font-display text-3xl sm:text-4xl lg:text-5xl font-bold text-foreground mb-4">
            Contact <span className="text-gradient-accent">Us</span>
          </h2>
          <p className="text-muted-foreground max-w-xl mx-auto text-lg">
            Have questions? We'd love to hear from you.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="max-w-lg mx-auto"
        >
          <form onSubmit={handleSubmit} className="glass rounded-2xl p-8 shadow-float space-y-5">
            <div>
              <label className="text-sm font-medium text-foreground mb-2 block">Name</label>
              <Input
                placeholder="Your name"
                required
                className="bg-secondary/50 border-border focus:border-accent focus:ring-accent/30 rounded-xl h-12 transition-all"
              />
            </div>
            <div>
              <label className="text-sm font-medium text-foreground mb-2 block">Email</label>
              <Input
                type="email"
                placeholder="you@example.com"
                required
                className="bg-secondary/50 border-border focus:border-accent focus:ring-accent/30 rounded-xl h-12 transition-all"
              />
            </div>
            <div>
              <label className="text-sm font-medium text-foreground mb-2 block">Message</label>
              <Textarea
                placeholder="How can we help?"
                required
                rows={4}
                className="bg-secondary/50 border-border focus:border-accent focus:ring-accent/30 rounded-xl transition-all resize-none"
              />
            </div>
            <Button
              type="submit"
              disabled={submitted}
              className="w-full bg-gradient-to-r from-primary to-accent text-accent-foreground font-semibold h-12 rounded-xl shadow-glow-accent hover:scale-[1.02] transition-all duration-300"
            >
              {submitted ? (
                <motion.span
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  className="flex items-center gap-2"
                >
                  <CheckCircle size={18} />
                  Sent!
                </motion.span>
              ) : (
                <span className="flex items-center gap-2">
                  <Send size={18} />
                  Send Message
                </span>
              )}
            </Button>
          </form>
        </motion.div>
      </div>
    </section>
  );
};

export default ContactSection;
