import { motion } from "framer-motion";
import { Star, Quote } from "lucide-react";

const testimonials = [
  {
    name: "Dr. Sarah Chen",
    role: "Cardiologist",
    text: "Medibot has transformed how I manage patient consultations. The AI triage is remarkably accurate and saves critical time.",
    rating: 5,
  },
  {
    name: "Rajiv Patel",
    role: "Patient",
    text: "I was able to get a preliminary diagnosis at 2 AM and book a specialist appointment the same morning. Life-changing.",
    rating: 5,
  },
  {
    name: "Emily Rodriguez",
    role: "Nurse Practitioner",
    text: "The medical records system is seamless. Sharing patient history with specialists takes seconds, not days.",
    rating: 5,
  },
  {
    name: "James Wright",
    role: "Patient",
    text: "Finding a nearby hospital during an emergency was instant. The real-time navigation probably saved my mother's life.",
    rating: 5,
  },
];

const TestimonialsSection = () => {
  return (
    <section id="testimonials" className="py-24 md:py-32 relative">
      <div className="container mx-auto px-4 md:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <span className="inline-block text-accent text-sm font-semibold tracking-wider uppercase mb-4">
            Testimonials
          </span>
          <h2 className="font-display text-3xl sm:text-4xl lg:text-5xl font-bold text-foreground mb-4">
            Trusted by <span className="text-gradient-accent">Thousands</span>
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
            Real stories from patients and healthcare professionals who trust Medibot.
          </p>
        </motion.div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {testimonials.map((t, i) => (
            <motion.div
              key={t.name}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-30px" }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              className="glass rounded-2xl p-6 shadow-float hover:shadow-float-lg hover:scale-[1.02] transition-all duration-500 group cursor-default"
            >
              <Quote size={24} className="text-accent/30 mb-4 group-hover:text-accent/60 transition-colors" />
              <p className="text-foreground text-sm leading-relaxed mb-6">{t.text}</p>
              <div className="flex gap-1 mb-3">
                {Array.from({ length: t.rating }).map((_, j) => (
                  <Star key={j} size={14} className="fill-warning text-warning" />
                ))}
              </div>
              <div>
                <div className="font-semibold text-foreground text-sm">{t.name}</div>
                <div className="text-muted-foreground text-xs">{t.role}</div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default TestimonialsSection;
