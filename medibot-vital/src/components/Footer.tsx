import { Heart } from "lucide-react";

const Footer = () => {
  return (
    <footer className="relative py-16 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-t from-primary/10 to-transparent" />
      <div className="container mx-auto px-4 md:px-8 relative z-10">
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-10 mb-12">
          {/* Brand */}
          <div className="sm:col-span-2 lg:col-span-1">
            <div className="flex items-center gap-2 mb-4">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center">
                <span className="text-accent-foreground font-bold text-sm">M</span>
              </div>
              <span className="font-display text-xl font-bold text-foreground tracking-tight">
                Medibot
              </span>
            </div>
            <p className="text-muted-foreground text-sm leading-relaxed max-w-xs">
              AI-powered healthcare for everyone. Accessible, trusted, and always available.
            </p>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="font-display font-semibold text-foreground mb-4 text-sm">Platform</h4>
            <ul className="space-y-2">
              {["AI Triage", "Find Doctors", "Book Appointment", "Medical Records"].map((l) => (
                <li key={l}>
                  <a href="#" className="text-muted-foreground text-sm hover:text-accent transition-colors">
                    {l}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="font-display font-semibold text-foreground mb-4 text-sm">Company</h4>
            <ul className="space-y-2">
              {["About Us", "Careers", "Blog", "Press"].map((l) => (
                <li key={l}>
                  <a href="#" className="text-muted-foreground text-sm hover:text-accent transition-colors">
                    {l}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="font-display font-semibold text-foreground mb-4 text-sm">Legal</h4>
            <ul className="space-y-2">
              {["Privacy Policy", "Terms of Service", "HIPAA Compliance", "Cookie Policy"].map((l) => (
                <li key={l}>
                  <a href="#" className="text-muted-foreground text-sm hover:text-accent transition-colors">
                    {l}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="border-t border-border pt-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-muted-foreground text-sm flex items-center gap-1">
            © 2026 Medibot. Made with <Heart size={14} className="text-destructive" /> for better healthcare.
          </p>
          <div className="flex gap-4 text-muted-foreground text-sm">
            <a href="#" className="hover:text-accent transition-colors">Twitter</a>
            <a href="#" className="hover:text-accent transition-colors">LinkedIn</a>
            <a href="#" className="hover:text-accent transition-colors">GitHub</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
