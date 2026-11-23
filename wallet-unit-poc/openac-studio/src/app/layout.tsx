import type { Metadata } from "next";
import "./globals.css";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SiteNav } from "@/components/SiteNav";

export const metadata: Metadata = {
  title: "OpenAC Studio — Anonymous Credential Integration Designer",
  description:
    "Design, visualize, and analyze anonymous credential flows with interactive module selection, sequence diagrams, and threat modeling.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col">
        <TooltipProvider delayDuration={300}>
          <SiteNav />
          <main className="flex-1">{children}</main>
          <footer className="border-t bg-white py-8 text-xs text-gray-500">
            <div className="max-w-7xl mx-auto px-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <p className="text-gray-400">
                  OpenAC Studio — a checklist-based design tool, not a formal security proof.
                </p>
                <div className="flex flex-wrap gap-x-5 gap-y-1">
                  <a href="https://github.com/ethereum/zkID" target="_blank" rel="noopener noreferrer" className="hover:text-gray-800 transition-colors">
                    OpenAC GitHub
                  </a>
                  <a href="https://github.com/privacy-ethereum/zkspecs/tree/main/specs/5" target="_blank" rel="noopener noreferrer" className="hover:text-gray-800 transition-colors">
                    Forum Implementation Spec
                  </a>
                </div>
              </div>
            </div>
          </footer>
        </TooltipProvider>
      </body>
    </html>
  );
}
