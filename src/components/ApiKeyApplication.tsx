import React, { useState } from 'react';
import { Bot, Mail, Users, Info, Send, CheckCircle } from 'lucide-react';

export default function ApiKeyApplication() {
  const [formData, setFormData] = useState({
    botName: '',
    botId: '',
    serverCount: '',
    developerEmail: '',
    purpose: ''
  });
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res = await fetch('/api/v1/public/api-key/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          serverCount: parseInt(formData.serverCount)
        })
      });

      if (res.ok) {
        setSuccess(true);
      } else {
        const data = await res.json();
        setError(data.error || 'Failed to submit application');
      }
    } catch (err) {
      setError('Connection error');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="border-2 border-[#141414] p-12 text-center space-y-6 bg-white animate-in fade-in zoom-in duration-300">
        <div className="flex justify-center">
          <div className="w-20 h-20 bg-green-100 text-green-600 rounded-full flex items-center justify-center animate-bounce">
            <CheckCircle className="w-10 h-10" />
          </div>
        </div>
        <h2 className="text-4xl font-bold uppercase tracking-tighter">Application Received</h2>
        <p className="font-mono text-sm opacity-60 max-w-md mx-auto">
          Our team will review your bot and send the API key to your email if approved. This process typically takes 24-48 hours.
        </p>
        <button 
          onClick={() => setSuccess(false)}
          className="border-2 border-[#141414] px-8 py-3 font-mono text-xs uppercase tracking-widest hover:bg-[#141414] hover:text-[#E4E3E0] transition-all"
        >
          Submit Another
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto border-2 border-[#141414] bg-white p-12 space-y-12">
      <header className="space-y-4 border-b border-[#141414] pb-8">
        <h2 className="text-4xl font-bold uppercase tracking-tighter">Apply for API Key</h2>
        <p className="font-mono text-sm opacity-60">
          Connect your Discord bot to the Be Safe global network.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-8">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-2">
            <label className="font-mono text-[10px] uppercase font-bold opacity-50 flex items-center gap-2">
              <Bot className="w-3 h-3" /> Bot Name
            </label>
            <input 
              required
              type="text" 
              placeholder="e.g. SafetyBot"
              value={formData.botName}
              onChange={(e) => setFormData({ ...formData, botName: e.target.value })}
              className="w-full bg-transparent border-2 border-[#141414] p-3 font-mono text-sm focus:outline-none focus:bg-[#141414] focus:text-[#E4E3E0] transition-colors"
            />
          </div>
          <div className="space-y-2">
            <label className="font-mono text-[10px] uppercase font-bold opacity-50 flex items-center gap-2">
              <Bot className="w-3 h-3" /> Bot App ID
            </label>
            <input 
              required
              type="text" 
              placeholder="123456789012345678"
              value={formData.botId}
              onChange={(e) => setFormData({ ...formData, botId: e.target.value })}
              className="w-full bg-transparent border-2 border-[#141414] p-3 font-mono text-sm focus:outline-none focus:bg-[#141414] focus:text-[#E4E3E0] transition-colors"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-2">
            <label className="font-mono text-[10px] uppercase font-bold opacity-50 flex items-center gap-2">
              <Users className="w-3 h-3" /> Server Count
            </label>
            <input 
              required
              type="number" 
              placeholder="Total servers using your bot"
              value={formData.serverCount}
              onChange={(e) => setFormData({ ...formData, serverCount: e.target.value })}
              className="w-full bg-transparent border-2 border-[#141414] p-3 font-mono text-sm focus:outline-none focus:bg-[#141414] focus:text-[#E4E3E0] transition-colors"
            />
          </div>
          <div className="space-y-2">
            <label className="font-mono text-[10px] uppercase font-bold opacity-50 flex items-center gap-2">
              <Mail className="w-3 h-3" /> Developer Email
            </label>
            <input 
              required
              type="email" 
              placeholder="your@email.com"
              value={formData.developerEmail}
              onChange={(e) => setFormData({ ...formData, developerEmail: e.target.value })}
              className="w-full bg-transparent border-2 border-[#141414] p-3 font-mono text-sm focus:outline-none focus:bg-[#141414] focus:text-[#E4E3E0] transition-colors"
            />
          </div>
        </div>

        <div className="space-y-2">
          <label className="font-mono text-[10px] uppercase font-bold opacity-50 flex items-center gap-2">
            <Info className="w-3 h-3" /> Integration Purpose
          </label>
          <textarea 
            required
            rows={4}
            placeholder="Explain how your bot will use our safety data..."
            value={formData.purpose}
            onChange={(e) => setFormData({ ...formData, purpose: e.target.value })}
            className="w-full bg-transparent border-2 border-[#141414] p-3 font-mono text-sm focus:outline-none focus:bg-[#141414] focus:text-[#E4E3E0] transition-colors resize-none"
          />
        </div>

        {error && <p className="font-mono text-xs text-red-600 uppercase font-bold">{error}</p>}

        <button 
          type="submit"
          disabled={loading}
          className="w-full bg-[#141414] text-[#E4E3E0] py-4 font-mono text-xs uppercase tracking-[0.2em] font-bold hover:bg-[#141414]/90 transition-all flex items-center justify-center gap-3 disabled:opacity-50"
        >
          {loading ? 'Submitting...' : (
            <>
              <Send className="w-4 h-4" />
              Submit Application
            </>
          )}
        </button>
      </form>
    </div>
  );
}
