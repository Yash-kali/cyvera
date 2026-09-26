import React, { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { sendChatMessageApi, getChatHistoryApi, ChatMessage } from '../../api/chat';
import {
  X,
  Send,
  Sparkles,
  Shield,
  Code,
  DollarSign,
  Layers,
  Bot,
  User
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const FloatingChatPanel: React.FC = () => {
  const location = useLocation();

  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  // Derive active context from route location
  const getRouteContext = () => {
    const path = location.pathname;
    if (path.startsWith('/scans/')) {
      return { route: path, scope: 'Scan Details', target_url: 'https://staging-api.autopentest.ai' };
    } else if (path === '/scans/new') {
      return { route: path, scope: 'New Scan' };
    } else if (path === '/findings') {
      return { route: path, scope: 'Findings Triage' };
    } else if (path === '/analytics') {
      return { route: path, scope: 'Risk Analytics' };
    }
    return { route: path, scope: 'AutoPentest Security Platform' };
  };

  const currentContext = getRouteContext();

  const fetchHistory = async () => {
    try {
      const history = await getChatHistoryApi();
      if (history && history.length > 0) {
        setMessages(history);
      } else {
        setMessages([
          {
            id: 0,
            user_id: 0,
            session_id: 'default',
            sender: 'assistant',
            message: 'Hello Operator! How can I assist with vulnerability remediation or technical code analysis?',
            created_at: new Date().toISOString(),
          },
        ]);
      }
    } catch (err) {
      console.warn('Failed to load chat history:', err);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  // Close panel when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        // Optional auto-minimize on outside click
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSend = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || loading) return;

    const userTempMsg: ChatMessage = {
      id: Date.now(),
      user_id: 1,
      session_id: 'default',
      sender: 'user',
      message: text,
      context: currentContext,
      created_at: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userTempMsg]);
    setInputMessage('');
    setLoading(true);

    try {
      const res = await sendChatMessageApi(text, currentContext);
      const assistantMsg: ChatMessage = {
        id: Date.now() + 1,
        user_id: 1,
        session_id: 'default',
        sender: 'assistant',
        message: res.reply,
        context: currentContext,
        created_at: res.created_at || new Date().toISOString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      console.error('Copilot send message error:', err);
      const errorMsg: ChatMessage = {
        id: Date.now() + 1,
        user_id: 1,
        session_id: 'default',
        sender: 'assistant',
        message: '⚠️ Service connection timeout. Please check backend status.',
        created_at: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const quickPrompts = [
    { label: 'Explain finding', icon: Shield },
    { label: 'Remediation code', icon: Code },
    { label: 'Business impact', icon: DollarSign },
    { label: 'OWASP mapping', icon: Layers },
  ];

  return (
    <div className="fixed bottom-5 right-5 z-50 font-sans" ref={panelRef}>
      {/* Subtle Floating Action Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="p-3.5 rounded-full bg-[#0b101d] border border-white/20 text-cyber-cyan hover:border-cyber-cyan transition-colors shadow-2xl flex items-center space-x-2 cursor-pointer group"
          title="Open AI Security Copilot"
        >
          <Bot className="w-5 h-5 text-cyber-cyan group-hover:scale-105 transition-transform" />
          <span className="hidden sm:inline-block font-mono text-xs font-semibold text-slate-200 pr-1">
            AI Assistant
          </span>
        </button>
      )}

      {/* Expandable Chat Window */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 15, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 15, scale: 0.96 }}
            transition={{ duration: 0.2 }}
            className="w-[92vw] sm:w-[400px] h-[520px] glass-card rounded-2xl border border-white/15 shadow-2xl flex flex-col overflow-hidden bg-[#070b14]/95 backdrop-blur-md"
          >
            {/* Header */}
            <div className="p-3.5 bg-white/[0.03] border-b border-white/10 flex items-center justify-between font-mono">
              <div className="flex items-center space-x-2">
                <div className="p-1.5 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan">
                  <Bot className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 font-display text-xs">AI Security Copilot</h3>
                  <div className="text-[10px] text-slate-400 font-sans">Scope: {currentContext.scope}</div>
                </div>
              </div>

              <button
                onClick={() => setIsOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                title="Minimize Copilot"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Chat Messages */}
            <div className="flex-1 p-3.5 overflow-y-auto space-y-3 font-sans text-xs">
              {messages.map((m) => {
                const isUser = m.sender === 'user';
                return (
                  <div
                    key={m.id}
                    className={`flex items-start space-x-2 ${isUser ? 'flex-row-reverse space-x-reverse' : ''}`}
                  >
                    <div
                      className={`p-1.5 rounded-lg border flex-shrink-0 ${
                        isUser
                          ? 'bg-cyber-cyan/10 border-cyber-cyan/30 text-cyber-cyan'
                          : 'bg-white/5 border-white/10 text-slate-300'
                      }`}
                    >
                      {isUser ? <User className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
                    </div>

                    <div
                      className={`p-3 rounded-xl max-w-[84%] text-xs leading-relaxed ${
                        isUser
                          ? 'bg-cyber-cyan/10 border border-cyber-cyan/30 text-slate-100 rounded-tr-none'
                          : 'bg-white/[0.04] border border-white/10 text-slate-200 rounded-tl-none font-mono whitespace-pre-wrap'
                      }`}
                    >
                      {m.message}
                    </div>
                  </div>
                );
              })}

              {loading && (
                <div className="flex items-center space-x-2 text-slate-400 font-mono text-xs p-2">
                  <div className="w-3 h-3 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin" />
                  <span>Analyzing security query...</span>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Quick Prompts */}
            <div className="px-3 py-1.5 bg-black/20 border-t border-white/5 flex gap-1.5 overflow-x-auto font-mono text-[10px]">
              {quickPrompts.map((qp) => {
                const Icon = qp.icon;
                return (
                  <button
                    key={qp.label}
                    onClick={() => handleSend(qp.label)}
                    disabled={loading}
                    className="px-2 py-1 rounded-lg bg-white/5 border border-white/10 hover:border-white/20 text-slate-300 hover:text-white flex items-center space-x-1 whitespace-nowrap transition-colors disabled:opacity-50"
                  >
                    <Icon className="w-3 h-3 text-slate-400" />
                    <span>{qp.label}</span>
                  </button>
                );
              })}
            </div>

            {/* Input Bar */}
            <div className="p-2.5 bg-white/[0.02] border-t border-white/10 flex items-center space-x-2">
              <input
                type="text"
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                placeholder="Ask Security Copilot..."
                className="flex-1 px-3 py-2 rounded-xl bg-black/40 border border-white/10 focus:border-white/20 text-xs text-slate-100 placeholder-slate-500 outline-none font-mono"
              />
              <button
                onClick={() => handleSend()}
                disabled={loading || !inputMessage.trim()}
                className="p-2 rounded-xl bg-cyber-cyan text-slate-950 font-bold hover:bg-[#00d8e6] transition-colors disabled:opacity-40"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>

          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
