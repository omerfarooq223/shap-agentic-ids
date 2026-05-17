import { Cpu, ChevronDown, Zap, X, Send, MessageSquare } from 'lucide-react';

const ChatWidget = ({
  chatOpen,
  setChatOpen,
  chatFullscreen,
  setChatFullscreen,
  chatMessages,
  chatLoading,
  chatInput,
  setChatInput,
  sendChat,
  chatEndRef
}) => {
  return (
    <div className="chat-fab-wrapper">
      <div className={`chat-popup ${chatOpen ? 'open' : ''} ${chatFullscreen ? 'fullscreen' : ''}`}>
        <div className="chat-overlay-header">
          <div className="chat-overlay-title">
            <Cpu size={16} />
            <span>IDS AI Analyst</span>
            <span className="chat-model-badge">LLaMA-3.3-70B</span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="chat-close-btn" title={chatFullscreen ? 'Minimize' : 'Expand'} onClick={() => setChatFullscreen(f => !f)}>
              {chatFullscreen ? <ChevronDown size={14} /> : <Zap size={14} />}
            </button>
            <button className="chat-close-btn" onClick={() => { setChatOpen(false); setChatFullscreen(false); }}><X size={14} /></button>
          </div>
        </div>
        <div className="chat-messages">
          {chatMessages.map((msg, i) => (
            <div key={i} className={`chat-msg ${msg.role}`}>
              {msg.role === 'assistant' && <div className="chat-avatar-bot"><Cpu size={13} /></div>}
              <div className="chat-bubble">{msg.content}</div>
            </div>
          ))}
          {chatLoading && (
            <div className="chat-msg assistant">
              <div className="chat-avatar-bot"><Cpu size={13} /></div>
              <div className="chat-bubble chat-typing"><span /><span /><span /></div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>
        <div className="chat-input-row">
          <input className="chat-input" placeholder="Ask about threats, MITRE tactics..."
            value={chatInput} onChange={e => setChatInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && sendChat()} />
          <button className="chat-send-btn" onClick={sendChat} disabled={chatLoading}>
            <Send size={14} />
          </button>
        </div>
      </div>
      <button className="chat-fab" onClick={() => setChatOpen(o => !o)} aria-label="AI Analyst">
        <MessageSquare size={18} />
        <span>AI ANALYST</span>
      </button>
    </div>
  );
};

export default ChatWidget;