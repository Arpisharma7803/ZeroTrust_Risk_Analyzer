import { useState, useEffect, useRef, useCallback } from "react";

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const BASE_URL = "http://127.0.0.1:8000";
const AUTO_REFRESH_INTERVAL = 30000;

// ─── MITRE ATT&CK TAGS ────────────────────────────────────────────────────────
const MITRE = {
  "Pass-the-Hash":       { id: "T1550.002" },
  "Token Relay":         { id: "T1134"     },
  "Credential Stuffing": { id: "T1110.004" },
  "ARP Spoofing":        { id: "T1557.002" },
  "Port Scanning":       { id: "T1046"     },
  "Unknown":             { id: "T1000"     },
};

// ─── MOCK DATA ────────────────────────────────────────────────────────────────
const MOCK = {
  networkGraph: {
    nodes: [
      { id: "DC-01",   type: "server",   risk: 88 },
      { id: "DB-02",   type: "database", risk: 72 },
      { id: "WEB-03",  type: "server",   risk: 45 },
      { id: "PC-04",   type: "endpoint", risk: 91 },
      { id: "PC-05",   type: "endpoint", risk: 33 },
      { id: "FW-01",   type: "firewall", risk: 20 },
      { id: "PRNT-01", type: "endpoint", risk: 58 },
      { id: "SRV-07",  type: "server",   risk: 65 },
    ],
    edges: [
      { source: "FW-01",   target: "WEB-03" },
      { source: "WEB-03",  target: "DC-01"  },
      { source: "DC-01",   target: "DB-02"  },
      { source: "PC-04",   target: "DC-01"  },
      { source: "PC-05",   target: "WEB-03" },
      { source: "PRNT-01", target: "DC-01"  },
      { source: "SRV-07",  target: "DB-02"  },
      { source: "PC-04",   target: "DB-02"  },
    ],
  },
  lateralMovement: {
    paths: [
      { path: ["PC-04", "DC-01", "DB-02"],    risk: 94, method: "Pass-the-Hash"      },
      { path: ["PC-04", "DB-02"],             risk: 81, method: "Credential Stuffing" },
      { path: ["PRNT-01", "DC-01", "DB-02"],  risk: 76, method: "Token Relay"         },
    ],
  },
  riskAnalysis: {
    nodes: [
      { id: "PC-04",   score: 91, factors: ["Unusual login times", "High outbound traffic"] },
      { id: "DC-01",   score: 88, factors: ["Multiple failed auths", "Lateral conn spike"]  },
      { id: "DB-02",   score: 72, factors: ["Unauthorized query attempts"]                   },
      { id: "SRV-07",  score: 65, factors: ["Port scan detected"]                            },
      { id: "PRNT-01", score: 58, factors: ["ARP spoofing attempt"]                          },
      { id: "WEB-03",  score: 45, factors: ["Outdated TLS version"]                          },
      { id: "PC-05",   score: 33, factors: ["Normal baseline activity"]                      },
      { id: "FW-01",   score: 20, factors: ["Up-to-date, low traffic"]                       },
    ],
  },
};

// ─── API ──────────────────────────────────────────────────────────────────────
async function fetchAPI(endpoint) {
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`);
    if (!res.ok) throw new Error("Network error");
    const data = await res.json();
    if (endpoint === "/network-graph") {
      return {
        nodes: (data.nodes || []).map(n =>
          typeof n === "string" ? { id: n, type: "endpoint", risk: 50 } : n
        ),
        edges: (data.edges || []).map(e =>
          Array.isArray(e) ? { source: e[0], target: e[1] } : e
        ),
      };
    }
    if (endpoint === "/lateral-movement") {
      return {
        paths: (data.paths || []).map(p => ({
          path:   Array.isArray(p) ? p : p.path || [],
          risk:   p.risk   || 50,
          method: p.method || "Unknown",
        })),
      };
    }
    if (endpoint === "/risk-analysis") {
      return {
        nodes: (data.nodes || []).map(n =>
          typeof n === "string" ? { id: n, score: 50, factors: ["Detected"] } : n
        ),
      };
    }
    return data;
  } catch {
    const map = {
      "/network-graph":    MOCK.networkGraph,
      "/lateral-movement": MOCK.lateralMovement,
      "/risk-analysis":    MOCK.riskAnalysis,
    };
    return new Promise(r => setTimeout(() => r(map[endpoint]), 600));
  }
}

// ─── UTILITIES ────────────────────────────────────────────────────────────────
const riskColor = s => s >= 80 ? "#ff3b5c" : s >= 60 ? "#ff8c00" : s >= 40 ? "#f0c000" : "#00e0a0";
const riskLabel = s => s >= 80 ? "CRITICAL"  : s >= 60 ? "HIGH"    : s >= 40 ? "MEDIUM"  : "LOW";

// ─── EXPORT CSV ───────────────────────────────────────────────────────────────
function exportCSV(riskData) {
  if (!riskData) return;
  const rows = [["Node ID", "Risk Score", "Level", "Factors"]];
  riskData.nodes.forEach(n => {
    rows.push([n.id, n.score, riskLabel(n.score), (n.factors || []).join(" | ")]);
  });
  const csv  = rows.map(r => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url;
  a.download = `zerotrust_risk_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── FEATURE 1: LOGIN PAGE ────────────────────────────────────────────────────
function LoginPage({ onLogin }) {
  const [user,    setUser]    = useState("");
  const [pass,    setPass]    = useState("");
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = () => {
    if (!user || !pass) { setError("Please enter credentials"); return; }
    setLoading(true);
    setTimeout(() => {
      if (user === "admin" && pass === "admin123") {
        onLogin(user);
      } else {
        setError("Invalid credentials — try admin / admin123");
        setLoading(false);
      }
    }, 800);
  };

  return (
    <div style={{
      minHeight: "100vh", background: "#04090f",
      display: "flex", alignItems: "center", justifyContent: "center",
      backgroundImage: "radial-gradient(ellipse at 20% 20%, rgba(0,224,160,0.06) 0%, transparent 50%), radial-gradient(ellipse at 80% 80%, rgba(255,60,92,0.06) 0%, transparent 50%)",
    }}>
      <div style={{
        background: "rgba(255,255,255,0.025)", border: "1px solid rgba(0,224,160,0.2)",
        borderRadius: 16, padding: "48px 40px", width: 360,
        boxShadow: "0 0 40px rgba(0,224,160,0.08)",
      }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 12, margin: "0 auto 16px",
            background: "linear-gradient(135deg, rgba(0,224,160,0.2), rgba(0,224,160,0.05))",
            border: "1px solid rgba(0,224,160,0.3)",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26,
          }}>⬡</div>
          <div style={{ fontFamily: "'Courier New', monospace", fontSize: 20, fontWeight: "bold", color: "#fff", letterSpacing: "0.08em" }}>
            ZERO TRUST
          </div>
          <div style={{ fontFamily: "monospace", fontSize: 11, color: "#00e0a0", letterSpacing: "0.2em", marginTop: 2 }}>
            ANALYZER
          </div>
          <div style={{ fontFamily: "monospace", fontSize: 9, color: "#334", marginTop: 6, letterSpacing: "0.12em" }}>
            ENTERPRISE SECURITY DASHBOARD
          </div>
        </div>

        {[["USERNAME", user, setUser, "text", "admin"],
          ["PASSWORD", pass, setPass, "password", "••••••••"]].map(([label, val, setter, type, ph]) => (
          <div key={label} style={{ marginBottom: 14 }}>
            <div style={{ fontFamily: "monospace", fontSize: 9, color: "#556", letterSpacing: "0.15em", marginBottom: 6 }}>
              {label}
            </div>
            <input
              type={type} value={val}
              onChange={e => setter(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleLogin()}
              placeholder={ph}
              style={{
                width: "100%", background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8,
                padding: "10px 14px", color: "#dde", fontFamily: "monospace",
                fontSize: 13, outline: "none", boxSizing: "border-box",
              }}
            />
          </div>
        ))}

        {error && (
          <div style={{ fontFamily: "monospace", fontSize: 10, color: "#ff3b5c", marginBottom: 12, textAlign: "center" }}>
            {error}
          </div>
        )}

        <button onClick={handleLogin} style={{
          width: "100%", padding: 12, marginTop: 8,
          background: "rgba(0,224,160,0.15)", border: "1px solid rgba(0,224,160,0.4)",
          borderRadius: 8, color: "#00e0a0", fontFamily: "monospace",
          fontSize: 12, fontWeight: "bold", cursor: "pointer", letterSpacing: "0.1em",
        }}>
          {loading ? "VERIFYING..." : "LOGIN →"}
        </button>

        <div style={{ textAlign: "center", marginTop: 20, fontFamily: "monospace", fontSize: 9, color: "#223", letterSpacing: "0.1em" }}>
          NEVER TRUST · ALWAYS VERIFY
        </div>
      </div>
    </div>
  );
}

// ─── NETWORK GRAPH COMPONENT ──────────────────────────────────────────────────
function NetworkGraph({ data, loading }) {
  const canvasRef = useRef(null);
  const animRef   = useRef(null);
  const posRef    = useRef({});
  const velRef    = useRef({});
  const [hovered,  setHovered]  = useState(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!data) return;
    const { nodes, edges } = data;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const W = canvas.width  = canvas.offsetWidth;
    const H = canvas.height = canvas.offsetHeight;

    nodes.forEach(n => {
      if (!posRef.current[n.id]) {
        posRef.current[n.id] = { x: W*0.15 + Math.random()*W*0.7, y: H*0.15 + Math.random()*H*0.7 };
        velRef.current[n.id] = { x: 0, y: 0 };
      }
    });

    const draw = () => {
      const ctx = canvas.getContext("2d");
      ctx.clearRect(0, 0, W, H);

      nodes.forEach(a => {
        nodes.forEach(b => {
          if (a.id === b.id) return;
          const pa = posRef.current[a.id], pb = posRef.current[b.id];
          const dx = pa.x-pb.x, dy = pa.y-pb.y;
          const dist = Math.sqrt(dx*dx+dy*dy)||1;
          const repel = 3500/(dist*dist);
          velRef.current[a.id].x += (dx/dist)*repel;
          velRef.current[a.id].y += (dy/dist)*repel;
        });
      });

      edges.forEach(({ source, target }) => {
        const pa = posRef.current[source], pb = posRef.current[target];
        if (!pa||!pb) return;
        const dx = pb.x-pa.x, dy = pb.y-pa.y;
        const dist = Math.sqrt(dx*dx+dy*dy)||1;
        const spring = (dist-120)*0.025;
        const fx = (dx/dist)*spring, fy = (dy/dist)*spring;
        velRef.current[source].x += fx; velRef.current[source].y += fy;
        velRef.current[target].x -= fx; velRef.current[target].y -= fy;
      });

      nodes.forEach(n => {
        const p = posRef.current[n.id];
        velRef.current[n.id].x += (W/2-p.x)*0.003;
        velRef.current[n.id].y += (H/2-p.y)*0.003;
        velRef.current[n.id].x *= 0.85;
        velRef.current[n.id].y *= 0.85;
        p.x = Math.max(40, Math.min(W-40, p.x+velRef.current[n.id].x));
        p.y = Math.max(40, Math.min(H-40, p.y+velRef.current[n.id].y));
      });

      edges.forEach(({ source, target }) => {
        const pa = posRef.current[source], pb = posRef.current[target];
        if (!pa||!pb) return;
        const isHot = hovered===source||hovered===target;
        ctx.beginPath(); ctx.moveTo(pa.x,pa.y); ctx.lineTo(pb.x,pb.y);
        ctx.strokeStyle = isHot ? "rgba(0,224,160,0.5)" : "rgba(0,224,160,0.12)";
        ctx.lineWidth = isHot ? 1.5 : 0.8; ctx.stroke();
      });

      nodes.forEach(n => {
        const p = posRef.current[n.id];
        const color = riskColor(n.risk);
        const isHov = hovered===n.id, isSel = selected===n.id;
        const r = isHov||isSel ? 22 : 16;
        const grd = ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,r*2.5);
        grd.addColorStop(0, color+"55"); grd.addColorStop(1,"transparent");
        ctx.beginPath(); ctx.arc(p.x,p.y,r*2.5,0,Math.PI*2);
        ctx.fillStyle = grd; ctx.fill();
        ctx.beginPath(); ctx.arc(p.x,p.y,r,0,Math.PI*2);
        ctx.fillStyle = "#0a1628"; ctx.fill();
        ctx.strokeStyle = color; ctx.lineWidth = isSel?2.5:1.5; ctx.stroke();
        ctx.fillStyle = isHov||isSel?"#fff":"#8ab";
        ctx.font = `${isHov?"bold ":""}10px 'Courier New',monospace`;
        ctx.textAlign = "center";
        ctx.fillText(n.id, p.x, p.y+r+12);
        if (isHov||isSel) {
          ctx.fillStyle = color; ctx.font = "bold 9px 'Courier New',monospace";
          ctx.fillText(`${n.risk}`, p.x, p.y+4);
        }
      });

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [data, hovered, selected]);

  const handleMouseMove = useCallback(e => {
    if (!data) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = e.clientX-rect.left, my = e.clientY-rect.top;
    let found = null;
    data.nodes.forEach(n => {
      const p = posRef.current[n.id];
      if (p && Math.hypot(mx-p.x, my-p.y) < 22) found = n.id;
    });
    setHovered(found);
    canvasRef.current.style.cursor = found ? "pointer" : "default";
  }, [data]);

  const handleClick = useCallback(e => {
    if (!data) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = e.clientX-rect.left, my = e.clientY-rect.top;
    let found = null;
    data.nodes.forEach(n => {
      const p = posRef.current[n.id];
      if (p && Math.hypot(mx-p.x, my-p.y) < 22) found = n.id;
    });
    setSelected(found);
  }, [data]);

  return (
    <div style={{ position: "relative", width: "100%", height: "100%" }}>
      {loading && <LoadingOverlay label="Loading graph..." />}
      <canvas ref={canvasRef} onMouseMove={handleMouseMove} onClick={handleClick}
        style={{ width: "100%", height: "100%", display: "block" }} />
      {selected && data && (() => {
        const node = data.nodes.find(n => n.id === selected);
        return node ? (
          <div style={{
            position: "absolute", bottom: 12, left: 12,
            background: "rgba(10,22,40,0.95)", border: `1px solid ${riskColor(node.risk)}`,
            borderRadius: 8, padding: "10px 14px", minWidth: 160,
          }}>
            <div style={{ color: "#fff", fontFamily: "monospace", fontSize: 13, fontWeight: "bold" }}>{node.id}</div>
            <div style={{ color: "#8ab", fontSize: 11, fontFamily: "monospace", marginTop: 2 }}>{node.type?.toUpperCase()}</div>
            <div style={{ color: riskColor(node.risk), fontSize: 12, fontFamily: "monospace", marginTop: 6 }}>
              Risk: {node.risk} — {riskLabel(node.risk)}
            </div>
            <button onClick={() => setSelected(null)} style={{
              marginTop: 8, background: "transparent", border: "none",
              color: "#556", cursor: "pointer", fontSize: 10, fontFamily: "monospace",
            }}>✕ dismiss</button>
          </div>
        ) : null;
      })()}
    </div>
  );
}

// ─── LATERAL MOVEMENT COMPONENT ───────────────────────────────────────────────
function LateralMovement({ data, loading, searchQuery }) {
  const [expanded, setExpanded] = useState(0);
  if (loading) return <LoadingOverlay label="Analyzing paths..." />;
  if (!data)   return null;

  const filtered = data.paths.filter(item =>
    !searchQuery ||
    item.path.some(p => p.toLowerCase().includes(searchQuery.toLowerCase())) ||
    item.method?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {filtered.length === 0 && (
        <div style={{ color: "#334", fontFamily: "monospace", fontSize: 11, textAlign: "center", padding: 20 }}>
          No paths match search
        </div>
      )}
      {filtered.map((item, i) => {
        const isOpen = expanded === i;
        const c      = riskColor(item.risk);
        const mitre  = MITRE[item.method] || MITRE["Unknown"];
        return (
          <div key={i} onClick={() => setExpanded(isOpen ? -1 : i)} style={{
            background: isOpen ? "rgba(255,60,92,0.06)" : "rgba(255,255,255,0.02)",
            border: `1px solid ${isOpen ? c : "rgba(255,255,255,0.07)"}`,
            borderRadius: 8, padding: "12px 16px", cursor: "pointer", transition: "all 0.2s",
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                {item.path.map((node, j) => (
                  <span key={j} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{
                      fontFamily: "monospace", fontSize: 12,
                      color: j===0 ? "#ff8c00" : j===item.path.length-1 ? "#ff3b5c" : "#aac",
                      background: "rgba(255,255,255,0.05)", borderRadius: 4,
                      padding: "2px 8px", border: "1px solid rgba(255,255,255,0.08)",
                    }}>{node}</span>
                    {j < item.path.length-1 && <span style={{ color: c, fontSize: 14 }}>→</span>}
                  </span>
                ))}
              </div>
              <RiskBadge score={item.risk} />
            </div>

            {isOpen && (
              <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid rgba(255,255,255,0.07)" }}>
                <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
                  <div>
                    <div style={{ color: "#556", fontSize: 10, fontFamily: "monospace", marginBottom: 3 }}>TECHNIQUE</div>
                    <div style={{ color: "#f0c000", fontFamily: "monospace", fontSize: 12 }}>{item.method}</div>
                  </div>
                  <div>
                    <div style={{ color: "#556", fontSize: 10, fontFamily: "monospace", marginBottom: 3 }}>MITRE ATT&CK</div>
                    <div style={{
                      color: "#50a0ff", fontFamily: "monospace", fontSize: 11,
                      background: "rgba(80,160,255,0.08)", border: "1px solid rgba(80,160,255,0.2)",
                      borderRadius: 4, padding: "2px 8px", display: "inline-block",
                    }}>{mitre.id}</div>
                  </div>
                  <div>
                    <div style={{ color: "#556", fontSize: 10, fontFamily: "monospace", marginBottom: 3 }}>HOPS</div>
                    <div style={{ color: "#aac", fontFamily: "monospace", fontSize: 12 }}>{item.path.length-1}</div>
                  </div>
                  <div>
                    <div style={{ color: "#556", fontSize: 10, fontFamily: "monospace", marginBottom: 3 }}>SEVERITY</div>
                    <div style={{ color: c, fontFamily: "monospace", fontSize: 12 }}>{riskLabel(item.risk)}</div>
                  </div>
                </div>
                <div style={{
                  marginTop: 10, padding: "8px 12px",
                  background: "rgba(255,60,92,0.06)", borderRadius: 6,
                  fontFamily: "monospace", fontSize: 11, color: "#8ab",
                }}>
                  ⚠ Recommended: Isolate <span style={{ color: "#ff8c00" }}>{item.path[0]}</span> and reset credentials on all path nodes.
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── RISK PANEL COMPONENT ─────────────────────────────────────────────────────
function RiskPanel({ data, loading, searchQuery, filterLevel }) {
  if (loading) return <LoadingOverlay label="Calculating risk..." />;
  if (!data)   return null;

  let sorted = [...data.nodes].sort((a, b) => b.score - a.score);
  if (searchQuery)        sorted = sorted.filter(n => n.id.toLowerCase().includes(searchQuery.toLowerCase()));
  if (filterLevel !== "ALL") sorted = sorted.filter(n => riskLabel(n.score) === filterLevel);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {sorted.length === 0 && (
        <div style={{ color: "#334", fontFamily: "monospace", fontSize: 11, textAlign: "center", padding: 20 }}>
          No nodes match filter
        </div>
      )}
      {sorted.map((n, i) => {
        const c = riskColor(n.score);
        return (
          <div key={n.id} style={{
            background: "rgba(255,255,255,0.02)", borderRadius: 8,
            padding: "10px 14px", border: "1px solid rgba(255,255,255,0.06)",
            transition: "border-color 0.2s",
          }}
            onMouseEnter={e => e.currentTarget.style.borderColor = c+"44"}
            onMouseLeave={e => e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)"}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ color: "#334", fontFamily: "monospace", fontSize: 12, minWidth: 20 }}>#{i+1}</span>
                <span style={{ color: "#dde", fontFamily: "monospace", fontSize: 13, fontWeight: "bold" }}>{n.id}</span>
              </div>
              <RiskBadge score={n.score} />
            </div>
            <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 4, overflow: "hidden" }}>
              <div style={{
                height: "100%", width: `${n.score}%`, borderRadius: 4,
                background: `linear-gradient(90deg, ${c}88, ${c})`,
                transition: "width 0.8s cubic-bezier(0.16,1,0.3,1)",
                boxShadow: `0 0 8px ${c}66`,
              }} />
            </div>
            {n.factors && (
              <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 4 }}>
                {n.factors.map((f, j) => (
                  <span key={j} style={{
                    fontSize: 9, fontFamily: "monospace", color: "#778",
                    background: "rgba(255,255,255,0.04)", borderRadius: 3,
                    padding: "2px 6px", border: "1px solid rgba(255,255,255,0.06)",
                  }}>{f}</span>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── FEATURE 2: ALERT BANNER ──────────────────────────────────────────────────
function AlertBanner({ riskData }) {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed || !riskData) return null;
  const critical = riskData.nodes.filter(n => n.score >= 80);
  if (critical.length === 0) return null;

  return (
    <div style={{
      background: "rgba(255,60,92,0.08)", border: "1px solid rgba(255,60,92,0.3)",
      borderRadius: 8, padding: "10px 16px",
      display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ff3b5c", animation: "pulse 1s infinite" }} />
        <span style={{ fontFamily: "monospace", fontSize: 11, color: "#ff3b5c", fontWeight: "bold" }}>CRITICAL ALERT</span>
        <span style={{ fontFamily: "monospace", fontSize: 11, color: "#8ab" }}>
          {critical.length} device{critical.length > 1 ? "s" : ""} need immediate isolation:
          {" "}{critical.map(n => n.id).join(", ")}
        </span>
      </div>
      <button onClick={() => setDismissed(true)} style={{
        background: "transparent", border: "1px solid rgba(255,60,92,0.3)",
        color: "#ff3b5c", borderRadius: 4, padding: "2px 10px",
        cursor: "pointer", fontFamily: "monospace", fontSize: 10,
      }}>DISMISS</button>
    </div>
  );
}

// ─── FEATURE 6: SUMMARY CARD ──────────────────────────────────────────────────
function SummaryCard({ riskData, movementData, graphData }) {
  if (!riskData || !movementData || !graphData) return null;
  const critical = riskData.nodes.filter(n => n.score >= 80).length;
  const paths    = movementData.paths.length;
  const total    = riskData.nodes.length;
  const avgScore = Math.round(riskData.nodes.reduce((a, n) => a + n.score, 0) / (total || 1));
  const health   = Math.max(0, 100 - avgScore);

  return (
    <div style={{
      background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 10, padding: "12px 16px",
      display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap",
    }}>
      <div style={{ fontFamily: "monospace", fontSize: 10, color: "#445", letterSpacing: "0.1em", minWidth: 100 }}>
        THREAT SUMMARY
      </div>
      <div style={{ display: "flex", gap: 16, flex: 1, flexWrap: "wrap" }}>
        {critical > 0 && (
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "#ff3b5c" }}>
            🔴 {critical} device{critical > 1 ? "s" : ""} need immediate isolation
          </span>
        )}
        <span style={{ fontFamily: "monospace", fontSize: 11, color: "#ff8c00" }}>
          🟠 {paths} attack path{paths !== 1 ? "s" : ""} detected
        </span>
        <span style={{ fontFamily: "monospace", fontSize: 11, color: health > 60 ? "#00e0a0" : "#f0c000" }}>
          {health > 60 ? "🟢" : "🟡"} Network health: {health}/100
        </span>
      </div>
    </div>
  );
}

// ─── SHARED COMPONENTS ────────────────────────────────────────────────────────
function RiskBadge({ score }) {
  const c = riskColor(score);
  return (
    <span style={{
      background: c+"18", border: `1px solid ${c}55`, color: c,
      fontFamily: "monospace", fontSize: 10, padding: "2px 8px",
      borderRadius: 4, fontWeight: "bold", letterSpacing: "0.05em",
    }}>
      {score} {riskLabel(score)}
    </span>
  );
}

function LoadingOverlay({ label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", flexDirection: "column", gap: 14 }}>
      <div style={{
        width: 36, height: 36, border: "2px solid rgba(0,224,160,0.15)",
        borderTop: "2px solid #00e0a0", borderRadius: "50%",
        animation: "spin 0.8s linear infinite",
      }} />
      <div style={{ color: "#336", fontFamily: "monospace", fontSize: 11 }}>{label}</div>
    </div>
  );
}

function Panel({ title, subtitle, icon, children, style, extra }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 12, display: "flex", flexDirection: "column", overflow: "hidden", ...style,
    }}>
      <div style={{
        padding: "14px 20px 12px", borderBottom: "1px solid rgba(255,255,255,0.05)",
        display: "flex", alignItems: "center", gap: 12, background: "rgba(0,0,0,0.15)", flexWrap: "wrap",
      }}>
        <span style={{ fontSize: 18 }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ color: "#dde", fontFamily: "'Courier New',monospace", fontSize: 13, fontWeight: "bold", letterSpacing: "0.08em" }}>{title}</div>
          {subtitle && <div style={{ color: "#445", fontFamily: "monospace", fontSize: 10, marginTop: 1 }}>{subtitle}</div>}
        </div>
        {extra}
        <div style={{ display: "flex", gap: 6 }}>
          {["#ff3b5c","#f0c000","#00e0a0"].map((c,i) => (
            <div key={i} style={{ width: 7, height: 7, borderRadius: "50%", background: c, opacity: 0.6 }} />
          ))}
        </div>
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>{children}</div>
    </div>
  );
}

function StatCard({ label, value, sub, color }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 10, padding: "14px 18px", flex: 1,
    }}>
      <div style={{ color: "#446", fontFamily: "monospace", fontSize: 9, letterSpacing: "0.12em", marginBottom: 6 }}>{label}</div>
      <div style={{ color: color||"#00e0a0", fontFamily: "'Courier New',monospace", fontSize: 28, fontWeight: "bold", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ color: "#445", fontFamily: "monospace", fontSize: 10, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function SearchBar({ value, onChange, placeholder }) {
  return (
    <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder||"Search..."}
      style={{
        background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 6, padding: "4px 10px", color: "#aac",
        fontFamily: "monospace", fontSize: 10, outline: "none", width: 130,
      }}
    />
  );
}

// ─── MAIN APP ──────────────────────────────────────────────────────────────────
export default function App() {
  const [loggedIn,  setLoggedIn]  = useState(false);
  const [username,  setUsername]  = useState("");
  const [graphData,    setGraphData]    = useState(null);
  const [movementData, setMovementData] = useState(null);
  const [riskData,     setRiskData]     = useState(null);
  const [loading, setLoading] = useState({ graph: true, movement: true, risk: true });
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [countdown,   setCountdown]   = useState(30);
  const [searchRisk,     setSearchRisk]     = useState("");
  const [searchMovement, setSearchMovement] = useState("");
  const [filterLevel,    setFilterLevel]    = useState("ALL");
  const [theme,          setTheme]          = useState("dark");

  const loadAll = useCallback(async () => {
    setLoading({ graph: true, movement: true, risk: true });
    const [g, m, r] = await Promise.all([
      fetchAPI("/network-graph"),
      fetchAPI("/lateral-movement"),
      fetchAPI("/risk-analysis"),
    ]);
    setGraphData(g); setMovementData(m); setRiskData(r);
    setLoading({ graph: false, movement: false, risk: false });
    setLastRefresh(new Date());
    setCountdown(30);
  }, []);

  // FEATURE 1: Auto refresh every 30 seconds
  useEffect(() => {
    if (!loggedIn) return;
    loadAll();
    const interval = setInterval(loadAll, AUTO_REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [loadAll, loggedIn]);

  // Countdown timer
  useEffect(() => {
    if (!loggedIn) return;
    const timer = setInterval(() => setCountdown(c => c <= 1 ? 30 : c-1), 1000);
    return () => clearInterval(timer);
  }, [loggedIn]);

  const criticalCount = riskData?.nodes.filter(n => n.score >= 80).length ?? 0;
  const highCount     = riskData?.nodes.filter(n => n.score >= 60 && n.score < 80).length ?? 0;
  const pathCount     = movementData?.paths.length ?? 0;
  const nodeCount     = graphData?.nodes.length ?? 0;

  // FEATURE 7: Login gate
  if (!loggedIn) {
    return <LoginPage onLogin={user => { setLoggedIn(true); setUsername(user); }} />;
  }

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,224,160,0.2); border-radius: 4px; }
        @keyframes spin   { to { transform: rotate(360deg); } }
        @keyframes pulse  { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        input::placeholder { color: #334; }
      `}</style>

      <div style={{
        minHeight: "100vh",
        background: theme === "dark" ? "#060e1c" : "#eef2f7",
        backgroundImage: theme === "dark" ? "radial-gradient(ellipse at 20% 20%, rgba(0,224,160,0.04) 0%, transparent 50%), radial-gradient(ellipse at 80% 80%, rgba(255,60,92,0.04) 0%, transparent 50%)" : "none",
        color: theme === "dark" ? "#ccd" : "#1a2332",
        fontFamily: "'Courier New',monospace",
        padding: "20px 24px", display: "flex", flexDirection: "column", gap: 12,
        animation: "fadeIn 0.4s ease", transition: "background 0.3s",
      }}>

        {/* HEADER */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 8,
              background: "linear-gradient(135deg,#00e0a033,#00e0a011)",
              border: "1px solid rgba(0,224,160,0.3)",
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18,
            }}>⬡</div>
            <div>
              <h1 style={{ fontSize: 18, color: theme==="dark"?"#dde":"#1a2332", letterSpacing: "0.05em", fontWeight: "normal" }}>
                ZERO TRUST <span style={{ color: "#00e0a0" }}>ANALYZER</span>
              </h1>
              <div style={{ fontSize: 9, color: "#446", letterSpacing: "0.15em" }}>ENTERPRISE LATERAL MOVEMENT & RISK DETECTION</div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            {/* User */}
            <span style={{ fontFamily: "monospace", fontSize: 10, color: "#445" }}>👤 {username.toUpperCase()}</span>

            {/* Countdown */}
            <div style={{
              fontFamily: "monospace", fontSize: 10, color: "#334",
              background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)",
              borderRadius: 6, padding: "4px 10px",
            }}>↺ {countdown}s</div>

            {/* Last refresh */}
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 9, color: "#446", letterSpacing: "0.1em" }}>LAST REFRESH</div>
              <div style={{ fontSize: 11, color: "#556" }}>{lastRefresh.toLocaleTimeString()}</div>
            </div>

            {/* Live */}
            <div style={{
              display: "flex", alignItems: "center", gap: 6,
              background: "rgba(0,224,160,0.06)", border: "1px solid rgba(0,224,160,0.2)",
              borderRadius: 6, padding: "4px 10px",
            }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#00e0a0", animation: "pulse 2s infinite" }} />
              <span style={{ fontSize: 10, color: "#00e0a0" }}>LIVE</span>
            </div>

            {/* FEATURE 8: Theme toggle */}
            <button onClick={() => setTheme(t => t==="dark"?"light":"dark")} style={{
              background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
              color: "#aac", borderRadius: 6, padding: "6px 12px",
              cursor: "pointer", fontFamily: "monospace", fontSize: 10,
            }}>{theme==="dark" ? "☀ LIGHT" : "🌙 DARK"}</button>

            {/* FEATURE 4: Export CSV */}
            <button onClick={() => exportCSV(riskData)} style={{
              background: "rgba(80,160,255,0.08)", border: "1px solid rgba(80,160,255,0.25)",
              color: "#50a0ff", borderRadius: 6, padding: "6px 14px",
              cursor: "pointer", fontFamily: "monospace", fontSize: 11,
            }}>⬇ EXPORT CSV</button>

            {/* Refresh */}
            <button onClick={loadAll} style={{
              background: "rgba(0,224,160,0.08)", border: "1px solid rgba(0,224,160,0.25)",
              color: "#00e0a0", borderRadius: 6, padding: "6px 14px",
              cursor: "pointer", fontFamily: "monospace", fontSize: 11,
            }}>↺ REFRESH</button>

            {/* Logout */}
            <button onClick={() => setLoggedIn(false)} style={{
              background: "rgba(255,60,92,0.08)", border: "1px solid rgba(255,60,92,0.25)",
              color: "#ff3b5c", borderRadius: 6, padding: "6px 14px",
              cursor: "pointer", fontFamily: "monospace", fontSize: 11,
            }}>LOGOUT</button>
          </div>
        </div>

        {/* FEATURE 2: Alert Banner */}
        <AlertBanner riskData={riskData} />

        {/* FEATURE 6: Summary Card */}
        <SummaryCard riskData={riskData} movementData={movementData} graphData={graphData} />

        {/* Stat Cards */}
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <StatCard label="MONITORED NODES" value={nodeCount||"—"}     sub="devices in graph"        color="#00e0a0" />
          <StatCard label="ATTACK PATHS"    value={pathCount||"—"}     sub="lateral movement routes" color="#f0c000" />
          <StatCard label="CRITICAL RISK"   value={criticalCount||"—"} sub="score ≥ 80"              color="#ff3b5c" />
          <StatCard label="HIGH RISK"       value={highCount||"—"}     sub="score 60–79"             color="#ff8c00" />
        </div>

        {/* Main Panels */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gridTemplateRows: "420px 400px", gap: 14 }}>

          {/* Network Graph */}
          <Panel title="NETWORK TOPOLOGY" subtitle="live force-directed graph · click node for details" icon="◈" style={{ gridColumn: "1 / 3" }}>
            <NetworkGraph data={graphData} loading={loading.graph} />
          </Panel>

          {/* FEATURE 5: Lateral Movement with search + MITRE tags */}
          <Panel
            title="LATERAL MOVEMENT"
            subtitle="MITRE ATT&CK tagged attack paths"
            icon="⟶"
            extra={<SearchBar value={searchMovement} onChange={setSearchMovement} placeholder="Search paths..." />}
          >
            <LateralMovement data={movementData} loading={loading.movement} searchQuery={searchMovement} />
          </Panel>

          {/* FEATURE 3: Risk Panel with search + filter */}
          <Panel
            title="RISK ANALYSIS"
            subtitle="node threat scores · sorted by severity"
            icon="▲"
            extra={
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <SearchBar value={searchRisk} onChange={setSearchRisk} placeholder="Search nodes..." />
                <select value={filterLevel} onChange={e => setFilterLevel(e.target.value)} style={{
                  background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 6, padding: "4px 8px", color: "#aac",
                  fontFamily: "monospace", fontSize: 10, outline: "none",
                }}>
                  {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(l => (
                    <option key={l} value={l} style={{ background: "#0a1628" }}>{l}</option>
                  ))}
                </select>
              </div>
            }
          >
            <RiskPanel data={riskData} loading={loading.risk} searchQuery={searchRisk} filterLevel={filterLevel} />
          </Panel>
        </div>

        {/* Footer */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: 4, flexWrap: "wrap", gap: 8 }}>
          <div style={{ fontSize: 9, color: "#334", letterSpacing: "0.1em" }}>
            ZERO TRUST MODEL — CONTINUOUS VERIFICATION — NEVER TRUST, ALWAYS VERIFY
          </div>
          <div style={{ fontSize: 9, color: "#334" }}>
            <span style={{ color: "#ff3b5c" }}>● CRITICAL</span>
            <span style={{ color: "#ff8c00", marginLeft: 10 }}>● HIGH</span>
            <span style={{ color: "#f0c000", marginLeft: 10 }}>● MEDIUM</span>
            <span style={{ color: "#00e0a0", marginLeft: 10 }}>● LOW</span>
          </div>
        </div>

      </div>
    </>
  );
}