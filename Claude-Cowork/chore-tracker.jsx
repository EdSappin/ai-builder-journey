import { useState } from "react";

const CHORES = [
  { name: "Make bed", icon: "🛏️" },
  { name: "Brush teeth", icon: "🪥" },
  { name: "Clean room", icon: "🧹" },
  { name: "Do homework", icon: "📚" },
  { name: "Set the table", icon: "🍽️" },
  { name: "Feed pet", icon: "🐾" },
  { name: "Put away toys", icon: "🧸" },
  { name: "Help with dishes", icon: "🫧" },
];

const STARS_FOR_ALLOWANCE = 8;

const defaultKids = [
  { name: "Kid 1", stars: 0, completedChores: [], allowanceEarned: 0 },
  { name: "Kid 2", stars: 0, completedChores: [], allowanceEarned: 0 },
];

function StarDisplay({ count, max }) {
  return (
    <div style={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
      {Array.from({ length: max }).map((_, i) => (
        <span
          key={i}
          style={{
            fontSize: 22,
            filter: i < count ? "none" : "grayscale(1) opacity(0.25)",
            transition: "all 0.3s ease",
            transform: i < count ? "scale(1.1)" : "scale(0.9)",
          }}
        >
          ⭐
        </span>
      ))}
    </div>
  );
}

function ProgressBar({ stars }) {
  const pct = Math.min((stars / STARS_FOR_ALLOWANCE) * 100, 100);
  return (
    <div
      style={{
        width: "100%",
        height: 14,
        background: "#e8e0f0",
        borderRadius: 7,
        overflow: "hidden",
        position: "relative",
      }}
    >
      <div
        style={{
          height: "100%",
          width: `${pct}%`,
          background: "linear-gradient(90deg, #f6c344, #f59e0b)",
          borderRadius: 7,
          transition: "width 0.5s ease",
        }}
      />
      <span
        style={{
          position: "absolute",
          right: 6,
          top: -1,
          fontSize: 10,
          fontWeight: 700,
          color: "#7c3aed",
        }}
      >
        {stars}/{STARS_FOR_ALLOWANCE}
      </span>
    </div>
  );
}

export default function ChoreTracker() {
  const [kids, setKids] = useState(defaultKids);
  const [editingName, setEditingName] = useState(null);
  const [nameInput, setNameInput] = useState("");
  const [celebration, setCelebration] = useState(null);
  const [allowanceAmount, setAllowanceAmount] = useState("5.00");

  const toggleChore = (kidIdx, choreName) => {
    setKids((prev) =>
      prev.map((kid, i) => {
        if (i !== kidIdx) return kid;
        const already = kid.completedChores.includes(choreName);
        let newCompleted, newStars;
        if (already) {
          newCompleted = kid.completedChores.filter((c) => c !== choreName);
          newStars = kid.stars - 1;
        } else {
          newCompleted = [...kid.completedChores, choreName];
          newStars = kid.stars + 1;
        }
        if (!already && newStars >= STARS_FOR_ALLOWANCE) {
          setCelebration(kid.name);
          setTimeout(() => setCelebration(null), 3000);
        }
        return { ...kid, completedChores: newCompleted, stars: newStars };
      })
    );
  };

  const collectAllowance = (kidIdx) => {
    setKids((prev) =>
      prev.map((kid, i) => {
        if (i !== kidIdx || kid.stars < STARS_FOR_ALLOWANCE) return kid;
        return {
          ...kid,
          stars: kid.stars - STARS_FOR_ALLOWANCE,
          completedChores: [],
          allowanceEarned: kid.allowanceEarned + parseFloat(allowanceAmount || 0),
        };
      })
    );
  };

  const addKid = () => {
    setKids((prev) => [
      ...prev,
      {
        name: `Kid ${prev.length + 1}`,
        stars: 0,
        completedChores: [],
        allowanceEarned: 0,
      },
    ]);
  };

  const removeKid = (idx) => {
    if (kids.length <= 1) return;
    setKids((prev) => prev.filter((_, i) => i !== idx));
  };

  const startEditName = (idx) => {
    setEditingName(idx);
    setNameInput(kids[idx].name);
  };

  const saveName = (idx) => {
    if (nameInput.trim()) {
      setKids((prev) =>
        prev.map((kid, i) =>
          i === idx ? { ...kid, name: nameInput.trim() } : kid
        )
      );
    }
    setEditingName(null);
  };

  const resetAll = () => {
    setKids((prev) =>
      prev.map((kid) => ({ ...kid, stars: 0, completedChores: [] }))
    );
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "linear-gradient(135deg, #ede9fe 0%, #fdf4ff 50%, #fef3c7 100%)",
        padding: "24px 12px",
        fontFamily: "'Segoe UI', system-ui, -apple-system, sans-serif",
      }}
    >
      {celebration && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0,0,0,0.4)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 999,
            animation: "fadeIn 0.3s ease",
          }}
          onClick={() => setCelebration(null)}
        >
          <div
            style={{
              background: "white",
              borderRadius: 24,
              padding: "40px 48px",
              textAlign: "center",
              boxShadow: "0 20px 60px rgba(124,58,237,0.3)",
              maxWidth: 360,
            }}
          >
            <div style={{ fontSize: 56, marginBottom: 12 }}>🎉</div>
            <h2
              style={{
                fontSize: 24,
                color: "#7c3aed",
                margin: "0 0 8px",
                fontWeight: 800,
              }}
            >
              Amazing job, {celebration}!
            </h2>
            <p style={{ color: "#6b7280", fontSize: 15, margin: 0 }}>
              You earned {STARS_FOR_ALLOWANCE} stars! Time to collect your allowance!
            </p>
          </div>
        </div>
      )}

      <div style={{ maxWidth: 720, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <h1
            style={{
              fontSize: 32,
              fontWeight: 800,
              color: "#7c3aed",
              margin: "0 0 4px",
            }}
          >
            ⭐ Chore Tracker ⭐
          </h1>
          <p style={{ color: "#9ca3af", fontSize: 14, margin: 0 }}>
            Complete chores to earn stars — collect allowance at{" "}
            {STARS_FOR_ALLOWANCE} stars!
          </p>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 10,
            marginBottom: 24,
            flexWrap: "wrap",
          }}
        >
          <label
            style={{ fontSize: 13, color: "#6b7280", fontWeight: 600 }}
          >
            Allowance amount: $
          </label>
          <input
            type="number"
            value={allowanceAmount}
            onChange={(e) => setAllowanceAmount(e.target.value)}
            style={{
              width: 70,
              padding: "6px 10px",
              borderRadius: 8,
              border: "2px solid #e5e7eb",
              fontSize: 14,
              fontWeight: 600,
              textAlign: "center",
              outline: "none",
            }}
            min="0"
            step="0.50"
          />
          <button
            onClick={addKid}
            style={{
              padding: "6px 16px",
              background: "#7c3aed",
              color: "white",
              border: "none",
              borderRadius: 8,
              fontSize: 13,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            + Add Kid
          </button>
          <button
            onClick={resetAll}
            style={{
              padding: "6px 16px",
              background: "#e5e7eb",
              color: "#6b7280",
              border: "none",
              borderRadius: 8,
              fontSize: 13,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Reset All
          </button>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: kids.length === 1 ? "1fr" : "repeat(auto-fit, minmax(300px, 1fr))",
            gap: 20,
          }}
        >
          {kids.map((kid, kidIdx) => (
            <div
              key={kidIdx}
              style={{
                background: "white",
                borderRadius: 20,
                padding: 24,
                boxShadow: "0 4px 24px rgba(124,58,237,0.08)",
                border: kid.stars >= STARS_FOR_ALLOWANCE
                  ? "3px solid #f59e0b"
                  : "3px solid transparent",
                transition: "border 0.3s ease",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: 12,
                }}
              >
                {editingName === kidIdx ? (
                  <div style={{ display: "flex", gap: 6 }}>
                    <input
                      value={nameInput}
                      onChange={(e) => setNameInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && saveName(kidIdx)}
                      autoFocus
                      style={{
                        fontSize: 18,
                        fontWeight: 700,
                        border: "2px solid #7c3aed",
                        borderRadius: 8,
                        padding: "2px 8px",
                        outline: "none",
                        width: 120,
                      }}
                    />
                    <button
                      onClick={() => saveName(kidIdx)}
                      style={{
                        background: "#7c3aed",
                        color: "white",
                        border: "none",
                        borderRadius: 6,
                        padding: "2px 10px",
                        cursor: "pointer",
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      Save
                    </button>
                  </div>
                ) : (
                  <h2
                    onClick={() => startEditName(kidIdx)}
                    style={{
                      fontSize: 20,
                      fontWeight: 800,
                      color: "#7c3aed",
                      margin: 0,
                      cursor: "pointer",
                      borderBottom: "2px dashed transparent",
                    }}
                    title="Click to rename"
                  >
                    {kid.name}
                  </h2>
                )}
                {kids.length > 1 && (
                  <button
                    onClick={() => removeKid(kidIdx)}
                    style={{
                      background: "none",
                      border: "none",
                      color: "#d1d5db",
                      fontSize: 18,
                      cursor: "pointer",
                      padding: "0 4px",
                    }}
                    title="Remove"
                  >
                    ✕
                  </button>
                )}
              </div>

              <StarDisplay count={kid.stars} max={STARS_FOR_ALLOWANCE} />
              <div style={{ margin: "8px 0 16px" }}>
                <ProgressBar stars={kid.stars} />
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: 8,
                  marginBottom: 16,
                }}
              >
                {CHORES.map((chore) => {
                  const done = kid.completedChores.includes(chore.name);
                  return (
                    <button
                      key={chore.name}
                      onClick={() => toggleChore(kidIdx, chore.name)}
                      style={{
                        padding: "10px 8px",
                        borderRadius: 12,
                        border: done
                          ? "2px solid #7c3aed"
                          : "2px solid #e5e7eb",
                        background: done
                          ? "linear-gradient(135deg, #ede9fe, #f5f3ff)"
                          : "#fafafa",
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 13,
                        fontWeight: done ? 700 : 500,
                        color: done ? "#7c3aed" : "#6b7280",
                        transition: "all 0.2s ease",
                        textAlign: "left",
                      }}
                    >
                      <span style={{ fontSize: 18 }}>{chore.icon}</span>
                      <span style={{ flex: 1 }}>{chore.name}</span>
                      {done && (
                        <span style={{ fontSize: 14, color: "#7c3aed" }}>✓</span>
                      )}
                    </button>
                  );
                })}
              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "12px 16px",
                  background: kid.stars >= STARS_FOR_ALLOWANCE
                    ? "linear-gradient(135deg, #fef3c7, #fde68a)"
                    : "#f9fafb",
                  borderRadius: 12,
                }}
              >
                <div>
                  <div
                    style={{ fontSize: 11, color: "#9ca3af", fontWeight: 600 }}
                  >
                    TOTAL EARNED
                  </div>
                  <div
                    style={{
                      fontSize: 20,
                      fontWeight: 800,
                      color: "#059669",
                    }}
                  >
                    ${kid.allowanceEarned.toFixed(2)}
                  </div>
                </div>
                <button
                  onClick={() => collectAllowance(kidIdx)}
                  disabled={kid.stars < STARS_FOR_ALLOWANCE}
                  style={{
                    padding: "10px 20px",
                    borderRadius: 12,
                    border: "none",
                    background:
                      kid.stars >= STARS_FOR_ALLOWANCE
                        ? "linear-gradient(135deg, #7c3aed, #a855f7)"
                        : "#e5e7eb",
                    color:
                      kid.stars >= STARS_FOR_ALLOWANCE ? "white" : "#9ca3af",
                    fontSize: 14,
                    fontWeight: 700,
                    cursor:
                      kid.stars >= STARS_FOR_ALLOWANCE
                        ? "pointer"
                        : "not-allowed",
                    transition: "all 0.2s ease",
                    boxShadow:
                      kid.stars >= STARS_FOR_ALLOWANCE
                        ? "0 4px 12px rgba(124,58,237,0.3)"
                        : "none",
                  }}
                >
                  💰 Collect ${allowanceAmount}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
