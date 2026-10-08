import { useState, useEffect } from "react";
import {
  LayoutDashboard,
  Target,
  Radar,
  ShieldAlert,
  FileText,
  Bell,
  Settings,
  Users,
  ChevronDown,
  Plus,
  Play,
  ScanSearch,
  CheckCircle,
  AlertTriangle,
  ShieldCheck,
  Clock3,
  Layers3,
  FileSearch,
} from "lucide-react";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  RadarChart,
PolarGrid,
PolarAngleAxis,
PolarRadiusAxis,
Radar as RadarArea,

} from "recharts";

import "./App.css";
import ScansPage from "./ScansPage";


const getSeverityData = (scans) => {
  const findings = scans.flatMap((scan) => scan.findings || []);

  return [
    {
      name: "Critical",
      value: findings.filter((f) => f.severity === "Critical").length,
    },
    {
      name: "High",
      value: findings.filter((f) => f.severity === "High").length,
    },
    {
      name: "Medium",
      value: findings.filter((f) => f.severity === "Medium").length,
    },
    {
      name: "Low",
      value: findings.filter((f) => f.severity === "Low").length,
    },
    {
      name: "Info",
      value: findings.filter((f) => f.severity === "Info").length,
    },
  ];
};

const getSeverityTrend = (scans) => {
  return scans
    .slice(0, 7)
    .reverse()
    .map((scan, index) => {
      const findings = scan.findings || [];

      return {
        name: `Scan ${index + 1}`,
        high: findings.filter(
          (f) => f.severity === "High" || f.severity === "Critical"
        ).length,
        medium: findings.filter((f) => f.severity === "Medium").length,
        low: findings.filter(
          (f) => f.severity === "Low" || f.severity === "Info"
        ).length,
      };
    });
};

function App() {

const [activePage, setActivePage] = useState("dashboard");

const [showScanModal, setShowScanModal] = useState(false);
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStage, setScanStage] = useState("Initializing Scan");
  const [scanJobId, setScanJobId] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [findingSearch, setFindingSearch] = useState("");
  const [findingSeverity, setFindingSeverity] = useState("All");
  const [findingCategory, setFindingCategory] = useState("All");
  const [findingConfidence, setFindingConfidence] = useState("All");
  
  const [users, setUsers] = useState(() => {
  try {
    const savedUsers = localStorage.getItem("vulnhawk_users");
    return savedUsers
      ? JSON.parse(savedUsers)
      : [{
          id: "admin-1",
          name: "Admin",
          email: "admin@vulnhawk.local",
          role: "Admin",
          status: "Active",
        }];
  } catch {
    return [{
      id: "admin-1",
      name: "Admin",
      email: "admin@vulnhawk.local",
      role: "Admin",
      status: "Active",
    }];
  }
});

const [showUserModal, setShowUserModal] = useState(false);
const [userForm, setUserForm] = useState({
  name: "",
  email: "",
  role: "Security Analyst",
});

const [currentUserId, setCurrentUserId] = useState("admin-1");
const [showProfileMenu, setShowProfileMenu] = useState(false);

const currentUser =
  users.find((user) => user.id === currentUserId) || users[0];

const currentRole = currentUser?.role || "Admin";

const permissions = {
  canManageUsers: currentRole === "Admin",
  canManageSettings: currentRole === "Admin",
  canManageTargets:
    currentRole === "Admin" || currentRole === "Security Analyst",
  canRunScans:
    currentRole === "Admin" || currentRole === "Security Analyst",
};





const [recentScans, setRecentScans] = useState(() => {

  const savedScans =
    localStorage.getItem("vulnhawk_recent_scans");

  return savedScans
    ? JSON.parse(savedScans)
    : [];

});

useEffect(() => {

  localStorage.setItem(
    "vulnhawk_recent_scans",
    JSON.stringify(recentScans)
  );

}, [recentScans]);

useEffect(() => {
  localStorage.setItem("vulnhawk_users", JSON.stringify(users));
}, []);

const latestScan = recentScans[0];

const allFindings = recentScans.flatMap(
  (scan) => scan.findings || []
);

const activeTargets = new Set(
  recentScans.map((scan) => scan.target)
).size;

const totalScans = recentScans.length;

const vulnerabilityCount =
  latestScan?.vulnerabilities ?? 0;

const latestScore =
  latestScan?.score ?? 0;

const currentFindings = latestScan?.findings || [];

const highPlusCount =
  currentFindings.filter(
    (finding) =>
      finding.severity === "High" ||
      finding.severity === "Critical"
  ).length;

const filteredFindings = currentFindings.filter((finding) => {
  const search = findingSearch.trim().toLowerCase();

  const matchesSearch =
  !search ||
  (finding.title || "").toLowerCase().includes(search) ||
  (finding.category || "").toLowerCase().includes(search) ||
  (finding.cwe || finding.cwe_id || "").toLowerCase().includes(search) ||
  (finding.endpoint || finding.affected_url || "")
    .toLowerCase()
    .includes(search);

  const matchesSeverity =
    findingSeverity === "All" ||
    (finding.severity || "").toLowerCase() ===
      findingSeverity.toLowerCase();

  const matchesCategory =
    findingCategory === "All" ||
    (finding.category || "").toLowerCase() ===
      findingCategory.toLowerCase();

  const matchesConfidence =
    findingConfidence === "All" ||
    (finding.confidence || "").toLowerCase() ===
      findingConfidence.toLowerCase();

  return (
    matchesSearch &&
    matchesSeverity &&
    matchesCategory &&
    matchesConfidence
  );
});

const findingCategories = [
  "All",
  ...new Set(
    currentFindings
      .map((finding) => finding.category)
      .filter(Boolean)
  ),
];

const findingSeverities = [
  "All",
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
];

const findingConfidences = [
  "All",
  "High",
  "Medium",
  "Low",
];



const currentScanData = latestScan
  ? [latestScan]
  : [];

const severityData = getSeverityData(currentScanData);

const severityTrend = getSeverityTrend(recentScans);

const vulnerabilityData = [
  "Security Headers",
  "Cookies",
  "SSL/TLS",
  "XSS",
  "SQL Injection",
  "Path Traversal",
  "Open Redirect",
  "CSRF",
  "Information Disclosure",
].map((category) => ({
  name: category,
  value: currentFindings.filter(
    (finding) => finding.category === category
  ).length,
}));

  return (

    <div className="app">

      {/* SIDEBAR */}

      <aside className="sidebar">

        <div className="logo">
          <div className="logo-icon">🦅</div>
          <div>
            <h2 style={{ color: "#ffffff", margin: 0 }}>VulnHawk</h2>
            <span style={{ color: "#94a3b8" }}>Security Scanner</span>
          </div>
        </div>


        <nav>

          <a
            className={activePage === "dashboard" ? "active" : ""}
            onClick={() => setActivePage("dashboard")}
          >
            <LayoutDashboard size={18} />
            Dashboard
          </a>

          {permissions.canManageTargets && (
            <div className="nav-section">
              <div className="section-title">
                <Target size={17} />
                Targets
                <ChevronDown size={15} />
              </div>

              <a
                className={activePage === "targets" ? "active" : ""}
                onClick={() => setActivePage("targets")}
              >
                Manage Targets
              </a>

              <a
                className={activePage === "new-target" ? "active" : ""}
                onClick={() => {
                  setActivePage("new-target");
                  setShowScanModal(true);
                }}
              >
                New Target
              </a>
            </div>
          )}

          <a
            className={activePage === "scans" ? "active" : ""}
            onClick={() => setActivePage("scans")}
          >
            <Radar size={18} />
            Scans
          </a>

          <a
            className={activePage === "vulnerabilities" ? "active" : ""}
            onClick={() => setActivePage("vulnerabilities")}
          >
            <ShieldAlert size={18} />
            Vulnerabilities
          </a>

          <a
            className={activePage === "reports" ? "active" : ""}
            onClick={() => setActivePage("reports")}
          >
            <FileText size={18} />
            Reports
          </a>

          <a
            className={activePage === "notifications" ? "active" : ""}
            onClick={() => setActivePage("notifications")}
          >
            <Bell size={18} />
            Notifications
          </a>

          {permissions.canManageUsers && (
            <a
              className={activePage === "users" ? "active" : ""}
              onClick={() => setActivePage("users")}
            >
              <Users size={18} />
              Users
            </a>
          )}

          {permissions.canManageSettings && (
            <a
              className={activePage === "settings" ? "active" : ""}
              onClick={() => setActivePage("settings")}
            >
              <Settings size={18} />
              Settings
            </a>
          )}

        </nav>


        <div className="sidebar-bottom">

          <div className="version">
            VulnHawk v1.0.0
          </div>

        </div>

      </aside>


      {/* MAIN */}

      <main className="main">

{activePage === "scans" ? (

  <ScansPage scans={recentScans} />

) : activePage === "targets" ? (

  <div className="dashboard-content">
    <header className="topbar">
      <div>
        <h1>Manage Targets</h1>
        <p>Targets recorded from VulnHawk security assessments</p>
      </div>
      <button
        className="scan-button"
        onClick={() => {
          setActivePage("new-target");
          setShowScanModal(true);
        }}
      >
        <Plus size={17} />
        Add Target
      </button>
    </header>

    <section className="card" style={{ marginTop: "24px" }}>
      <div className="card-header">
        <div>
          <h3>Target Inventory</h3>
          <p>Unique targets found in scan history</p>
        </div>
        <strong>{activeTargets} targets</strong>
      </div>

      {recentScans.length > 0 ? (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Latest Score</th>
                <th>Findings</th>
                <th>Last Scan</th>
              </tr>
            </thead>
            <tbody>
              {[...new Map(
                recentScans.map((scan) => [scan.target, scan])
              ).values()].map((scan, index) => (
                <tr key={`${scan.target}-${index}`}>
                  <td><strong>{scan.target}</strong></td>
                  <td>{scan.score}/100</td>
                  <td>{scan.vulnerabilities}</td>
                  <td>{scan.date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ padding: "36px", textAlign: "center", color: "#64748b" }}>
          No targets yet. Add your first authorized target to begin.
        </div>
      )}
    </section>
  </div>

) : activePage === "vulnerabilities" ? (

  <div className="dashboard-content">
    <header className="topbar">
      <div>
        <h1>Vulnerabilities</h1>
        <p>Findings collected from recorded security assessments</p>
      </div>
      <button
        className="secondary-button"
        onClick={() => setActivePage("scans")}
      >
        <Radar size={17} />
        View Scans
      </button>
    </header>

    <section className="card" style={{ marginTop: "24px" }}>
      <div className="card-header">
        <div>
          <h3>Security Findings</h3>
          <p>{allFindings.length} findings across {recentScans.length} scans</p>
        </div>
      </div>

      {allFindings.length > 0 ? (
        <div style={{ display: "grid", gap: "10px" }}>
          {allFindings.map((finding, index) => {
            const title =
              typeof finding === "string"
                ? finding
                : finding?.title || finding?.name || finding?.issue || "Security Finding";
            const severity =
              typeof finding === "string"
                ? "Info"
                : finding?.severity || "Info";

            return (
              <div
                key={`${title}-${index}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "16px",
                  padding: "15px 16px",
                  border: "1px solid #e5e7eb",
                  borderRadius: "12px",
                  background: "#fff",
                }}
              >
                <div>
                  <strong>{title}</strong>
                  <div style={{ marginTop: "4px", fontSize: "12px", color: "#64748b" }}>
                    {typeof finding === "object" && finding?.category
                      ? finding.category
                      : "Security"}
                  </div>
                </div>
                <span
                  style={{
                    padding: "6px 10px",
                    borderRadius: "999px",
                    fontSize: "11px",
                    fontWeight: 700,
                    background:
                      severity === "Critical" || severity === "High"
                        ? "#fef2f2"
                        : severity === "Medium"
                        ? "#fff7ed"
                        : "#eff6ff",
                    color:
                      severity === "Critical" || severity === "High"
                        ? "#dc2626"
                        : severity === "Medium"
                        ? "#c2410c"
                        : "#2563eb",
                  }}
                >
                  {severity}
                </span>
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ padding: "36px", textAlign: "center", color: "#64748b" }}>
          No vulnerability findings recorded yet.
        </div>
      )}
    </section>
  </div>

) : activePage === "reports" ? (

  <div className="dashboard-content">
    <header className="topbar">
      <div>
        <h1>Reports</h1>
        <p>Security assessment reports generated by VulnHawk</p>
      </div>
      <button
        className="scan-button"
        onClick={() => setActivePage("scans")}
      >
        <FileText size={17} />
        Open Scan Reports
      </button>
    </header>

    <section className="card" style={{ marginTop: "24px" }}>
      <div className="card-header">
        <div>
          <h3>Generated Reports</h3>
          <p>Open a completed assessment to generate or review its PDF report.</p>
        </div>
      </div>

      {recentScans.length > 0 ? (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Score</th>
                <th>Findings</th>
                <th>Date</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((scan, index) => (
                <tr key={`${scan.target}-${scan.date}-${index}`}>
                  <td><strong>{scan.target}</strong></td>
                  <td>{scan.score}/100</td>
                  <td>{scan.vulnerabilities}</td>
                  <td>{scan.date}</td>
                  <td>
                    <button
                      className="secondary-button"
                      onClick={() => setActivePage("scans")}
                    >
                      View in Scans
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ padding: "36px", textAlign: "center", color: "#64748b" }}>
          No reports available yet.
        </div>
      )}
    </section>
  </div>

) : activePage === "notifications" ? (

  <div className="dashboard-content">
    <header className="topbar">
      <div>
        <h1>Notifications</h1>
        <p>Recent VulnHawk assessment activity</p>
      </div>
    </header>

    <section className="card" style={{ marginTop: "24px" }}>
      <div className="card-header">
        <div>
          <h3>Activity</h3>
          <p>Latest scan events</p>
        </div>
      </div>

      {recentScans.length > 0 ? (
        <div style={{ display: "grid", gap: "10px" }}>
          {recentScans.slice(0, 10).map((scan, index) => (
            <div
              key={`${scan.target}-${scan.date}-${index}`}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "14px",
                padding: "15px",
                borderBottom: index < Math.min(recentScans.length, 10) - 1
                  ? "1px solid #e5e7eb"
                  : "none",
              }}
            >
              <Bell size={18} color="#2563eb" />
              <div>
                <strong>Scan completed</strong>
                <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
                  {scan.target} • {scan.date} • Score {scan.score}/100
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div style={{ padding: "36px", textAlign: "center", color: "#64748b" }}>
          No notifications yet.
        </div>
      )}
    </section>
  </div>

) : activePage === "users" ? (

  permissions.canManageUsers ? (
  <div className="dashboard-content">
  <header className="topbar">
    <div>
      <h1>User Management</h1>
      <p>Manage VulnHawk workspace users and roles</p>
    </div>

    {permissions.canManageUsers && (
      <button
        className="scan-button"
        onClick={() => {
          setUserForm({
            name: "",
            email: "",
            role: "Security Analyst",
          });
          setShowUserModal(true);
        }}
      >
        <Plus size={17} />
        Add User
      </button>
    )}
  </header>

  <section className="card" style={{ marginTop: "24px" }}>
    <div className="card-header">
      <div>
        <h3>Workspace Users</h3>
        <p>{users.length} user{users.length === 1 ? "" : "s"} registered</p>
      </div>
      <span
        style={{
          padding: "7px 11px",
          borderRadius: "999px",
          background: "#eff6ff",
          color: "#2563eb",
          fontSize: "12px",
          fontWeight: 700,
        }}
      >
        Local Workspace
      </span>
    </div>

    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div
                    style={{
                      width: "34px",
                      height: "34px",
                      borderRadius: "50%",
                      background: "#2563eb",
                      color: "#fff",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                    }}
                  >
                    {(user.name || "U").charAt(0).toUpperCase()}
                  </div>
                  <strong>{user.name}</strong>
                </div>
              </td>
              <td>{user.email}</td>
              <td>
                <span
                  style={{
                    padding: "5px 9px",
                    borderRadius: "999px",
                    background: user.role === "Admin" ? "#f3e8ff" : user.role === "Security Analyst" ? "#eff6ff" : "#f1f5f9",
                    color: user.role === "Admin" ? "#7e22ce" : user.role === "Security Analyst" ? "#2563eb" : "#475569",
                    fontSize: "11px",
                    fontWeight: 700,
                  }}
                >
                  {user.role}
                </span>
              </td>
              <td>
                <span style={{ color: "#15803d", fontWeight: 700, fontSize: "12px" }}>
                  ● {user.status}
                </span>
              </td>
              <td>
                {user.role === "Admin" ? (
                  <span style={{ color: "#94a3b8", fontSize: "12px" }}>
                    Primary account
                  </span>
                ) : (
                  <button
                    className="secondary-button"
                    onClick={() =>
                      setUsers((previous) =>
                        previous.filter((item) => item.id !== user.id)
                      )
                    }
                  >
                    Remove
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </section>

  {showUserModal && (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 4000,
        background: "rgba(15, 23, 42, 0.65)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "20px",
      }}
    >
      <div
        style={{
          width: "min(500px, 100%)",
          background: "#fff",
          borderRadius: "18px",
          padding: "28px",
          boxShadow: "0 25px 70px rgba(0,0,0,0.25)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "22px" }}>
          <div>
            <h2 style={{ margin: 0 }}>Add New User</h2>
            <p style={{ margin: "6px 0 0", color: "#64748b", fontSize: "13px" }}>
              Add a member to the VulnHawk workspace.
            </p>
          </div>
          <button
            onClick={() => setShowUserModal(false)}
            style={{
              border: "none",
              background: "#f1f5f9",
              borderRadius: "9px",
              width: "36px",
              height: "36px",
              cursor: "pointer",
              fontSize: "20px",
              color: "#64748b",
            }}
          >
            ×
          </button>
        </div>

        <label style={{ display: "block", fontWeight: 700, fontSize: "13px", marginBottom: "7px" }}>
          Full Name
        </label>
        <input
          value={userForm.name}
          onChange={(e) => setUserForm({ ...userForm, name: e.target.value })}
          placeholder="Enter full name"
          style={{
            width: "100%",
            boxSizing: "border-box",
            padding: "12px",
            border: "1px solid #dbe3ef",
            borderRadius: "10px",
            marginBottom: "16px",
            outline: "none",
          }}
        />

        <label style={{ display: "block", fontWeight: 700, fontSize: "13px", marginBottom: "7px" }}>
          Email
        </label>
        <input
          type="email"
          value={userForm.email}
          onChange={(e) => setUserForm({ ...userForm, email: e.target.value })}
          placeholder="user@example.com"
          style={{
            width: "100%",
            boxSizing: "border-box",
            padding: "12px",
            border: "1px solid #dbe3ef",
            borderRadius: "10px",
            marginBottom: "16px",
            outline: "none",
          }}
        />

        <label style={{ display: "block", fontWeight: 700, fontSize: "13px", marginBottom: "7px" }}>
          Role
        </label>
        <select
          value={userForm.role}
          onChange={(e) => setUserForm({ ...userForm, role: e.target.value })}
          style={{
            width: "100%",
            boxSizing: "border-box",
            padding: "12px",
            border: "1px solid #dbe3ef",
            borderRadius: "10px",
            marginBottom: "24px",
            background: "#fff",
            outline: "none",
          }}
        >
          <option value="Security Analyst">Security Analyst</option>
          <option value="Viewer">Viewer</option>
          <option value="Admin">Admin</option>
        </select>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
          <button className="secondary-button" onClick={() => setShowUserModal(false)}>
            Cancel
          </button>
          <button
            className="scan-button"
            onClick={() => {
              const name = userForm.name.trim();
              const email = userForm.email.trim();

              if (!name || !email) {
                alert("Please enter the user's name and email.");
                return;
              }

              if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                alert("Please enter a valid email address.");
                return;
              }

              setUsers((previous) => [
                ...previous,
                {
                  id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                  name,
                  email,
                  role: userForm.role,
                  status: "Active",
                },
              ]);

              setShowUserModal(false);
              setUserForm({
                name: "",
                email: "",
                role: "Security Analyst",
              });
            }}
          >
            <Plus size={17} />
            Add User
          </button>
        </div>
      </div>
    </div>
  )}
</div>
) : (
  <div className="dashboard-content">
    <header className="topbar">
      <div>
        <h1>Access Restricted</h1>
        <p>User management is available only to Administrators.</p>
      </div>
    </header>

    <section
      className="card"
      style={{
        marginTop: "24px",
        padding: "32px",
        textAlign: "center",
      }}
    >
      <ShieldAlert size={38} />
      <h3>Administrator permission required</h3>
      <p style={{ color: "#64748b" }}>
        Your current role is <strong>{currentRole}</strong>.
        You cannot add or remove workspace users.
      </p>
      <button
        className="secondary-button"
        onClick={() => setActivePage("dashboard")}
      >
        Back to Dashboard
      </button>
    </section>
  </div>
)

) : activePage === "settings" ? (

  <div className="dashboard-content">
    <header className="topbar">
      <div>
        <h1>Settings</h1>
        <p>VulnHawk application settings</p>
      </div>
    </header>
    <section className="card" style={{ marginTop: "24px", padding: "28px" }}>
      <h3>Scanner Configuration</h3>
      <p style={{ color: "#64748b" }}>
        Backend scanner configuration is managed through the project configuration files.
      </p>
    </section>
  </div>

) : (

   <div className="dashboard-content">


       {/* VULNHAWK COMMAND HEADER */}

<header className="command-header">

  <div className="brand-block">
    <div className="brand-eagle">🦅</div>

    <div>
      <h1>VULN<span>HAWK</span></h1>
      <p>Web Application Security Scanner</p>
    </div>
  </div>

  <div className="target-control">

    <Target size={19} />

    <input
      type="text"
      value={target}
      onChange={(e) => setTarget(e.target.value)}
      placeholder="Enter authorized target..."
    />

    <ChevronDown size={18} />

  </div>

  <button
    className="command-scan-button"
    onClick={() => setShowScanModal(true)}
    disabled={scanning}
  >
    <Play size={18} />
    {scanning ? "Scanning..." : "Start Scan"}
  </button>

  <button className="command-icon-button">
    <Settings size={19} />
  </button>

  <button className="command-icon-button notification-button">
    <Bell size={19} />
    {recentScans.length > 0 && (
      <span className="notification-dot"></span>
    )}
  </button>

  <div className="command-profile">

    <div className="command-avatar">
      A
    </div>

    <div>
      <strong>Admin</strong>
      <span>{currentRole}</span>
    </div>

    <ChevronDown size={17} />

  </div>

</header>


{/* COMMAND CENTER METRICS */}

<section className="command-metrics">

  {/* SECURITY SCORE */}

  <div className="metric-card score-card">

    <div className="metric-icon score-icon">
      <ShieldCheck size={25} />
    </div>

    <div className="metric-content">

      <span>SECURITY SCORE</span>

      <div className="metric-value">
        {latestScan ? latestScore : "—"}
        {latestScan && <small>/100</small>}
      </div>

      <div className="metric-status">
        {latestScan
          ? latestScore >= 90
            ? "Excellent"
            : latestScore >= 75
            ? "Good"
            : latestScore >= 50
            ? "Moderate"
            : "Needs Attention"
          : "No Scan"}
      </div>

    </div>

  </div>


  {/* TOTAL FINDINGS */}

  <div className="metric-card findings-card">

    <div className="metric-icon findings-icon">
      <ShieldAlert size={25} />
    </div>

    <div className="metric-content">

      <span>TOTAL FINDINGS</span>

      <div className="metric-value">
        {vulnerabilityCount}
      </div>

      <div className="metric-subtext">
        {highPlusCount > 0
          ? `${highPlusCount} High / Critical`
          : "No High / Critical"}
      </div>

    </div>

  </div>


  {/* ACTIVE TESTS */}

  <div className="metric-card tests-card">

    <div className="metric-icon tests-icon">
      <Radar size={25} />
    </div>

    <div className="metric-content">

      <span>ACTIVE TESTS</span>

      <div className="metric-value">
        4
      </div>

      <div className="metric-subtext">
        XSS • SQLi • Path Traversal • Open Redirect
      </div>

    </div>

  </div>


  {/* TECHNOLOGIES */}

  <div className="metric-card technology-card">

    <div className="metric-icon technology-icon">
      <Target size={25} />
    </div>

    <div className="metric-content">

      <span>TECHNOLOGIES</span>

      <div className="metric-value">
        {latestScan?.technologies?.Technologies?.length || 0}
      </div>

      <div className="metric-subtext">
        {latestScan?.technologies?.Technologies?.length
          ? latestScan.technologies.Technologies
              .slice(0, 2)
              .map((tech) => tech.name)
              .join(", ")
          : "No technologies detected"}
      </div>

    </div>

  </div>


  {/* SCAN DURATION */}

  <div className="metric-card duration-card">

    <div className="metric-icon duration-icon">
      <Clock3 size={25} />
    </div>

    <div className="metric-content">

      <span>SCAN STATUS</span>

      <div className="metric-value">
        {latestScan ? "READY" : "IDLE"}
      </div>

      <div className="metric-subtext">
        {latestScan
          ? "Latest assessment completed"
          : "Awaiting assessment"}
      </div>

    </div>

  </div>

</section>


        {/* QUICK ACTIONS */}

        <section className="actions-row">

          <button  
   className="scan-button"
  onClick={() => setShowScanModal(true)}
>
  <Play size={17} />
  Launch New Scan
          </button>

          <button
  className="secondary-button"
  onClick={() => setActivePage("scans")}
>
  <FileText size={17} />
  {latestScan ? "View Latest Report" : "View Scan Reports"}
</button>

        </section>


        {/* SECURITY COMMAND ANALYSIS */}

<section className="security-analysis-grid">

  {/* VULNERABILITY DISTRIBUTION */}

  <div className="cyber-card vulnerability-panel">

    <div className="cyber-card-header">
      <div>
        <h3>Vulnerability Distribution</h3>
        <p>Current scan finding breakdown</p>
      </div>

      <ShieldAlert size={19} />
    </div>

    <div className="distribution-content">

      <div className="donut-container">

        <ResponsiveContainer width="100%" height={250}>

          <PieChart>

            <Pie
              data={severityData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={58}
              outerRadius={88}
              paddingAngle={4}
              stroke="none"
            >

              {severityData.map((entry, index) => (
                <Cell
                  key={`severity-${index}`}
                  fill={[
                    "#ff315c",
                    "#ff7a18",
                    "#ffc400",
                    "#00bfff",
                    "#7c4dff",
                  ][index]}
                />
              ))}

            </Pie>

            <Tooltip />

          </PieChart>

        </ResponsiveContainer>

        <div className="donut-center">
          <strong>{vulnerabilityCount}</strong>
          <span>Findings</span>
        </div>

      </div>


      <div className="severity-list">

        {severityData.map((item) => {

          const total =
            severityData.reduce(
              (sum, current) => sum + current.value,
              0
            );

          const percentage =
            total > 0
              ? Math.round((item.value / total) * 100)
              : 0;

          return (
            <div
              className="severity-row"
              key={item.name}
            >

              <div className="severity-name">

                <span
                  className={`severity-dot ${item.name.toLowerCase()}`}
                />

                <span>{item.name}</span>

              </div>

              <strong>{item.value}</strong>

              <span className="severity-percent">
                {percentage}%
              </span>

            </div>
          );

        })}

      </div>

    </div>

  </div>


  {/* SECURITY ASSESSMENT */}

  <div className="cyber-card radar-panel">

    <div className="cyber-card-header">

      <div>
        <h3>Security Assessment</h3>
        <p>Scanner module coverage</p>
      </div>

      <ShieldCheck size={19} />

    </div>

    <div className="radar-wrapper">

      <ResponsiveContainer width="100%" height={285}>

        <RadarChart
          data={[
            {
              subject: "Headers",
              value: latestScan?.headers ? 100 : 0,
            },
            {
              subject: "SSL/TLS",
              value: latestScan?.ssl ? 100 : 0,
            },
            {
              subject: "Cookies",
              value: latestScan?.cookies ? 100 : 0,
            },
            {
              subject: "Network",
              value: latestScan?.ports ? 100 : 0,
            },
            {
              subject: "Application",
              value: latestScan?.crawl ? 100 : 0,
            },
            {
              subject: "Active Tests",
              value:
                latestScan?.xss ||
                latestScan?.sqli
                  ? 100
                  : 0,
            },
          ]}
          cx="50%"
          cy="50%"
          outerRadius="68%"
        >

          <PolarGrid
            stroke="#1e5d8f"
          />

          <PolarAngleAxis
            dataKey="subject"
            tick={{
              fill: "#b8d8f5",
              fontSize: 10,
            }}
          />

          <PolarRadiusAxis
            domain={[0, 100]}
            tick={false}
            axisLine={false}
          />

          <RadarArea
            name="Coverage"
            dataKey="value"
            stroke="#00e5ff"
            fill="#00bfff"
            fillOpacity={0.28}
            strokeWidth={2}
          />

          <Tooltip />

        </RadarChart>

      </ResponsiveContainer>

    </div>

  </div>


  {/* ACTIVE SECURITY TESTS */}

  <div className="cyber-card tests-panel">

    <div className="cyber-card-header">

      <div>
        <h3>Active Security Tests</h3>
        <p>Evidence-based active testing</p>
      </div>

      <Radar size={19} />

    </div>


    <div className="test-list">

      {[
        {
          name: "XSS",
          fullName: "Cross-Site Scripting",
          data: latestScan?.xss,
          color: "pink",
        },
        {
          name: "SQL Injection",
          fullName: "SQL Injection",
          data: latestScan?.sqli,
          color: "orange",
        },
        {
          name: "Path Traversal",
          fullName: "Path Traversal",
          data: latestScan?.path_traversal,
          color: "purple",
        },
        {
          name: "Open Redirect",
          fullName: "Open Redirect",
          data: latestScan?.open_redirect,
          color: "blue",
        },
      ].map((test) => {

        const completed = Boolean(test.data);

        const findings =
          test.data?.findings?.length ?? 0;

        return (
          <div
            className="active-test-row"
            key={test.name}
          >

            <div
              className={`test-icon ${test.color}`}
            >
              <ShieldAlert size={18} />
            </div>

            <div className="test-info">

              <strong>{test.name}</strong>

              <span>{test.fullName}</span>

              <div className="test-progress">
                <div
                  className={`test-progress-fill ${test.color}`}
                  style={{
                    width: completed
                      ? "100%"
                      : "0%",
                  }}
                />
              </div>

            </div>

            <div className="test-result">

              <span>
                {completed ? "Tested" : "Pending"}
              </span>

              <strong
                className={
                  findings > 0
                    ? "has-findings"
                    : "clean-test"
                }
              >
                {findings} findings
              </strong>

            </div>

          </div>
        );

      })}

    </div>

  </div>

</section>

        {/* TECHNOLOGY FINGERPRINTING */}

<section className="cyber-card technology-fingerprint">

  <div className="cyber-card-header">

    <div>
      <h3>Technology Fingerprinting</h3>
      <p>Technologies identified by VulnHawk</p>
    </div>

    <Radar size={20} />

  </div>


  {latestScan?.technologies &&
  !latestScan.technologies.Error ? (

    <div className="technology-content">

      {/* DETECTED TECHNOLOGIES */}

      <div className="technology-list">

        {(
          latestScan.technologies.Technologies || []
        ).length > 0 ? (

          latestScan.technologies.Technologies.map(
            (technology, index) => (

              <div
                className="technology-item"
                key={`${technology.name}-${index}`}
              >

                <div className="technology-icon">
                  <Layers3 size={22} />
                </div>

                <div className="technology-info">

                  <strong>
                    {technology.name}
                  </strong>

                  <span>
                    {technology.category ||
                      "Technology"}
                  </span>

                  <div className="confidence-badge">
                    {technology.confidence ||
                      "Unknown"} Confidence
                  </div>

                </div>

              </div>

            )
          )

        ) : (

          <div className="technology-empty">
            No technologies detected
          </div>

        )}

      </div>


      {/* EVIDENCE */}

      <div className="technology-evidence">

        <div className="evidence-title">
          <FileSearch size={18} />
          <span>Evidence</span>
        </div>


        {(
          latestScan.technologies.Evidence || []
        ).length > 0 ? (

          latestScan.technologies.Evidence.map(
            (evidence, index) => (

              <div
                className="evidence-item"
                key={index}
              >

                <FileSearch size={16} />

                <div>

                  <strong>
                    {evidence.source ||
                      "Detection Evidence"}
                  </strong>

                  <p>
                    {evidence.evidence ||
                      "Evidence available"}
                  </p>

                </div>

              </div>

            )
          )

        ) : (

          <div className="technology-empty">
            No fingerprint evidence available
          </div>

        )}

      </div>

    </div>

  ) : (

    <div className="technology-empty large">
      Technology information unavailable
    </div>

  )}

</section>


      {/* VULNERABILITY FINDINGS */}

<section className="cyber-card vulnerability-findings">

  {/* HEADER */}
  <div className="cyber-card-header">

    {/* TITLE ROW */}
    <div className="finding-header-title">

      <div>
        <div className="finding-title-with-icon">
  <ScanSearch size={22} />
  <h3>Vulnerability Findings</h3>
</div>

        <p>
          Security findings identified during the current assessment
        </p>
      </div>

      <ShieldAlert size={20} />

    </div>

    {/* SEARCH + FILTERS */}
    <div className="finding-controls">

      <div className="finding-search-box">

  <div className="finding-input-wrap">

    <input
      type="text"
      value={findingSearch}
      onChange={(e) => setFindingSearch(e.target.value)}
      placeholder="Search findings..."
    />

    {findingSearch && (
      <button
        type="button"
        onClick={() => setFindingSearch("")}
        className="finding-search-clear"
        aria-label="Clear search"
      >
        ×
      </button>
    )}

  </div>

</div>
      <div className="finding-filter-group">

        <select
          value={findingSeverity}
          onChange={(e) => setFindingSeverity(e.target.value)}
        >
          {findingSeverities.map((severity) => (
            <option key={severity} value={severity}>
              Severity: {severity}
            </option>
          ))}
        </select>

        <select
          value={findingCategory}
          onChange={(e) => setFindingCategory(e.target.value)}
        >
          {findingCategories.map((category) => (
            <option key={category} value={category}>
              Category: {category}
            </option>
          ))}
        </select>

        <select
          value={findingConfidence}
          onChange={(e) => setFindingConfidence(e.target.value)}
        >
          {findingConfidences.map((confidence) => (
            <option key={confidence} value={confidence}>
              Confidence: {confidence}
            </option>
          ))}
        </select>

        <button
          type="button"
          className="finding-clear-filters"
          onClick={() => {
            setFindingSearch("");
            setFindingSeverity("All");
            setFindingCategory("All");
            setFindingConfidence("All");
          }}
        >
          Clear Filters
        </button>

      </div>

    </div>

  </div>

  {/* RESULT COUNT */}
  <div className="finding-result-count">
    Showing {filteredFindings.length} of {currentFindings.length} findings
  </div>

  {currentFindings.length > 0 ? (

    <div className="findings-table-wrapper">

      <table className="findings-table">

        <thead>
          <tr>
            <th>Severity</th>
            <th>Finding</th>
            <th>Category</th>
            <th>CWE</th>
            <th>Confidence</th>
            <th>Action</th>
          </tr>
        </thead>

        <tbody>

          {filteredFindings.map((finding, index) => {

            const severity =
              finding.severity || "Info";

            const severityClass =
              severity.toLowerCase();

            return (

              <tr key={`${finding.title}-${index}`}>

                <td>
                  <span
                    className={`severity-badge ${severityClass}`}
                  >
                    {severity}
                  </span>
                </td>

                <td>

                  <div className="finding-title">
                    {finding.title ||
                      finding.name ||
                      "Security Finding"}
                  </div>

                  {finding.description && (
                    <div className="finding-description">
                      {finding.description}
                    </div>
                  )}

                </td>

                <td>
                  {finding.category || "Security"}
                </td>

                <td>
                  {finding.cwe || finding.cwe_id || "—"}
                </td>

                <td>

                  <span
                    className={`confidence-text ${
                      (
                        finding.confidence ||
                        "Unknown"
                      ).toLowerCase()
                    }`}
                  >
                    {finding.confidence ||
                      "Unknown"}
                  </span>

                </td>

                <td>

                  <button
                    type="button"
                    className="finding-details-btn"
                    onClick={() => {
                      console.log(
                        "finding selected:",
                        finding
                      );
                      setSelectedFinding(finding);
                    }}
                  >
                    View Details
                  </button>

                </td>

              </tr>

            );

          })}

        </tbody>

      </table>

    </div>

  ) : (

    <div className="findings-empty">

      <CheckCircle size={28} />

      <strong>
        No vulnerabilities detected
      </strong>

      <span>
        VulnHawk did not identify any security
        findings in the current assessment.
      </span>

    </div>

  )}

</section>

{selectedFinding && (
  <div
    className="finding-modal-overlay"
    onClick={() => setSelectedFinding(null)}
  >
    <div
      className="finding-modal"
      onClick={(e) => e.stopPropagation()}
    >

      <div className="finding-modal-header">

        <div>
          <h2>
            {selectedFinding.title ||
              selectedFinding.name ||
              "Security Finding"}
          </h2>

          <p>
            Detailed vulnerability intelligence
          </p>
        </div>

        <button
          className="finding-modal-close"
          onClick={() => setSelectedFinding(null)}
        >
          ×
        </button>

      </div>


      <div className="finding-modal-body">

        <div className="finding-detail-grid">

          <div className="finding-detail-item">
            <span>Severity</span>
            <strong>
              {selectedFinding.severity || "Info"}
            </strong>
          </div>

          <div className="finding-detail-item">
            <span>Category</span>
            <strong>
              {selectedFinding.category || "Security"}
            </strong>
          </div>

          <div className="finding-detail-item">
            <span>CWE</span>
            <strong>
              {selectedFinding.cwe || selectedFinding.cwe_id || "—"}
            </strong>
          </div>

          <div className="finding-detail-item">
            <span>Confidence</span>
            <strong>
              {selectedFinding.confidence || "Unknown"}
            </strong>
          </div>

        </div>


        <div className="finding-detail-section">
          <h4>Endpoint</h4>

          <div className="finding-detail-value">
            {selectedFinding.endpoint ||
              selectedFinding.affected_url ||
              "Not specified"}
          </div>
        </div>


        <div className="finding-detail-section">
          <h4>Parameter</h4>

          <div className="finding-detail-value">
            {selectedFinding.parameter ||
              "Not specified"}
          </div>
        </div>


        <div className="finding-detail-section">
          <h4>Description</h4>

          <p>
            {selectedFinding.description ||
              "No description available."}
          </p>
        </div>


        <div className="finding-detail-section">
          <h4>Impact</h4>

          <p>
            {selectedFinding.impact ||
              "Impact information is not available for this finding."}
          </p>
        </div>


        <div className="finding-detail-section">
          <h4>Recommendation</h4>

          <p>
            {selectedFinding.recommendation ||
              "No remediation recommendation is available."}
          </p>
        </div>


        <div className="finding-detail-section">
          <h4>Evidence</h4>

          <pre className="finding-evidence">
            {selectedFinding.evidence
              ? typeof selectedFinding.evidence === "string"
                ? selectedFinding.evidence
                : JSON.stringify(
                    selectedFinding.evidence,
                    null,
                    2
                  )
              : "No evidence recorded."}
          </pre>
        </div>

      </div>


      <div className="finding-modal-footer">

        <button
          className="finding-close-btn"
          onClick={() => setSelectedFinding(null)}
        >
          view Details
        </button>

      </div>

    </div>
  </div>
)}
        {/* SSL / TLS */}

        <section className="card scanner-card">

          <div className="card-header">

            <div>
              <h3>SSL / TLS</h3>
              <p>Certificate and HTTPS security status</p>
            </div>

            <ShieldCheck size={21} />

          </div>


          {latestScan?.ssl ? (

            <div className="ssl-box">

              <div className="ssl-status">

                <span>Status</span>

                <strong
                  className={
                    latestScan.ssl.Status === "Secure"
                      ? "ssl-secure"
                      : latestScan.ssl.Status === "Unavailable"
                      ? "ssl-unavailable"
                      : "ssl-warning"
                  }
                >
                  {latestScan.ssl.Status || "Unknown"}
                </strong>

              </div>


              {latestScan.ssl.Issuer && (

                <div className="ssl-detail">

                  <span>Issuer</span>

                  <strong>
                    {Object.values(
                      latestScan.ssl.Issuer
                    ).join(" / ")}
                  </strong>

                </div>

              )}


              {latestScan.ssl["Valid Until"] && (

                <div className="ssl-detail">

                  <span>Valid Until</span>

                  <strong>
                    {latestScan.ssl["Valid Until"]}
                  </strong>

                </div>

              )}


              {latestScan.ssl.Reason && (

                <div className="ssl-detail">

                  <span>Reason</span>

                  <strong>
                    {latestScan.ssl.Reason}
                  </strong>

                </div>

              )}

            </div>

          ) : (

            <div className="empty-scanner">
              SSL/TLS information unavailable
            </div>

          )}

        </section>


        {/* COOKIE SECURITY */}

        <section className="card scanner-card">

          <div className="card-header">

            <div>
              <h3>Cookie Security</h3>
              <p>Cookie protection attributes</p>
            </div>

            <ShieldAlert size={21} />

          </div>


          {latestScan?.cookies &&
          !latestScan.cookies.Error ? (

            latestScan.cookies.Status === "No cookies found" ? (

              <div className="empty-scanner">
                No cookies found
              </div>

            ) : (

              <div className="cookie-list">

                {Object.entries(
                  latestScan.cookies
                ).map(([cookie, details]) => (

                  <div
                    className="cookie-item"
                    key={cookie}
                  >

                    <strong>
                      {cookie}
                    </strong>

                    <div className="cookie-flags">

                      <span
                        className={
                          details.Secure
                            ? "cookie-good"
                            : "cookie-bad"
                        }
                      >
                        Secure: {details.Secure ? "Yes" : "No"}
                      </span>

                      <span
                        className={
                          details.HttpOnly
                            ? "cookie-good"
                            : "cookie-bad"
                        }
                      >
                        HttpOnly: {details.HttpOnly ? "Yes" : "No"}
                      </span>

                      <span
                        className={
                          details.SameSite !== "Missing"
                            ? "cookie-good"
                            : "cookie-bad"
                        }
                      >
                        SameSite: {details.SameSite}
                      </span>

                    </div>

                  </div>

                ))}

              </div>

            )

          ) : (

            <div className="empty-scanner">
              Cookie information unavailable
            </div>

          )}

        </section>

        {/* OPEN PORTS */}

        <section className="card scanner-card">

          <div className="card-header">

            <div>
              <h3>Open Ports</h3>
              <p>Network services discovered by Nmap</p>
            </div>

            <Radar size={21} />

          </div>


          {latestScan?.ports?.Ports &&
           Object.values(latestScan.ports.Ports).some(
             (details) => details.State === "open"
           ) ? (

           <div className="ports-list">

  {/* TABLE HEADER */}
  <div className="ports-header">

    <div>PORT</div>
    <div>SERVICE</div>
    <div>PRODUCT</div>
    <div>VERSION</div>
    <div>EXTRA INFO</div>
    <div>STATE</div>

  </div>

  {/* OPEN PORTS */}
  {Object.entries(latestScan.ports.Ports)
    .filter(([port, details]) => details.State === "open")
    .map(([port, details]) => (

      <div className="port-item" key={port}>

        {/* PORT */}
        <div className="port-number">
          {port}
        </div>

        {/* SERVICE */}
        <div className="port-column service-column">
  <strong>
    {details.Service || "Unknown"}
  </strong>
</div>

        {/* PRODUCT */}
        <div className="port-column">
  <span>
    {details.Product || "—"}
  </span>
</div>

        {/* VERSION */}
        <div className="port-column">
  <span>
    {details.Version || "—"}
  </span>
</div>

        {/* EXTRA INFO */}
       <div className="port-column">
  <span>
    {details.ExtraInfo || "—"}
  </span>
</div>

        {/* STATE */}
        <span
          className={
            details.State === "open"
              ? "port-status open"
              : "port-status"
          }
        >
          {details.State || "Unknown"}
        </span>

      </div>

    ))}

</div>

          ) : (

            <div className="empty-scanner">
              No port information available
            </div>

          )}

        </section>


        {/* SECURITY HEADERS */}

        <section className="card scanner-card">

          <div className="card-header">

            <div>
              <h3>Security Headers</h3>
              <p>HTTP security header analysis</p>
            </div>

            <ShieldCheck size={21} />

          </div>


          {latestScan?.headers &&
          !latestScan.headers.Error ? (

            <div className="headers-list">

              {Object.entries(
                latestScan.headers
              ).map(([header, status]) => (

                <div
                  className="header-item"
                  key={header}
                >

                  <div className="header-name">
                    {header}
                  </div>


                  <span
                    className={
                      status === "Present"
                        ? "header-status present"
                        : "header-status missing"
                    }
                  >

                    {status === "Present"
                      ? "Present"
                      : "Missing"}

                  </span>

                </div>

              ))}

            </div>

          ) : (

            <div className="empty-scanner">
              Security header information unavailable
            </div>

          )}

        </section>

        {/* VULNERABILITY FINDINGS */}

        <section className="card findings-card">

          <div className="card-header">

            <div>
              <h3>Vulnerability Findings</h3>
              <p>Issues detected during the latest scan</p>
            </div>

            <ShieldAlert size={21} />

          </div>


          {latestScan?.findings?.length > 0 ? (

            <div className="findings-list">

              {latestScan.findings.map((finding, index) => (

                <div className="finding-item" key={index}>

                  <div className="finding-icon">
                    <ShieldAlert size={18} />
                  </div>


                  <div className="finding-content">

                    <strong>
                      {finding.title}
                    </strong>

                    <span>
                      {finding.category}
                    </span>

                  </div>


                  <span
                    className={`severity-badge ${finding.severity.toLowerCase()}`}
                  >
                    {finding.severity}
                  </span>

                </div>

              ))}

            </div>

          ) : (

            <div className="no-findings">

              <CheckCircle size={20} />

              No vulnerabilities detected

            </div>

          )}

        </section>


        {/* RECENT SCANS */}

        <section className="card recent">

          <div className="card-header">

            <div>
              <h3>Recent Scans</h3>
              <p>Latest VulnHawk security assessments</p>
            </div>

            <button
              className="secondary-button"
              onClick={() => setActivePage("scans")}
            >
              View All
            </button>

          </div>


          <div className="table-wrapper">

            <table>

              <thead>

                <tr>
                  <th>Target</th>
                  <th>Security Score</th>
                  <th>Vulnerabilities</th>
                  <th>Status</th>
                  <th>Date</th>
                </tr>

              </thead>


            <tbody>

  {recentScans.length > 0 ? (

    recentScans.map((scan, index) => (

      <tr key={index}>

        <td>
          <strong>{scan.target}</strong>
        </td>

        <td>

          <span
            className={
              scan.score >= 75
                ? "score good"
                : scan.score >= 50
                ? "score medium-score"
                : "score low-score"
            }
          >
            {scan.score}
          </span>

        </td>

        <td>
          {scan.vulnerabilities}
        </td>

        <td>

          <span className="scan-status completed">
            <CheckCircle size={14} />
            {scan.status}
          </span>

        </td>

        <td>
          {scan.date}
        </td>

      </tr>

    ))

  ) : (

    <tr>

      <td colSpan="5" style={{ textAlign: "center" }}>
        No scans yet
      </td>

    </tr>

  )}

</tbody>

            </table>

          </div>

        </section>
        {/* SCAN MODAL */}

        {showScanModal && (
          <div className="modal-overlay">

            <div className="scan-modal">

              <div className="modal-header">

                <div>
                  <h2>Launch Security Scan</h2>
                  <p>Enter an authorized target URL</p>
                </div>

                <button
                  className="modal-close"
                  onClick={() => setShowScanModal(false)}
                >
                  ×
                </button>

              </div>

              <label htmlFor="target-url">
                Target URL
              </label>

              <input
                id="target-url"
                type="text"
                placeholder="https://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />

              <button
                className="scan-button modal-scan"
                disabled={scanning}
                onClick={async () => {
                  if (!target.trim()) {
                    alert("Please enter a target URL");
                    return;
                  }

                  try {
                    setScanning(true);
                    setScanProgress(0);
                    setScanStage("Initializing Scan");
                    setScanJobId(null);

                    // Close the launch form immediately so only the
                    // scan-progress overlay remains visible.
                    setShowScanModal(false);

                    // Start a background scan job.
                    const startResponse = await fetch(
                      "http://127.0.0.1:8001/scan/start",
                      {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                          target: target.trim(),
                        }),
                      }
                    );

                    const startData = await startResponse.json();

                    if (!startResponse.ok) {
                      throw new Error(
                        startData.detail || "Unable to start scan"
                      );
                    }

                    const jobId = startData.job_id;
                    setScanJobId(jobId);

                    // Poll the real backend progress endpoint.
                    const pollScan = async () => {
                      const statusResponse = await fetch(
                        `http://127.0.0.1:8001/scan/status/${jobId}`
                      );

                      const statusData = await statusResponse.json();

                      if (!statusResponse.ok) {
                        throw new Error(
                          statusData.detail || "Unable to read scan status"
                        );
                      }

                      const nextProgress = statusData.progress ?? 0;
                      const nextStage = statusData.stage || "Scanning...";

                      setScanProgress((previousProgress) =>
                        previousProgress === nextProgress
                          ? previousProgress
                          : nextProgress
                      );

                      setScanStage((previousStage) =>
                        previousStage === nextStage
                          ? previousStage
                          : nextStage
                      );

                      if (statusData.status === "completed") {
                        const data = statusData.result;

                        console.log(
                          "VulnHawk Scan Result:",
                          data
                        );

                        setScanResult(data);
                        setRecentScans((previousScans) => [
  {
    target: target.trim(),

    score: data.security?.score ?? 0,

    vulnerabilities:
      data.security?.findings?.length ?? 0,

    findings:
      data.security?.findings ?? [],

    // Core scan results
    http_discovery:
      data.results?.http_discovery ?? {},

    crawl:
      data.results?.crawl ?? {},

    headers:
      data.results?.headers ?? {},

    ssl:
      data.results?.ssl ?? {},

    technologies:
      data.results?.technologies ?? {},

    robots:
      data.results?.robots ?? {},

    sitemap:
      data.results?.sitemap ?? {},

    cookies:
      data.results?.cookies ?? {},

    ports:
      data.results?.ports ?? {},

    // Active web testing results
    xss:
      data.results?.xss ?? {},

    sqli:
      data.results?.sqli ?? {},
    path_traversal:
      data.results?.path_traversal ?? {},

    open_redirect:
      data.results?.open_redirect ?? {},

    status: "Completed",

    date: new Date().toLocaleString(),
  },

  ...previousScans,
]);

                        setScanProgress(100);
                        setScanStage("Scan Completed");

                        // Give the completed state a moment to be visible.
                        setTimeout(() => {
                          setScanning(false);
                          setShowScanModal(false);
                          setScanJobId(null);
                        }, 700);

                        return;
                      }

                      if (statusData.status === "failed") {
                        throw new Error(
                          statusData.error || "Scan failed"
                        );
                      }

                      setTimeout(pollScan, 1200);
                    };

                    pollScan();
                  } catch (error) {
                    console.error(error);
                    setScanning(false);
                    setScanJobId(null);
                    setShowScanModal(true);

                    alert(
                      `Scan failed: ${error.message}`
                    );
                  }
                }}
              >
                <Play size={17} />

                {scanning
                  ? "Scanning..."
                  : "Start Scan"
                }

              </button>
            </div>
          </div>
        )}

        {scanning && (
          <div
            style={{
      position: "fixed",
      inset: 0,
      zIndex: 3000,
      background: "rgba(7, 12, 24, 0.78)",
      backdropFilter: "blur(8px)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "24px",
            }}
          >
            <div
            style={{
              width: "min(620px, 100%)",
    maxHeight: "calc(100vh - 48px)",
    background: "#ffffff",
    borderRadius: "18px",
    padding: "28px",
    boxShadow: "0 25px 70px rgba(0,0,0,0.30)",
    overflowY: "auto",
    boxSizing: "border-box",
    margin: "auto 0",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "14px",
                  marginBottom: "22px",
                }}
              >
                <div
                  style={{
                    width: "46px",
                    height: "46px",
                    borderRadius: "12px",
                    background: "#eff6ff",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: "24px",
                  }}
                >
                  🛡️
                </div>

                <div>
                  <h2
                    style={{
                      margin: 0,
                      color: "#111827",
                      fontSize: "22px",
                    }}
                  >
                    VulnHawk Scan in Progress
                  </h2>
                  <p
                    style={{
                      margin: "5px 0 0",
                      color: "#6b7280",
                      fontSize: "13px",
                    }}
                  >
                    Analyzing {target.trim()}
                  </p>
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "9px",
                }}
              >
                <strong
                  style={{
                    color: "#1f2937",
                    fontSize: "14px",
                  }}
                >
                  {scanStage}
                </strong>

                <strong
                  style={{
                    color: "#2563eb",
                    fontSize: "16px",
                  }}
                >
                  {scanProgress}%
                </strong>
              </div>

              <div
                style={{
                  height: "10px",
                  width: "100%",
                  background: "#e5e7eb",
                  borderRadius: "999px",
                  overflow: "hidden",
                  marginBottom: "25px",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${scanProgress}%`,
                    background:
                      "linear-gradient(90deg, #2563eb, #4f46e5)",
                    borderRadius: "999px",
                    transition: "width 0.5s ease",
                  }}
                />
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns:
                    "repeat(2, minmax(0, 1fr))",
                  gap: "10px",
                }}
              >
                {[
                    ["HTTP / HTTPS Discovery", 8],
                    ["Web Application Crawling", 14],
                    ["Security Headers", 18],
                    ["SSL / TLS Analysis", 22],
                    ["Technology Detection", 34],
                    ["robots.txt Analysis", 46],
                    ["sitemap.xml Analysis", 58],
                    ["Cookie Security Analysis", 70],
                    ["Nmap Port Scan", 84],
                    ["XSS Reflection Analysis", 90],
                    ["SQL Injection Analysis", 92],
                    ["Path Traversal Analysis", 93],
                    ["Open Redirect Analysis", 94],
                    ["Security Score", 95],
                  ].map(([label, threshold]) => {
                  const completed = scanProgress > threshold;
                  const active = scanStage === label;

                  return (
                    <div
                      key={label}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "9px",
                        padding: "10px 12px",
                        borderRadius: "10px",
                        background: completed
                          ? "#f0fdf4"
                          : active
                          ? "#eff6ff"
                          : "#f9fafb",
                        border: `1px solid ${
                          completed
                            ? "#bbf7d0"
                            : active
                            ? "#bfdbfe"
                            : "#e5e7eb"
                        }`,
                      }}
                    >
                      <span
                        style={{
                          width: "22px",
                          height: "22px",
                          borderRadius: "50%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "12px",
                          fontWeight: 700,
                          background: completed
                            ? "#16a34a"
                            : active
                            ? "#2563eb"
                            : "#e5e7eb",
                          color:
                            completed || active
                              ? "#ffffff"
                              : "#6b7280",
                        }}
                      >
                        {completed ? "✓" : active ? "•" : "○"}
                      </span>

                      <span
                        style={{
                          fontSize: "12px",
                          fontWeight: completed || active ? 600 : 500,
                          color: completed
                            ? "#166534"
                            : active
                            ? "#1d4ed8"
                            : "#6b7280",
                        }}
                      >
                        {label}
                      </span>
                    </div>
                  );
                })}
              </div>

              <div
                style={{
                  marginTop: "20px",
                  paddingTop: "16px",
                  borderTop: "1px solid #e5e7eb",
                  display: "flex",
                  justifyContent: "space-between",
                  fontSize: "12px",
                  color: "#6b7280",
                }}
              >
                <span>
                  {scanJobId
                    ? `Job: ${scanJobId.slice(0, 8)}...`
                    : "Preparing scan job..."}
                </span>
                <span>Do not close the browser</span>
              </div>
            </div>
          </div>
        )}

      </div>
    )}
      </main>
    </div>
  );
}


export default App;

