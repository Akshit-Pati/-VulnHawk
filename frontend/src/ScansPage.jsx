import React, { useState } from "react";
import jsPDF from "jspdf";
import {
  Radar,
  CheckCircle,
  Eye,
  ShieldAlert,
  Search,
  X,
  Server,
  Globe,
  Lock,
  Cookie,
  FileSearch,
} from "lucide-react";

const formatValue = (value) => {
  if (value === null || value === undefined || value === "") {
    return "N/A";
  }

  if (typeof value !== "object") {
    return String(value);
  }

  return Object.entries(value)
    .map(([key, item]) => `${key}: ${formatValue(item)}`)
    .join(" • ");
};

const getPortEntries = (ports) => {
  if (!ports || typeof ports !== "object") {
    return [];
  }

  const portMap =
    ports.Ports && typeof ports.Ports === "object"
      ? ports.Ports
      : ports;

  return Object.entries(portMap).filter(
    ([key, value]) =>
      typeof value === "object" &&
      value !== null &&
      (key.includes("/") ||
        "State" in value ||
        "Service" in value)
  );
};

const getCookieEntries = (cookies) => {
  if (!cookies || typeof cookies !== "object") {
    return [];
  }

  return Object.entries(cookies).filter(
    ([, value]) =>
      value &&
      typeof value === "object" &&
      !Array.isArray(value)
  );
};

function ScansPage({ scans }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [selectedScan, setSelectedScan] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const filteredScans = scans.filter((scan) => {
    const matchesSearch = scan.target
      .toLowerCase()
      .includes(search.toLowerCase());

    const findings = scan.findings || [];
    const severities = findings.map((finding) =>
      typeof finding === "string"
        ? "Info"
        : finding?.severity || "Info"
    );

    const matchesSeverity =
      severityFilter === "All" ||
      severities.includes(severityFilter);

    const matchesStatus =
      statusFilter === "All" ||
      (scan.status || "Completed") === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const totalVulnerabilities = scans.reduce(
    (total, scan) => total + Number(scan.vulnerabilities || 0),
    0
  );

  const completedScans = scans.filter(
    (scan) => (scan.status || "Completed") === "Completed"
  ).length;

  const averageScore =
    scans.length > 0
      ? Math.round(
          scans.reduce(
            (total, scan) => total + Number(scan.score || 0),
            0
          ) / scans.length
        )
      : 0;

const generatePDFReport = (scan) => {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 16;
  const contentWidth = pageWidth - margin * 2;
  let y = 20;

  const colors = {
    navy: [15, 23, 42],
    blue: [37, 99, 235],
    blueLight: [239, 246, 255],
    text: [30, 41, 59],
    muted: [100, 116, 139],
    border: [226, 232, 240],
    green: [22, 163, 74],
    greenLight: [240, 253, 244],
    red: [220, 38, 38],
    redLight: [254, 242, 242],
    orange: [234, 88, 12],
    orangeLight: [255, 247, 237],
    yellow: [202, 138, 4],
    yellowLight: [254, 252, 232],
    purple: [124, 58, 237],
  };

  const setText = (color = colors.text) => {
    doc.setTextColor(...color);
  };

  const addPageIfNeeded = (needed = 16) => {
    if (y + needed > pageHeight - 22) {
      doc.addPage();
      y = 24;
      drawPageHeader();
    }
  };

  const drawPageHeader = () => {
    doc.setFillColor(...colors.navy);
    doc.rect(0, 0, pageWidth, 10, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.text("VULNHAWK", margin, 6.5);
    doc.setFont("helvetica", "normal");
    doc.text("Web Application Security Assessment", pageWidth - margin, 6.5, {
      align: "right",
    });
    setText();
  };

  const addSectionTitle = (title, subtitle = "") => {
    addPageIfNeeded(subtitle ? 25 : 18);

    doc.setFillColor(...colors.blue);
    doc.roundedRect(margin, y - 5, contentWidth, 9, 2, 2, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.text(title, margin + 5, y + 1);

    y += 12;

    if (subtitle) {
      setText(colors.muted);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(7.5);
      doc.text(subtitle, margin, y);
      y += 7;
    }

    setText();
  };

  const addWrappedText = (value, options = {}) => {
    const fontSize = options.fontSize || 8.5;
    const indent = options.indent || 0;
    const width = options.width || contentWidth - indent;
    const bold = options.bold || false;
    const gap = options.gap || 4;

    doc.setFont("helvetica", bold ? "bold" : "normal");
    doc.setFontSize(fontSize);

    const lines = doc.splitTextToSize(String(value ?? ""), width);
    addPageIfNeeded(lines.length * 4.2 + gap);
    doc.text(lines, margin + indent, y);
    y += lines.length * 4.2 + gap;
  };

  const addKeyValue = (label, value) => {
    addPageIfNeeded(9);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    setText(colors.muted);
    doc.text(`${label}:`, margin, y);

    const labelWidth = doc.getTextWidth(`${label}:`) + 4;

    doc.setFont("helvetica", "normal");
    setText();
    const lines = doc.splitTextToSize(
      String(value ?? "N/A"),
      contentWidth - labelWidth
    );

    doc.text(lines, margin + labelWidth, y);
    y += Math.max(5, lines.length * 4.2) + 1;
  };

  const formatValue = (value) => {
    if (value === null || value === undefined || value === "") {
      return "N/A";
    }

    if (typeof value !== "object") {
      return String(value);
    }

    return Object.entries(value)
      .map(([key, item]) => `${key}: ${formatValue(item)}`)
      .join(" • ");
  };

  const severityColor = (severity) => {
    const value = String(severity || "Info").toLowerCase();

    if (value === "critical") return colors.red;
    if (value === "high") return [239, 68, 68];
    if (value === "medium") return colors.orange;
    if (value === "low") return colors.blue;
    return colors.purple;
  };

  const severityLightColor = (severity) => {
    const value = String(severity || "Info").toLowerCase();

    if (value === "critical" || value === "high") {
      return colors.redLight;
    }
    if (value === "medium") return colors.orangeLight;
    if (value === "low") return colors.blueLight;
    return [245, 243, 255];
  };

  const drawBadge = (label, x, width, color, lightColor) => {
    doc.setFillColor(...lightColor);
    doc.roundedRect(x, y - 4, width, 10, 2, 2, "F");
    doc.setTextColor(...color);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.text(label, x + width / 2, y + 2.5, {
      align: "center",
    });
  };

  const findings = scan.findings || [];
  const severityNames = ["Critical", "High", "Medium", "Low", "Info"];
  const severityCounts = Object.fromEntries(
    severityNames.map((name) => [name, 0])
  );

  findings.forEach((finding) => {
    const severity =
      typeof finding === "string"
        ? "Info"
        : finding?.severity || "Info";

    if (severityCounts[severity] !== undefined) {
      severityCounts[severity] += 1;
    }
  });

  const score = Number(scan.score ?? 0);
  const vulnCount = Number(scan.vulnerabilities ?? findings.length ?? 0);

  const rating =
  score >= 90
    ? "Excellent"
    : score >= 75
    ? "Good"
    : score >= 50
    ? "Moderate"
    : score >= 25
    ? "Poor"
    : "Critical";

const ratingColor =
  score >= 90
    ? colors.green
    : score >= 75
    ? colors.blue
    : score >= 50
    ? colors.orange
    : colors.red;

  // =========================================================
  // COVER
  // =========================================================

  doc.setFillColor(...colors.navy);
  doc.rect(0, 0, pageWidth, pageHeight, "F");

  doc.setFillColor(...colors.blue);
  doc.circle(pageWidth - 24, 30, 32, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(28);
  doc.text("VULNHAWK", margin, 40);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.text(
    "Web Application Security Assessment Report",
    margin,
    50
  );

  doc.setFillColor(255, 255, 255);
  doc.roundedRect(
    margin,
    72,
    contentWidth,
    62,
    4,
    4,
    "F"
  );

  doc.setTextColor(...colors.muted);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.text("TARGET", margin + 8, 84);

  doc.setTextColor(...colors.text);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);

  const targetLines = doc.splitTextToSize(
    String(scan.target || "N/A"),
    contentWidth - 16
  );
  doc.text(targetLines, margin + 8, 94);

  doc.setTextColor(...colors.muted);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.text(`Scan Date: ${scan.date || "N/A"}`, margin + 8, 116);
  doc.text(`Status: ${scan.status || "Completed"}`, margin + 8, 124);

  // Score block on cover
  doc.setFillColor(...colors.blue);
  doc.roundedRect(
    margin,
    151,
    contentWidth,
    38,
    4,
    4,
    "F"
  );

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(23);
  doc.text(`${score}/100`, margin + 9, 168);

  doc.setFontSize(8);
  doc.setFont("helvetica", "normal");
  doc.text("Security Score", margin + 9, 179);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.text(String(vulnCount), margin + 78, 168);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.text("Findings", margin + 78, 179);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text(rating, margin + 125, 168);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.text("Assessment Rating", margin + 125, 179);

  doc.setTextColor(203, 213, 225);
  doc.setFontSize(7.5);
  doc.text(
    "Generated by VulnHawk Automated Security Scanner",
    margin,
    pageHeight - 22
  );

  doc.setTextColor(148, 163, 184);
  doc.text(
    "Use this report as an assessment record and validate findings before remediation.",
    margin,
    pageHeight - 14
  );

  // =========================================================
  // PAGE 2+
  // =========================================================

  doc.addPage();
  y = 24;
  drawPageHeader();

  addSectionTitle(
    "Assessment Summary",
    "Recorded details from the selected VulnHawk scan."
  );

  addKeyValue("Target", scan.target);
  addKeyValue("Scan Date", scan.date);
  addKeyValue("Status", scan.status || "Completed");
  addKeyValue("Security Rating", rating);
// =========================================================
// HTTP / HTTPS DISCOVERY
// =========================================================

addSectionTitle(
  "HTTP / HTTPS Discovery",
  "Reachability and redirect information collected during target discovery."
);

const httpDiscovery = scan.http_discovery || {};

if (Object.keys(httpDiscovery).length > 0) {
  addKeyValue("Target", httpDiscovery.target || scan.target);
  addKeyValue(
    "HTTP Reachable",
    httpDiscovery.http?.reachable ? "Yes" : "No"
  );
  addKeyValue(
    "HTTP Status",
    httpDiscovery.http?.status_code ?? "N/A"
  );
  addKeyValue(
    "HTTP Response Time",
    httpDiscovery.http?.response_time != null
      ? `${httpDiscovery.http.response_time}s`
      : "N/A"
  );
  addKeyValue(
    "HTTPS Reachable",
    httpDiscovery.https?.reachable ? "Yes" : "No"
  );
  addKeyValue(
    "HTTPS Status",
    httpDiscovery.https?.status_code ?? "N/A"
  );
  addKeyValue(
    "HTTPS Response Time",
    httpDiscovery.https?.response_time != null
      ? `${httpDiscovery.https.response_time}s`
      : "N/A"
  );
  addKeyValue(
    "Redirects to HTTPS",
    httpDiscovery.redirects_to_https ? "Yes" : "No"
  );
  addKeyValue(
    "Final URL",
    httpDiscovery.final_url || "N/A"
  );
} else {
  addWrappedText("No HTTP/HTTPS discovery data available.");
}

// =========================================================
// CRAWLING & ENDPOINT DISCOVERY
// =========================================================

addSectionTitle(
  "Web Crawling & Endpoint Discovery",
  "Same-origin pages, parameters, forms, JavaScript resources, and endpoints identified by the crawler."
);

const crawl = scan.crawl || {};

addKeyValue(
  "Pages Crawled",
  crawl.pages_crawled ?? 0
);

addKeyValue(
  "Parameters Discovered",
  Array.isArray(crawl.parameters)
    ? crawl.parameters.length
    : 0
);

addKeyValue(
  "Forms Discovered",
  Array.isArray(crawl.forms)
    ? crawl.forms.length
    : 0
);

addKeyValue(
  "JavaScript Files",
  Array.isArray(crawl.javascript_files)
    ? crawl.javascript_files.length
    : 0
);

addKeyValue(
  "JavaScript Endpoints",
  Array.isArray(crawl.javascript_endpoints)
    ? crawl.javascript_endpoints.length
    : 0
);

addKeyValue(
  "Endpoints",
  Array.isArray(crawl.endpoints)
    ? crawl.endpoints.length
    : 0
);

if (Array.isArray(crawl.parameters) && crawl.parameters.length > 0) {
  addWrappedText(
    `Discovered Parameters: ${crawl.parameters.join(", ")}`,
    { fontSize: 7.5 }
  );
}

if (
  Array.isArray(crawl.javascript_endpoints) &&
  crawl.javascript_endpoints.length > 0
) {
  addWrappedText(
    `Discovered JavaScript Endpoints: ${crawl.javascript_endpoints.join(", ")}`,
    { fontSize: 7.2 }
  );
}

  // Severity overview
  addSectionTitle(
    "Finding Severity Summary",
    "Distribution of findings by recorded severity."
  );

  const severityBoxWidth = (contentWidth - 12) / 5;

  severityNames.forEach((name, index) => {
    const x = margin + index * (severityBoxWidth + 3);
    const color = severityColor(name);
    const light = severityLightColor(name);

    doc.setFillColor(...light);
    doc.roundedRect(
      x,
      y - 4,
      severityBoxWidth,
      20,
      2,
      2,
      "F"
    );

    doc.setTextColor(...color);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.text(name, x + severityBoxWidth / 2, y + 3, {
      align: "center",
    });

    doc.setFontSize(13);
    doc.text(
      String(severityCounts[name]),
      x + severityBoxWidth / 2,
      y + 12,
      { align: "center" }
    );
  });

  y += 29;

  // Score assessment box
  addSectionTitle(
    "Security Score",
    "Overall score recorded by the VulnHawk scoring module."
  );

  doc.setFillColor(...colors.blueLight);
  doc.roundedRect(
    margin,
    y - 4,
    contentWidth,
    27,
    3,
    3,
    "F"
  );

  doc.setTextColor(...colors.blue);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.text(`${score}/100`, margin + 8, y + 10);

  doc.setFontSize(8);
  doc.setTextColor(...colors.muted);
  doc.text("Security Score", margin + 8, y + 18);

  doc.setTextColor(...ratingColor);
  doc.setFontSize(12);
  doc.text(rating, margin + 76, y + 10);

  doc.setFontSize(8);
  doc.setTextColor(...colors.muted);
  doc.text("Assessment Rating", margin + 76, y + 18);

  doc.setTextColor(...colors.red);
  doc.setFontSize(20);
  doc.text(String(vulnCount), margin + 130, y + 10);

  doc.setFontSize(8);
  doc.setTextColor(...colors.muted);
  doc.text("Total Findings", margin + 130, y + 18);

  y += 37;

  // =========================================================
  // FINDINGS
  // =========================================================

  addSectionTitle(
    "Vulnerability Findings",
    "Security findings recorded during the assessment."
  );

  if (findings.length > 0) {
    findings.forEach((finding, index) => {
      const title =
        typeof finding === "string"
          ? finding
          : finding?.title ||
            finding?.name ||
            finding?.issue ||
            "Security Finding";

      const severity =
        typeof finding === "string"
          ? "Info"
          : finding?.severity || "Info";

      const category =
        typeof finding === "string"
          ? "Security"
          : finding?.category || "Security";

      const details =
        typeof finding === "object" && finding
          ? getFindingDetails(finding)
          : getFindingDetails({
              title,
              severity,
              category,
            });

      addPageIfNeeded(48);

      doc.setFillColor(...colors.border);
      doc.roundedRect(
        margin,
        y - 4,
        contentWidth,
        11,
        2,
        2,
        "F"
      );

      doc.setTextColor(...colors.text);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);

      const titleLines = doc.splitTextToSize(
        `${index + 1}. ${title}`,
        contentWidth - 50
      );
      doc.text(titleLines[0], margin + 4, y + 2);

      drawBadge(
        severity,
        pageWidth - margin - 34,
        30,
        severityColor(severity),
        severityLightColor(severity)
      );

      y += 13;

      addKeyValue("Severity", severity);
      addKeyValue("Category", category);
    
      if (typeof finding === "object" && finding) {
        if (finding.cwe) {
          addKeyValue("CWE", finding.cwe);
        }

        if (finding.confidence) {
          addKeyValue("Confidence", finding.confidence);
        }

        if (finding.endpoint) {
          addKeyValue("Endpoint", finding.endpoint);
        }

        if (finding.parameter) {
          addKeyValue("Parameter", finding.parameter);
        }

        if (finding.impact) {
          addKeyValue("Impact", finding.impact);
        }

        if (finding.recommendation) {
          addKeyValue("Recommendation", finding.recommendation);
        }
      }
        if (details.description) {
        addWrappedText(`Description: ${details.description}`, {
          gap: 3,
        });
      }

      if (details.impact) {
        addWrappedText(`Impact: ${details.impact}`, {
          gap: 3,
        });
      }

      if (details.recommendation) {
        addWrappedText(
          `Recommendation: ${details.recommendation}`,
          { gap: 6 }
        );
      }
    });
  } else {
    addWrappedText(
      "No vulnerabilities were detected in the recorded scan results."
    );
  }

  // =========================================================
  // SECURITY HEADERS
  // =========================================================

  addSectionTitle(
    "Security Headers",
    "HTTP security-header checks recorded during the scan."
  );

  const headers = scan.headers || {};
  const headerEntries = Object.entries(headers);

  if (headerEntries.length > 0) {
    headerEntries.forEach(([key, value]) => {
      addPageIfNeeded(9);

      doc.setDrawColor(...colors.border);
      doc.line(margin, y + 3, pageWidth - margin, y + 3);

      doc.setTextColor(...colors.text);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.text(key, margin, y);

      const isPresent =
        String(value).toLowerCase() === "present";

      doc.setTextColor(
        ...(isPresent ? colors.green : colors.red)
      );
      doc.setFont("helvetica", "bold");
      doc.text(
        isPresent ? "Present" : String(value),
        pageWidth - margin,
        y,
        { align: "right" }
      );

      y += 8;
    });
  } else {
    addWrappedText("No security header data available.");
  }

  // =========================================================
  // TECHNOLOGIES
  // =========================================================

  addSectionTitle(
    "Technologies Detected",
    "Technology signatures identified by VulnHawk."
  );

const technologies = scan.technologies || {};
const detectedTechnologies = Array.isArray(technologies.Technologies)
  ? technologies.Technologies
  : [];

const technologyEvidence = Array.isArray(technologies.Evidence)
  ? technologies.Evidence
  : [];

if (detectedTechnologies.length > 0) {
  detectedTechnologies.forEach((tech, index) => {
    const name = tech?.name || "Unknown Technology";
    const category = tech?.category || "Unknown Category";
    const confidence = tech?.confidence || "Unknown";

    addKeyValue("Technology", name);
    addKeyValue("Category", category);
    addKeyValue("Confidence", confidence);

    if (index < detectedTechnologies.length - 1) {
      y += 4;
    }
  });
} else {
  addWrappedText("No technology detection data available.");
}

if (technologyEvidence.length > 0) {
  y += 4;

  addSectionTitle(
    "Technology Evidence",
    "Evidence collected by VulnHawk technology fingerprinting."
  );

  technologyEvidence.forEach((item) => {
    addKeyValue(
      "Technology",
      item?.technology || "Unknown"
    );

    addKeyValue(
      "Source",
      item?.source || "Unknown"
    );

    addKeyValue(
      "Confidence",
      item?.confidence || "Unknown"
    );

    if (item?.evidence) {
      addKeyValue(
        "Evidence",
        item.evidence
      );
    }

    y += 3;
  });
}

  // =========================================================
  // SSL / TLS
  // =========================================================

  addSectionTitle(
    "SSL / TLS Information",
    "Certificate and HTTPS security information."
  );

  const ssl = scan.ssl || {};
  const sslEntries = Object.entries(ssl);

  if (sslEntries.length > 0) {
    sslEntries.forEach(([key, value]) => {
      addKeyValue(key, formatValue(value));
    });
  } else {
    addWrappedText("No SSL/TLS data available.");
  }

  // =========================================================
  // COOKIES
  // =========================================================

  addSectionTitle(
    "Cookie Analysis",
    "Cookie attributes recorded during the assessment."
  );

  const cookies = scan.cookies || {};
  const cookieEntries = Object.entries(cookies).filter(
    ([, value]) =>
      value &&
      typeof value === "object" &&
      !Array.isArray(value)
  );

  if (cookieEntries.length > 0) {
    cookieEntries.forEach(([cookieName, details]) => {
      addPageIfNeeded(20);

      doc.setFillColor(248, 250, 252);
      doc.roundedRect(
        margin,
        y - 4,
        contentWidth,
        16,
        2,
        2,
        "F"
      );

      doc.setTextColor(...colors.text);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.text(cookieName, margin + 4, y + 1);

      const flags = [
        `Secure: ${
          details.Secure ? "Yes" : "No"
        }`,
        `HttpOnly: ${
          details.HttpOnly ? "Yes" : "No"
        }`,
        `SameSite: ${
          details.SameSite || "Missing"
        }`,
      ];

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);
      doc.setTextColor(...colors.muted);
      doc.text(flags.join("   "), margin + 4, y + 8);

      y += 21;
    });
  } else {
    addWrappedText(
      Object.keys(cookies).length
        ? formatValue(cookies)
        : "No cookie data available."
    );
  }

  // =========================================================
  // NETWORK PORTS
  // =========================================================

  addSectionTitle(
   "Network / Service Enumeration",
  "Host-level TCP/service observations identified during network enumeration. These results are not by themselves evidence of web application vulnerabilities."
);

  const rawPorts = scan.ports || {};
  const portMap =
    rawPorts.Ports && typeof rawPorts.Ports === "object"
      ? rawPorts.Ports
      : rawPorts;

  const portEntries = Object.entries(portMap).filter(
    ([, info]) =>
      info &&
      typeof info === "object" &&
      ("State" in info || "Service" in info)
  );

  if (portEntries.length > 0) {
    // Table header
    addPageIfNeeded(16);

    doc.setFillColor(...colors.navy);
    doc.roundedRect(
      margin,
      y - 5,
      contentWidth,
      10,
      2,
      2,
      "F"
    );

    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.text("PORT", margin + 5, y + 1);
    doc.text("STATE", margin + 50, y + 1);
    doc.text("SERVICE", margin + 92, y + 1);

    y += 12;

    portEntries.forEach(([port, info]) => {
      addPageIfNeeded(9);

      doc.setDrawColor(...colors.border);
      doc.line(margin, y + 3, pageWidth - margin, y + 3);

      doc.setTextColor(...colors.text);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.text(port, margin + 5, y);

      const state = info.State || "Unknown";
      doc.setTextColor(
        ...(state === "open" ? colors.green : colors.muted)
      );
      doc.text(state, margin + 50, y);

      doc.setTextColor(...colors.text);
      doc.setFont("helvetica", "normal");
      doc.text(
        String(info.Service || "Unknown"),
        margin + 92,
        y
      );

      y += 8;
    });
  } else {
    addWrappedText("No network port data available.");
  }

// =========================================================
// XSS ANALYSIS
// =========================================================

addSectionTitle(
  "XSS Reflection Analysis",
  "Controlled reflection testing performed against discovered parameters."
);

const xss = scan.xss || {};

addKeyValue(
  "Parameters Tested",
  Array.isArray(xss.tested_parameters)
    ? xss.tested_parameters.length
    : 0
);

addKeyValue(
  "Reflections Detected",
  Array.isArray(xss.reflections)
    ? xss.reflections.length
    : 0
);

addKeyValue(
  "XSS Findings",
  Array.isArray(xss.findings)
    ? xss.findings.length
    : 0
);

if (Array.isArray(xss.findings) && xss.findings.length > 0) {
  xss.findings.forEach((finding, index) => {
    addWrappedText(
      `${index + 1}. ${finding.title || "Potential Reflected XSS Sink"}`,
      { bold: true }
    );

    addKeyValue("Severity", finding.severity || "Info");
    addKeyValue("Confidence", finding.confidence || "N/A");
    addKeyValue("Endpoint", finding.endpoint || "N/A");
    addKeyValue("Parameter", finding.parameter || "N/A");
    addKeyValue("Context", finding.context || "N/A");
  });
} else {
  addWrappedText(
    "No reflected XSS evidence was identified in the tested parameters."
  );
}


// =========================================================
// SQL INJECTION ANALYSIS
// =========================================================

addSectionTitle(
  "SQL Injection Analysis",
  "Controlled input-differential and database error analysis performed against discovered parameters."
);

const sqli = scan.sqli || {};

addKeyValue(
  "Parameters Tested",
  Array.isArray(sqli.tested_parameters)
    ? sqli.tested_parameters.length
    : 0
);

addKeyValue(
  "Evidence Items",
  Array.isArray(sqli.evidence)
    ? sqli.evidence.length
    : 0
);

addKeyValue(
  "SQLi Findings",
  Array.isArray(sqli.findings)
    ? sqli.findings.length
    : 0
);

if (Array.isArray(sqli.findings) && sqli.findings.length > 0) {
  sqli.findings.forEach((finding, index) => {
    addWrappedText(
      `${index + 1}. ${finding.title || "Potential SQL Injection"}`,
      { bold: true }
    );

    addKeyValue("Severity", finding.severity || "Info");
    addKeyValue("Confidence", finding.confidence || "N/A");
    addKeyValue("Endpoint", finding.endpoint || "N/A");
    addKeyValue("Parameter", finding.parameter || "N/A");
  });
} else {
  addWrappedText(
    "No SQL injection evidence was identified in the tested parameters."
  );
}
  addSectionTitle(
  "Path Traversal Analysis",
  "Controlled path traversal testing performed against discovered parameters."
);

const pathTraversal = scan.path_traversal || {};

const pathTraversalTested = Array.isArray(
  pathTraversal.tested_parameters
)
  ? pathTraversal.tested_parameters
  : [];

const pathTraversalEvidence = Array.isArray(
  pathTraversal.evidence
)
  ? pathTraversal.evidence
  : [];

const pathTraversalFindings = Array.isArray(
  pathTraversal.findings
)
  ? pathTraversal.findings
  : [];

addKeyValue(
  "Parameters Tested",
  pathTraversalTested.length
);

addKeyValue(
  "Evidence Items",
  pathTraversalEvidence.length
);

addKeyValue(
  "Path Traversal Findings",
  pathTraversalFindings.length
);

if (pathTraversalFindings.length > 0) {
  pathTraversalFindings.forEach((finding, index) => {
    addKeyValue(
      "Finding",
      finding?.title || "Potential Path Traversal"
    );

    addKeyValue(
      "Severity",
      finding?.severity || "Unknown"
    );

    addKeyValue(
      "Confidence",
      finding?.confidence || "Unknown"
    );

    if (finding?.endpoint) {
      addKeyValue("Endpoint", finding.endpoint);
    }

    if (finding?.parameter) {
      addKeyValue("Parameter", finding.parameter);
    }

    if (finding?.cwe) {
      addKeyValue("CWE", finding.cwe);
    }

    if (index < pathTraversalFindings.length - 1) {
      y += 3;
    }
  });
} else {
  addWrappedText(
    "No path traversal evidence was identified in the tested parameters."
  );
}

  addSectionTitle(
  "Open Redirect Analysis",
  "Controlled open redirect testing performed against discovered parameters."
);

const openRedirect = scan.open_redirect || {};

const openRedirectTested = Array.isArray(
  openRedirect.tested_parameters
)
  ? openRedirect.tested_parameters
  : [];

const openRedirectEvidence = Array.isArray(
  openRedirect.evidence
)
  ? openRedirect.evidence
  : [];

const openRedirectFindings = Array.isArray(
  openRedirect.findings
)
  ? openRedirect.findings
  : [];

addKeyValue(
  "Parameters Tested",
  openRedirectTested.length
);

addKeyValue(
  "Evidence Items",
  openRedirectEvidence.length
);

addKeyValue(
  "Open Redirect Findings",
  openRedirectFindings.length
);

if (openRedirectFindings.length > 0) {
  openRedirectFindings.forEach((finding, index) => {
    addKeyValue(
      "Finding",
      finding?.title || "Potential Open Redirect"
    );

    addKeyValue(
      "Severity",
      finding?.severity || "Unknown"
    );

    addKeyValue(
      "Confidence",
      finding?.confidence || "Unknown"
    );

    if (finding?.endpoint) {
      addKeyValue("Endpoint", finding.endpoint);
    }

    if (finding?.parameter) {
      addKeyValue("Parameter", finding.parameter);
    }

    if (finding?.cwe) {
      addKeyValue("CWE", finding.cwe);
    }

    if (index < openRedirectFindings.length - 1) {
      y += 3;
    }
  });
} else {
  addWrappedText(
    "No open redirect evidence was identified in the tested parameters."
  );
}

  // =========================================================
  // METHODOLOGY
  // =========================================================

  addSectionTitle(
    "Assessment Methodology",
    "How VulnHawk structures the automated assessment."
  );

  addWrappedText(
    "VulnHawk uses a rule-based vulnerability detection approach combined with signature-based analysis and evidence-oriented active testing. The assessment includes HTTP/HTTPS discovery, same-origin web crawling, endpoint and parameter discovery, security-header analysis, SSL/TLS inspection, technology detection, robots.txt and sitemap analysis, cookie security inspection, network/service enumeration, reflected XSS analysis, SQL injection analysis, path traversal analysis, open redirect analysis, and evidence-based security scoring."
  );

  addWrappedText(
    "Active web tests use controlled test inputs against discovered endpoints and parameters. Findings are recorded only when the scanner observes relevant response evidence. Results depend on target accessibility, application behavior, authentication state, network conditions, scanner configuration, and the modules enabled for the assessment."
);

  // =========================================================
  // CONCLUSION
  // =========================================================

  addSectionTitle(
    "Assessment Conclusion",
    "Summary of the recorded scan."
  );

  doc.setFillColor(...colors.blueLight);
  doc.roundedRect(
    margin,
    y - 4,
    contentWidth,
    30,
    3,
    3,
    "F"
  );

  doc.setTextColor(...colors.text);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);

  const conclusion = `The assessment recorded a security score of ${score}/100 with ${vulnCount} finding(s). Review the documented findings, validate their applicability to the application, and apply remediation according to the application's architecture, security requirements, and deployment environment.`;

  const conclusionLines = doc.splitTextToSize(
    conclusion,
    contentWidth - 12
  );

  doc.text(conclusionLines, margin + 6, y + 6);
  y += Math.max(35, conclusionLines.length * 4.5 + 12);

  // =========================================================
  // FOOTERS
  // =========================================================

  const pageCount = doc.internal.getNumberOfPages();

  for (let page = 1; page <= pageCount; page += 1) {
    doc.setPage(page);

    if (page > 1) {
      doc.setDrawColor(...colors.border);
      doc.line(
        margin,
        pageHeight - 15,
        pageWidth - margin,
        pageHeight - 15
      );

      doc.setTextColor(...colors.muted);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);

      doc.text(
        "VulnHawk Security Scanner",
        margin,
        pageHeight - 8
      );

      doc.text(
        `Page ${page} of ${pageCount}`,
        pageWidth - margin,
        pageHeight - 8,
        { align: "right" }
      );
    }
  }

  const safeTarget = String(scan.target || "target")
    .replace(/^https?:\/\//, "")
    .replace(/[^a-zA-Z0-9.-]/g, "_");

  doc.save(`VulnHawk_Report_${safeTarget}.pdf`);
};

const getFindingDetails = (finding) => {
  const details = {
    "Missing Content-Security-Policy": {
      description:
        "The target is missing the Content-Security-Policy HTTP security header.",
      impact:
        "Without a suitable Content-Security-Policy, the application may have reduced protection against certain client-side injection attacks.",
      recommendation:
        "Configure an appropriate Content-Security-Policy header based on the application's required resources and trusted sources.",
    },

    "Missing Strict-Transport-Security": {
      description:
        "The target is missing the Strict-Transport-Security security header.",
      impact:
        "The browser may not be instructed to always use HTTPS for future connections to the target.",
      recommendation:
        "Configure the Strict-Transport-Security header with an appropriate max-age value and HTTPS configuration.",
    },

    "Missing X-Content-Type-Options": {
      description:
        "The target is missing the X-Content-Type-Options security header.",
      impact:
        "Browsers may have fewer restrictions against MIME type sniffing.",
      recommendation:
        "Configure X-Content-Type-Options with the value nosniff.",
    },

    "Missing X-Frame-Options": {
      description:
        "The target is missing the X-Frame-Options security header.",
      impact:
        "The application may have reduced protection against unwanted framing by other websites.",
      recommendation:
        "Configure an appropriate X-Frame-Options policy such as SAMEORIGIN where applicable.",
    },

    "Missing Referrer-Policy": {
      description:
        "The target is missing the Referrer-Policy security header.",
      impact:
        "More referrer information than necessary may potentially be exposed when navigating from the application.",
      recommendation:
        "Configure a Referrer-Policy appropriate for the application's privacy and functionality requirements.",
    },

    "Missing Permissions-Policy": {
      description:
        "The target is missing the Permissions-Policy security header.",
      impact:
        "The application does not explicitly define browser feature permissions through this header.",
      recommendation:
        "Configure Permissions-Policy to restrict browser features that the application does not require.",
    },
  };

  return (
    details[finding.title] || {
      description: "VulnHawk detected a security configuration finding.",
      impact:
        "The detected condition may affect the security posture of the target.",
      recommendation:
        "Review the affected configuration and apply an appropriate security control.",
    }
  );
};
  return (
    <div className="scans-page">

      {/* PAGE HEADER */}
      <div className="page-title-row">
        <div>
          <h1>Scan History</h1>
          <p>View and manage VulnHawk security assessments</p>
        </div>

        <div className="scan-count">
          <Radar size={18} />
          {scans.length} Scan{scans.length !== 1 ? "s" : ""}
        </div>
      </div>

      {/* SEARCH */}
      <div className="scan-search">
        <Search size={18} />

        <input
          type="text"
          placeholder="Search target..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* SCAN SUMMARY */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
          gap: "14px",
          marginBottom: "18px",
        }}
      >
        {[
          ["Total Scans", scans.length, "All recorded assessments"],
          ["Completed", completedScans, "Successfully completed"],
          ["Findings", totalVulnerabilities, "Across all scans"],
          ["Average Score", `${averageScore}/100`, "Across recorded scans"],
        ].map(([label, value, description]) => (
          <div
            key={label}
            style={{
              background: "#ffffff",
              border: "1px solid #e5e7eb",
              borderRadius: "14px",
              padding: "17px",
              boxShadow: "0 3px 12px rgba(15,23,42,0.04)",
            }}
          >
            <span
              style={{
                display: "block",
                fontSize: "11px",
                fontWeight: 700,
                color: "#64748b",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              {label}
            </span>
            <strong
              style={{
                display: "block",
                marginTop: "7px",
                fontSize: "24px",
                color: "#0f172a",
              }}
            >
              {value}
            </strong>
            <span
              style={{
                display: "block",
                marginTop: "4px",
                fontSize: "11px",
                color: "#94a3b8",
              }}
            >
              {description}
            </span>
          </div>
        ))}
      </div>

      {/* FILTERS */}
      <div
        style={{
          display: "flex",
          gap: "10px",
          alignItems: "center",
          flexWrap: "wrap",
          marginBottom: "16px",
        }}
      >
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{
            padding: "10px 13px",
            border: "1px solid #dbe3ef",
            borderRadius: "10px",
            background: "#ffffff",
            color: "#334155",
            outline: "none",
          }}
        >
          <option value="All">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{
            padding: "10px 13px",
            border: "1px solid #dbe3ef",
            borderRadius: "10px",
            background: "#ffffff",
            color: "#334155",
            outline: "none",
          }}
        >
          <option value="All">All Statuses</option>
          <option value="Completed">Completed</option>
        </select>

        {(search || severityFilter !== "All" || statusFilter !== "All") && (
          <button
            onClick={() => {
              setSearch("");
              setSeverityFilter("All");
              setStatusFilter("All");
            }}
            style={{
              border: "none",
              background: "#f1f5f9",
              color: "#475569",
              borderRadius: "10px",
              padding: "10px 13px",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            Clear Filters
          </button>
        )}

        <span
          style={{
            marginLeft: "auto",
            fontSize: "12px",
            color: "#64748b",
          }}
        >
          Showing {filteredScans.length} of {scans.length} scans
        </span>
      </div>

      {/* SCAN TABLE */}
      <div className="scan-history-card">

        <div className="scan-table-header">
          <span>Target</span>
          <span>Score</span>
          <span>Vulnerabilities</span>
          <span>Status</span>
          <span>Date</span>
          <span>Action</span>
        </div>

        {filteredScans.length > 0 ? (

          filteredScans.map((scan, index) => (

            <div className="scan-history-row" key={index}>

              {/* TARGET */}
              <div className="target-cell">
                <Radar size={18} />

                <strong>{scan.target}</strong>
              </div>

              {/* SCORE */}
              <div>
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
              </div>

              {/* VULNERABILITIES */}
              <div className="vulnerability-cell">
                <ShieldAlert size={16} />
                {scan.vulnerabilities}
                {scan.vulnerabilities > 0 && (
                  <span
                    style={{
                      marginLeft: "6px",
                      fontSize: "10px",
                      color: "#64748b",
                    }}
                  >
                    findings
                  </span>
                )}
              </div>

              {/* STATUS */}
              <div>
                <span className="scan-status completed">
                  <CheckCircle size={14} />
                  {scan.status}
                </span>
              </div>

              {/* DATE */}
              <div className="date-cell">
                {scan.date}
              </div>

              {/* VIEW */}
              <div>
                <button
                  className="view-scan-button"
                  onClick={() => setSelectedScan(scan)}
                >
                  <Eye size={15} />
                  View
                </button>
              </div>

            </div>
          ))

        ) : (

          <div className="empty-scan-history">
            <Radar size={35} />

            <h3>No scan history</h3>

            <p>
              Run your first security scan to see it here.
            </p>
          </div>

        )}

      </div>

      {/* ================================
          SCAN DETAILS MODAL
      ================================= */}

      {selectedScan && (

        <div
          className="scan-details-overlay"
          onClick={() => setSelectedScan(null)}
        >

          <div
            className="scan-details-modal"
            onClick={(e) => e.stopPropagation()}
          >

            {/* HEADER */}

            <div className="scan-details-header">

              <div>
                <h2>Scan Details</h2>

                <p>
                  Security assessment results
                </p>
              </div>

              <button
                className="generate-report-button"
      onClick={() => generatePDFReport(selectedScan)}
    >
      <FileSearch size={16} />
      Generate PDF
              </button>

<button
      className="details-close-button"
      onClick={() => setSelectedScan(null)}
    >
      <X size={20} />
    </button>
            </div>

            {/* TARGET */}

            <div className="details-target-card">

              <Radar size={22} />

              <div>
                <span>Target</span>

                <strong>
                  {selectedScan.target}
                </strong>

                <small
                  style={{
                    display: "block",
                    marginTop: "5px",
                    color: "#64748b",
                  }}
                >
                  Recorded by VulnHawk during this assessment
                </small>
              </div>

            </div>

            {/* SUMMARY */}

            <div className="details-summary-grid">

              <div className="detail-stat">

                <span>Security Score</span>

                <strong className="detail-score">
                  {selectedScan.score}/100
                </strong>
                <small
                  style={{
                    display: "block",
                    marginTop: "4px",
                    color: "#64748b",
                  }}
                >
                  {selectedScan.score >= 90
                    ? "Excellent"
                    : selectedScan.score >= 75
                    ? "Good"
                    : selectedScan.score >= 50
                    ? "Moderate"
                    : selectedScan.score >= 25
                    ? "Poor"
                    : "Critical"}
                </small>

              </div>

              <div className="detail-stat">

                <span>Vulnerabilities</span>

                <strong className="detail-vulnerability">
                  {selectedScan.vulnerabilities}
                </strong>

              </div>

              <div className="detail-stat">

                <span>Status</span>

                <strong className="detail-completed">
                  <CheckCircle size={16} />
                  {selectedScan.status}
                </strong>

              </div>

              <div className="detail-stat">

                <span>Scan Date</span>

                <strong className="detail-date">
                  {selectedScan.date}
                </strong>

              </div>

            </div>

            {/* VULNERABILITIES */}

            <div className="details-section">

              <div className="details-section-title">
                <ShieldAlert size={19} />
                <h3>Vulnerabilities</h3>
              </div>

              {selectedScan.findings &&
              selectedScan.findings.length > 0 ? (

                <div className="findings-list">

                  {selectedScan.findings.map(
                    (finding, index) => (

                      <div
                         className="finding-item"
  key={index}
  onClick={() => setSelectedFinding(finding)}
  style={{ cursor: "pointer" }}
                      >

                        <div className="finding-number">
                          {index + 1}
                        </div>

                        <div className="finding-content">

                          <strong>
                            {typeof finding === "string"
                              ? finding
                              : finding.title ||
                                finding.name ||
                                finding.issue ||
                                "Security Finding"}
                          </strong>

                          {typeof finding !== "string" &&
                            finding.description && (
                              <p>
                                {finding.description}
                              </p>
                            )}

                          {typeof finding !== "string" && (
                            <div
                              style={{
                                display: "flex",
                                gap: "8px",
                                alignItems: "center",
                                marginTop: "8px",
                                flexWrap: "wrap",
                              }}
                            >
                              <span
                                className={`finding-severity ${
                                  (finding.severity || "Info").toLowerCase()
                                }`}
                              >
                                {finding.severity || "Info"}
                              </span>

                              <span
                                style={{
                                  fontSize: "11px",
                                  color: "#64748b",
                                  fontWeight: 600,
                                }}
                              >
                                {finding.category || "Security"}
                              </span>
                            </div>
                          )}

                        </div>

                      </div>

                    )
                  )}

                </div>

              ) : (

                <div className="no-findings">
                  <CheckCircle size={20} />
                  No vulnerabilities detected.
                </div>

              )}

            </div>

            {/* TECHNICAL RESULTS */}

            <div className="technical-results">

              {/* HEADERS */}

              <div className="technical-card">

                <div className="technical-card-header">
                  <Globe size={18} />
                  <strong>Security Headers</strong>
                </div>

                <div className="technical-card-body">

                  {Object.keys(
                    selectedScan.headers || {}
                  ).length > 0 ? (

                    Object.entries(
                      selectedScan.headers
                    ).map(([key, value]) => (

                      <div
                        className="technical-row"
                        key={key}
                      >

                        <span>{key}</span>

                        <strong>
                          {String(value)}
                        </strong>

                      </div>

                    ))

                  ) : (
                    <p>No header data available.</p>
                  )}

                </div>

              </div>

              {/* PORTS */}

              <div className="technical-card">

                <div className="technical-card-header">
                  <Server size={18} />
                  <strong>Open Ports</strong>
                </div>

                <div className="technical-card-body">

                  {getPortEntries(selectedScan.ports).length > 0 ? (
                    getPortEntries(selectedScan.ports).map(
                      ([port, info]) => (
                        <div
                          className="technical-row"
                          key={port}
                        >
                          <span>
                            <strong>{port}</strong>
                            <small
                              style={{
                                display: "block",
                                marginTop: "4px",
                                color: "#94a3b8",
                              }}
                            >
                              {info.Service || "Unknown service"}
                            </small>
                          </span>

                          <strong
                            style={{
                              color:
                                info.State === "open"
                                  ? "#15803d"
                                  : "#64748b",
                            }}
                          >
                            {info.State || "Unknown"}
                          </strong>
                        </div>
                      )
                    )
                  ) : (
                    <p>No port data available.</p>
                  )}

                </div>

              </div>

              {/* TECHNOLOGIES */}

              <div className="technical-card">

                <div className="technical-card-header">
                  <FileSearch size={18} />
                  <strong>Technologies</strong>
                </div>

                <div className="technical-card-body">

                  {Object.keys(
                    selectedScan.technologies || {}
                  ).length > 0 ? (

                    Object.entries(
                      selectedScan.technologies
                    ).map(([key, value]) => (

                      <div
                        className="technical-row"
                        key={key}
                      >

                        <span>{key}</span>

                        <strong>
                          {typeof value === "object"
                            ? JSON.stringify(value)
                            : String(value)}
                        </strong>

                      </div>

                    ))

                  ) : (
                    <p>No technology data available.</p>
                  )}

                </div>

              </div>

              {/* SSL */}

              <div className="technical-card">

                <div className="technical-card-header">
                  <Lock size={18} />
                  <strong>SSL / TLS</strong>
                </div>

                <div className="technical-card-body">

                  {Object.keys(selectedScan.ssl || {}).length > 0 ? (
                    Object.entries(selectedScan.ssl).map(
                      ([key, value]) => (
                        <div
                          className="technical-row"
                          key={key}
                        >
                          <span>{key}</span>

                          <strong
                            style={{
                              maxWidth: "68%",
                              textAlign: "right",
                              lineHeight: 1.5,
                            }}
                          >
                            {formatValue(value)}
                          </strong>
                        </div>
                      )
                    )
                  ) : (
                    <p>No SSL/TLS data available.</p>
                  )}

                </div>

              </div>

              {/* COOKIES */}

              <div className="technical-card">

                <div className="technical-card-header">
                  <Cookie size={18} />
                  <strong>Cookies</strong>
                </div>

                <div className="technical-card-body">

                  {getCookieEntries(selectedScan.cookies).length > 0 ? (
                    getCookieEntries(selectedScan.cookies).map(
                      ([cookieName, details]) => (
                        <div
                          key={cookieName}
                          style={{
                            padding: "12px 0",
                            borderBottom: "1px solid #eef2f7",
                          }}
                        >
                          <strong
                            style={{
                              display: "block",
                              color: "#0f172a",
                              marginBottom: "8px",
                            }}
                          >
                            {cookieName}
                          </strong>

                          <div
                            style={{
                              display: "flex",
                              gap: "8px",
                              flexWrap: "wrap",
                            }}
                          >
                            {[
                              ["Secure", details.Secure],
                              ["HttpOnly", details.HttpOnly],
                              ["SameSite", details.SameSite],
                            ].map(([label, value]) => (
                              <span
                                key={label}
                                style={{
                                  padding: "5px 8px",
                                  borderRadius: "7px",
                                  fontSize: "11px",
                                  fontWeight: 700,
                                  background:
                                    value === true ||
                                    (label === "SameSite" &&
                                      value &&
                                      value !== "Missing")
                                      ? "#ecfdf5"
                                      : "#fff7ed",
                                  color:
                                    value === true ||
                                    (label === "SameSite" &&
                                      value &&
                                      value !== "Missing")
                                      ? "#15803d"
                                      : "#c2410c",
                                }}
                              >
                                {label}:{" "}
                                {value === true
                                  ? "Yes"
                                  : value || "Missing"}
                              </span>
                            ))}
                          </div>
                        </div>
                      )
                    )
                  ) : (
                    <p>No cookie data available.</p>
                  )}

                </div>

              </div>

            </div>

          </div>

        </div>

      )}
      {/* =====================================
          VULNERABILITY DETAIL MODAL
      ====================================== */}

      {selectedFinding && (
        <div
          className="finding-details-overlay"
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="finding-details-modal"
            onClick={(e) => e.stopPropagation()}
          >

            <div className="finding-details-header">

              <div>
                <h2>{selectedFinding.title}</h2>

                <p>
                  Detailed vulnerability information
                </p>
              </div>

              <button
                className="details-close-button"
                onClick={() => setSelectedFinding(null)}
              >
                <X size={20} />
              </button>

            </div>

            <div className="finding-meta">

              <div>
                <span>Severity</span>

                <strong
                  className={`finding-severity ${selectedFinding.severity.toLowerCase()}`}
                >
                  {selectedFinding.severity}
                </strong>
              </div>

              <div>
                <span>Category</span>

                <strong>
                  {selectedFinding.category}
                </strong>
              </div>

            </div>

            <div className="finding-detail-section">

              <h3>Description</h3>

              <p>
                {getFindingDetails(selectedFinding).description}
              </p>

            </div>

            <div className="finding-detail-section">

              <h3>Impact</h3>

              <p>
                {getFindingDetails(selectedFinding).impact}
              </p>

            </div>

            <div className="finding-detail-section">

              <h3>Recommendation</h3>

              <p>
                {getFindingDetails(selectedFinding).recommendation}
              </p>

            </div>

            <div className="finding-detected-by">

              <ShieldAlert size={18} />

              <div>
                <span>Detected by</span>
                <strong>VulnHawk Security Scanner</strong>
              </div>

            </div>

          </div>
        </div>
      )}
    </div>
  );
}

export default ScansPage;