import jsPDF from 'jspdf';
import type { ScanResult } from '../types/scan';

export function exportJsonReport(scan: ScanResult): void {
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scan, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', dataStr);
  downloadAnchor.setAttribute('download', `SecureCode_Report_${scan.id}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

export function exportCsvReport(scan: ScanResult): void {
  const headers = ['ID', 'Title', 'Category', 'Severity', 'CWE', 'OWASP', 'File', 'Line', 'Validation Status', 'Description'];
  const rows = scan.findings.map(f => [
    `"${f.id}"`,
    `"${f.title.replace(/"/g, '""')}"`,
    `"${f.category}"`,
    `"${f.severity}"`,
    `"${f.cwe}"`,
    `"${f.owaspCategory}"`,
    `"${f.file}"`,
    `"${f.startLine}"`,
    `"${f.validationStatus}"`,
    `"${f.description.replace(/"/g, '""')}"`
  ]);

  const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
  const encodedUri = encodeURI(csvContent);
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', encodedUri);
  downloadAnchor.setAttribute('download', `SecureCode_Findings_${scan.id}.csv`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

export function generatePdfReport(scan: ScanResult): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 20;

  // Title Banner
  doc.setFillColor(11, 16, 32); // #0B1020
  doc.rect(0, 0, pageWidth, 42, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.text('SecureCode AI — Security Audit Report', 15, 18);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184); // Slate 400
  doc.text('AI-Driven Code Security Vulnerability Detection & Remediation System', 15, 26);
  doc.text(`Generated: ${new Date().toUTCString()}  |  Scan ID: ${scan.id}`, 15, 33);

  y = 52;

  // Metadata Section
  doc.setTextColor(30, 41, 59);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.text('1. Scan Metadata & Execution Summary', 15, y);
  y += 7;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);

  const metaData = [
    `Project Name: ${scan.projectName}`,
    `Target File: ${scan.fileName}`,
    `Language: ${scan.language.toUpperCase()}`,
    `Lines Analyzed: ${scan.linesAnalyzed}`,
    `Duration: ${scan.durationMs}ms`,
    `Scan Status: ${scan.status}`
  ];

  metaData.forEach((item, idx) => {
    const col = idx % 2 === 0 ? 15 : 110;
    const rowY = y + Math.floor(idx / 2) * 6;
    doc.text(item, col, rowY);
  });

  y += 24;

  // Severity Summary Box
  doc.setDrawColor(226, 232, 240);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(15, y, pageWidth - 30, 22, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text('Total Findings:', 20, y + 8);
  doc.text(`${scan.findingsCount.total}`, 52, y + 8);

  doc.setTextColor(239, 68, 68); // Critical Red
  doc.text(`Critical: ${scan.findingsCount.critical}`, 75, y + 8);

  doc.setTextColor(249, 115, 22); // High Orange
  doc.text(`High: ${scan.findingsCount.high}`, 110, y + 8);

  doc.setTextColor(245, 158, 11); // Medium Amber
  doc.text(`Medium: ${scan.findingsCount.medium}`, 145, y + 8);

  doc.setTextColor(16, 185, 129); // Low Green
  doc.text(`Low: ${scan.findingsCount.low}`, 178, y + 8);

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text(`Highest Severity Detected: ${scan.highestSeverity}`, 20, y + 16);

  y += 32;

  // Findings Section
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(30, 41, 59);
  doc.text('2. Identified Vulnerabilities & Remediation Actions', 15, y);
  y += 8;

  if (scan.findings.length === 0) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139);
    doc.text('Zero vulnerabilities detected during this static security pass.', 15, y);
    y += 10;
  } else {
    scan.findings.forEach((finding, index) => {
      // Check page overflow
      if (y > 240) {
        doc.addPage();
        y = 20;
      }

      // Finding Header
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42);
      doc.text(`${index + 1}. [${finding.severity}] ${finding.title}`, 15, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(`Location: ${finding.file}:${finding.startLine}  |  CWE: ${finding.cwe}  |  OWASP: ${finding.owaspCategory}`, 15, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      const descLines = doc.splitTextToSize(`Description: ${finding.description}`, pageWidth - 30);
      doc.text(descLines, 15, y);
      y += descLines.length * 4;

      if (finding.evidence) {
        doc.setTextColor(185, 28, 28);
        const evLines = doc.splitTextToSize(`Evidence: ${finding.evidence}`, pageWidth - 30);
        doc.text(evLines, 15, y);
        y += evLines.length * 4;
      }

      doc.setTextColor(15, 118, 110);
      const fixLines = doc.splitTextToSize(`Remediation: ${finding.remediationCode}`, pageWidth - 30);
      doc.text(fixLines, 15, y);
      y += fixLines.length * 4 + 4;
    });
  }

  // Footer / Disclaimer
  if (y > 250) {
    doc.addPage();
    y = 20;
  }
  y += 6;
  doc.setDrawColor(203, 213, 225);
  doc.line(15, y, pageWidth - 15, y);
  y += 7;

  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'italic');
  doc.setTextColor(148, 163, 184);
  doc.text('Note: This security report is produced by SecureCode AI (Hybrid AST & Pattern Analysis).', 15, y);
  doc.text('Automated security findings should be reviewed and validated by security engineers prior to production deployment.', 15, y + 4);

  // Trigger Save
  doc.save(`SecureCode_Report_${scan.id}.pdf`);
}
