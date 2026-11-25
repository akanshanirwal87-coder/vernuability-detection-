import type { ScanResult } from '../types/scan';

export function downloadJson(data: unknown, filename: string): void {
  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function downloadUnifiedPatch(
  filename: string,
  originalCode: string,
  remediatedCode: string
): void {
  const patchHeader = `--- a/${filename}\n+++ b/${filename}\n@@ -1,${originalCode.split('\n').length} +1,${remediatedCode.split('\n').length} @@\n`;
  const originalLines = originalCode.split('\n').map((l) => `-${l}`).join('\n');
  const remediatedLines = remediatedCode.split('\n').map((l) => `+${l}`).join('\n');
  const patchContent = `${patchHeader}${originalLines}\n${remediatedLines}\n`;

  const blob = new Blob([patchContent], { type: 'text/x-diff' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${filename.replace(/\.[^/.]+$/, '')}.patch`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
