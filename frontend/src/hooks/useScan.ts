import { useState, useCallback } from 'react';
import { createScan, uploadFileScan, getScanById, deleteScan as apiDeleteScan } from '../services/scanService';
import type { ScanRequest, ScanResult } from '../types/scan';

export function useScan() {
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runScan = async (req: ScanRequest): Promise<ScanResult> => {
    setIsScanning(true);
    setError(null);
    try {
      const result = await createScan(req);
      setScanResult(result);
      return result;
    } catch (err: any) {
      const msg = err.response?.data?.message || err.message || 'Scan execution failed';
      setError(msg);
      throw err;
    } finally {
      setIsScanning(false);
    }
  };

  const runFileUploadScan = async (
    file: File,
    projectName: string = 'Uploaded Scan',
    language: string = 'python',
    projectId?: string
  ): Promise<ScanResult> => {
    setIsScanning(true);
    setError(null);
    try {
      const result = await uploadFileScan(file, projectName, language, projectId);
      setScanResult(result);
      return result;
    } catch (err: any) {
      const msg = err.response?.data?.message || err.message || 'File upload scan failed';
      setError(msg);
      throw err;
    } finally {
      setIsScanning(false);
    }
  };

  const loadScan = useCallback(async (scanId: string): Promise<ScanResult | null> => {
    setIsScanning(true);
    setError(null);
    try {
      const result = await getScanById(scanId);
      setScanResult(result);
      return result;
    } catch (err: any) {
      const msg = err.response?.data?.message || err.message || 'Failed to load scan';
      setError(msg);
      return null;
    } finally {
      setIsScanning(false);
    }
  }, []);

  const deleteScan = async (scanId: string): Promise<void> => {
    await apiDeleteScan(scanId);
    if (scanResult?.id === scanId) {
      setScanResult(null);
    }
  };

  return {
    isScanning,
    scanResult,
    error,
    runScan,
    runFileUploadScan,
    loadScan,
    deleteScan,
  };
}

export default useScan;
