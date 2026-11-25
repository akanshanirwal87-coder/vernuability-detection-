import { useState, useCallback, useRef } from 'react';
import { 
  createScan, 
  uploadFileScan, 
  getScanById, 
  deleteScan as apiDeleteScan,
  enqueueRepositoryScan,
  getScanJobStatus,
  cancelScanJob,
  type ScanJobStatusResponse
} from '../services/scanService';
import type { ScanRequest, ScanResult } from '../types/scan';

export function useScan() {
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [activeJob, setActiveJob] = useState<ScanJobStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollingTimerRef = useRef<any>(null);

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

  const runRepositoryScan = async (data: {
    repositoryUrl: string;
    branch?: string;
    commitSha?: string;
    projectId?: string;
    githubToken?: string;
  }): Promise<ScanResult> => {
    setIsScanning(true);
    setError(null);
    setActiveJob(null);

    try {
      const queueRes = await enqueueRepositoryScan(data);
      const jobId = queueRes.jobId;

      return await new Promise<ScanResult>((resolve, reject) => {
        const checkStatus = async () => {
          try {
            const jobStatus = await getScanJobStatus(jobId);
            setActiveJob(jobStatus);

            if (jobStatus.status === 'COMPLETED') {
              if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
              const fullScan = await getScanById(jobStatus.scanId);
              if (fullScan) {
                setScanResult(fullScan);
                setIsScanning(false);
                resolve(fullScan);
              } else {
                setIsScanning(false);
                reject(new Error('Scan completed but details could not be retrieved.'));
              }
            } else if (jobStatus.status === 'FAILED') {
              if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
              setIsScanning(false);
              const err = jobStatus.errorMessage || 'Repository scan failed.';
              setError(err);
              reject(new Error(err));
            } else if (jobStatus.status === 'CANCELLED') {
              if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
              setIsScanning(false);
              reject(new Error('Scan was cancelled.'));
            }
          } catch (e: any) {
            // Transient network error during polling; continue polling
          }
        };

        // Poll every 1.5 seconds
        pollingTimerRef.current = setInterval(checkStatus, 1500);
        checkStatus();
      });
    } catch (err: any) {
      setIsScanning(false);
      const msg = err.response?.data?.message || err.message || 'Repository scan submission failed';
      setError(msg);
      throw err;
    }
  };

  const cancelJob = async (jobId: string): Promise<void> => {
    if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
    await cancelScanJob(jobId);
    setIsScanning(false);
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
    activeJob,
    error,
    runScan,
    runFileUploadScan,
    runRepositoryScan,
    cancelJob,
    loadScan,
    deleteScan,
  };
}

export default useScan;
