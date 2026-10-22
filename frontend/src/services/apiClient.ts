import axios from 'axios';
import type { BackendHealthResponse } from '../types/scan';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export async function checkBackendHealth(): Promise<{ online: boolean; details?: BackendHealthResponse }> {
  try {
    const res = await apiClient.get<BackendHealthResponse>('/health', { timeout: 3000 });
    return { online: true, details: res.data };
  } catch (err) {
    return { online: false };
  }
}

