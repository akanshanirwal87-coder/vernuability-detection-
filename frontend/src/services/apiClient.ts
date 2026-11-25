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

// Attach Authorization Bearer token to all outgoing requests if stored
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('securecode_access_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export async function checkBackendHealth(): Promise<{ online: boolean; details?: BackendHealthResponse }> {
  try {
    const res = await apiClient.get<BackendHealthResponse>('/health', { timeout: 3000 });
    return { online: true, details: res.data };
  } catch (err) {
    return { online: false };
  }
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at?: string;
}

export interface AuthResponseData {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  user: UserProfile;
}

export async function loginUser(email: string, password: string): Promise<UserProfile> {
  const res = await apiClient.post<{ success: boolean; data: AuthResponseData }>('/api/v1/auth/login', { email, password });
  const data = res.data.data;
  localStorage.setItem('securecode_access_token', data.access_token);
  if (data.refresh_token) {
    localStorage.setItem('securecode_refresh_token', data.refresh_token);
  }
  localStorage.setItem('securecode_user', JSON.stringify(data.user));
  return data.user;
}

export async function registerUser(name: string, email: string, password: string): Promise<UserProfile> {
  const res = await apiClient.post<{ success: boolean; data: AuthResponseData }>('/api/v1/auth/register', { name, email, password });
  const data = res.data.data;
  localStorage.setItem('securecode_access_token', data.access_token);
  if (data.refresh_token) {
    localStorage.setItem('securecode_refresh_token', data.refresh_token);
  }
  localStorage.setItem('securecode_user', JSON.stringify(data.user));
  return data.user;
}

export async function logoutUser(): Promise<void> {
  const refreshToken = localStorage.getItem('securecode_refresh_token');
  if (refreshToken) {
    try {
      await apiClient.post('/api/v1/auth/logout', { refresh_token: refreshToken });
    } catch {
      // Ignore network errors on logout
    }
  }
  localStorage.removeItem('securecode_access_token');
  localStorage.removeItem('securecode_refresh_token');
  localStorage.removeItem('securecode_user');
}

export function getStoredUser(): UserProfile | null {
  try {
    const raw = localStorage.getItem('securecode_user');
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem('securecode_access_token');
}
