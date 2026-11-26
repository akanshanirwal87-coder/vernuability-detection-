import { api } from './api';
import { AuthService } from './authService';
import type { BackendHealthResponse } from '../types/scan';
import type { UserProfile, AuthResponseData } from '../types/auth';

// Re-export unified Axios instance (with refresh-token rotation & 401 handling)
export const apiClient = api;
export type { UserProfile, AuthResponseData };

export async function checkBackendHealth(): Promise<{ online: boolean; details?: BackendHealthResponse }> {
  try {
    const res = await apiClient.get<BackendHealthResponse>('/health', { timeout: 3000 });
    return { online: true, details: res.data };
  } catch {
    return { online: false };
  }
}

export async function loginUser(email: string, password: string): Promise<UserProfile> {
  return AuthService.login({ email, password });
}

export async function registerUser(name: string, email: string, password: string): Promise<UserProfile> {
  return AuthService.register({ name, email, password });
}

export async function logoutUser(): Promise<void> {
  return AuthService.logout();
}

export function getStoredUser(): UserProfile | null {
  return AuthService.getStoredUser();
}

export function isAuthenticated(): boolean {
  return AuthService.isAuthenticated();
}
