import { api } from './api';
import type { UserProfile, AuthResponseData, LoginRequest, RegisterRequest, ApiResponse } from '../types/auth';

export class AuthService {
  static async login(credentials: LoginRequest): Promise<UserProfile> {
    const res = await api.post<ApiResponse<AuthResponseData>>('/api/v1/auth/login', credentials);
    const data = res.data.data;
    localStorage.setItem('securecode_access_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('securecode_refresh_token', data.refresh_token);
    }
    localStorage.setItem('securecode_user', JSON.stringify(data.user));
    return data.user;
  }

  static async register(data: RegisterRequest): Promise<UserProfile> {
    const res = await api.post<ApiResponse<AuthResponseData>>('/api/v1/auth/register', {
      name: data.name,
      email: data.email,
      password: data.password,
    });
    const payload = res.data.data;
    localStorage.setItem('securecode_access_token', payload.access_token);
    if (payload.refresh_token) {
      localStorage.setItem('securecode_refresh_token', payload.refresh_token);
    }
    localStorage.setItem('securecode_user', JSON.stringify(payload.user));
    return payload.user;
  }

  static async logout(): Promise<void> {
    const refreshToken = localStorage.getItem('securecode_refresh_token');
    if (refreshToken) {
      try {
        await api.post('/api/v1/auth/logout', { refresh_token: refreshToken });
      } catch {
        // Ignore network errors on logout
      }
    }
    localStorage.removeItem('securecode_access_token');
    localStorage.removeItem('securecode_refresh_token');
    localStorage.removeItem('securecode_user');
  }

  static async getCurrentUser(): Promise<UserProfile | null> {
    if (!this.isAuthenticated()) return null;
    try {
      const res = await api.get<ApiResponse<UserProfile>>('/api/v1/auth/me');
      const user = res.data.data;
      localStorage.setItem('securecode_user', JSON.stringify(user));
      return user;
    } catch {
      return this.getStoredUser();
    }
  }

  static getStoredUser(): UserProfile | null {
    try {
      const raw = localStorage.getItem('securecode_user');
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  static isAuthenticated(): boolean {
    const token = localStorage.getItem('securecode_access_token');
    if (!token) return false;
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
        const payload = JSON.parse(payloadJson);
        if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) {
          // Expired access token: remain eligible only if a refresh token can renew it
          return !!localStorage.getItem('securecode_refresh_token');
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  static isAdmin(): boolean {
    const user = this.getStoredUser();
    return user?.role === 'ADMIN';
  }
}

export default AuthService;
