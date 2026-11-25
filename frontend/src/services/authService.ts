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
    const res = await api.post<ApiResponse<UserProfile>>('/api/v1/auth/register', {
      name: data.name,
      email: data.email,
      password: data.password,
    });
    // Automatically log in after registration
    return await this.login({ email: data.email, password: data.password });
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
    return !!localStorage.getItem('securecode_access_token');
  }

  static isAdmin(): boolean {
    const user = this.getStoredUser();
    return user?.role === 'ADMIN';
  }
}

export default AuthService;
