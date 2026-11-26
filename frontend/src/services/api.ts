import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value?: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Request Interceptor: Attach JWT Bearer Token
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('securecode_access_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Handle Refresh Token Rotation and Format Errors
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError<{ message?: string; error_code?: string }>) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // Automatic token refresh on 401 (if not already retried and not on auth endpoints)
    if (
      error.response?.status === 401 &&
      originalRequest &&
      !originalRequest._retry &&
      !originalRequest.url?.includes('/auth/')
    ) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            if (originalRequest.headers && token) {
              originalRequest.headers.Authorization = `Bearer ${token}`;
            }
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const storedRefreshToken = localStorage.getItem('securecode_refresh_token');
      if (!storedRefreshToken) {
        isRefreshing = false;
        const authErr = new Error('Authentication required. Please sign in to continue.');
        processQueue(authErr, null);
        localStorage.removeItem('securecode_access_token');
        localStorage.removeItem('securecode_user');
        window.dispatchEvent(new Event('securecode:session-expired'));
        return Promise.reject(authErr);
      }

      try {
        const refreshRes = await axios.post<{
          success: boolean;
          data: { access_token: string; refresh_token?: string };
        }>(`${API_BASE_URL}/api/v1/auth/refresh`, {
          refresh_token: storedRefreshToken,
        });

        const newAccessToken = refreshRes.data.data.access_token;
        localStorage.setItem('securecode_access_token', newAccessToken);
        if (refreshRes.data.data.refresh_token) {
          localStorage.setItem('securecode_refresh_token', refreshRes.data.data.refresh_token);
        }

        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        }

        processQueue(null, newAccessToken);
        return api(originalRequest);
      } catch (refreshErr) {
        processQueue(refreshErr, null);
        localStorage.removeItem('securecode_access_token');
        localStorage.removeItem('securecode_refresh_token');
        localStorage.removeItem('securecode_user');
        window.dispatchEvent(new Event('securecode:session-expired'));
        return Promise.reject(refreshErr);
      } finally {
        isRefreshing = false;
      }
    }

    // Format human-friendly error messages
    const status = error.response?.status;
    let message = error.response?.data?.message || error.message;

    if (status === 400) {
      message = message || 'Bad Request: Please check your input parameters.';
    } else if (status === 401) {
      message = 'Authentication required. Please sign in to continue.';
    } else if (status === 403) {
      message = 'Forbidden: You do not have permission to perform this action.';
    } else if (status === 404) {
      message = 'The requested resource was not found.';
    } else if (status === 422) {
      message = message || 'Validation Error: Invalid data format.';
    } else if (status === 429) {
      message = 'Rate limit exceeded: Too many requests. Please try again shortly.';
    } else if (status && status >= 500) {
      message = 'Internal server error: The security engine encountered an issue.';
    }

    return Promise.reject(new Error(message));
  }
);

export default api;
