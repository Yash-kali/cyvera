import axios from 'axios';

// Base API URL configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request Interceptor: Attach JWT Token from localStorage if present
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('autopentest_jwt_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Custom event to signal authentication failure across the application
export const AUTH_EXPIRED_EVENT = 'autopentest_auth_expired';

// Response Interceptor: Catch 401 Unauthorized errors and trigger auto-logout
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      console.warn('Authentication token expired or invalid. Triggering logout...');
      localStorage.removeItem('autopentest_jwt_token');
      localStorage.removeItem('autopentest_user_data');
      window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
    }
    return Promise.reject(error);
  }
);
