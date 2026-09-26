import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { jwtDecode } from 'jwt-decode';
import {
  User,
  LoginCredentials,
  RegisterCredentials,
  loginApi,
  registerApi,
  getCurrentUserApi
} from '../api/auth';
import { AUTH_EXPIRED_EVENT } from '../api/client';

interface JwtPayload {
  sub: string;
  user_id: number;
  email: string;
  exp: number;
  iat: number;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  loading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (credentials: RegisterCredentials) => Promise<void>;
  logout: () => void;
  tokenExpiresAt: number | null;
}

const TOKEN_KEY = 'autopentest_jwt_token';
const USER_KEY = 'autopentest_user_data';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<User | null>(() => {
    const savedUser = localStorage.getItem(USER_KEY);
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [tokenExpiresAt, setTokenExpiresAt] = useState<number | null>(null);

  const logout = useCallback(() => {
    console.log('Logging out user session...');
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken(null);
    setUser(null);
    setTokenExpiresAt(null);
  }, []);

  // Set up auto-logout timer based on JWT expiration
  const scheduleAutoLogout = useCallback((jwtToken: string) => {
    try {
      const decoded = jwtDecode<JwtPayload>(jwtToken);
      if (!decoded || !decoded.exp) return;

      const expiresAtMs = decoded.exp * 1000;
      setTokenExpiresAt(expiresAtMs);
      const currentTimeMs = Date.now();
      const timeRemaining = expiresAtMs - currentTimeMs;

      if (timeRemaining <= 0) {
        console.warn('Token has already expired. Logging out immediately...');
        logout();
      } else {
        console.log(`Auto-logout scheduled in ${Math.round(timeRemaining / 1000 / 60)} minutes.`);
        const timer = setTimeout(() => {
          console.warn('JWT Token expired. Auto-logging out user...');
          logout();
          alert('Session Expired: Your authentication token has expired. Please log in again.');
        }, timeRemaining);

        return () => clearTimeout(timer);
      }
    } catch (err) {
      console.error('Error decoding JWT token:', err);
      logout();
    }
  }, [logout]);

  // Initial Auth Check on app load
  useEffect(() => {
    let timerCleanup: (() => void) | undefined;

    const initializeAuth = async () => {
      const storedToken = localStorage.getItem(TOKEN_KEY);
      if (storedToken) {
        timerCleanup = scheduleAutoLogout(storedToken);
        try {
          // Verify session by fetching fresh user data from /api/v1/auth/me
          const freshUser = await getCurrentUserApi();
          setUser(freshUser);
          localStorage.setItem(USER_KEY, JSON.stringify(freshUser));
        } catch (err) {
          console.error('Failed to validate session token:', err);
          logout();
        }
      }
      setLoading(false);
    };

    initializeAuth();

    // Listen for global 401 unauthenticated events from Axios interceptor
    const handleAuthExpired = () => {
      logout();
    };

    window.addEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);

    return () => {
      if (timerCleanup) timerCleanup();
      window.removeEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
    };
  }, [scheduleAutoLogout, logout]);

  const login = async (credentials: LoginCredentials) => {
    setLoading(true);
    try {
      const response = await loginApi(credentials);
      localStorage.setItem(TOKEN_KEY, response.access_token);
      localStorage.setItem(USER_KEY, JSON.stringify(response.user));
      setToken(response.access_token);
      setUser(response.user);
      scheduleAutoLogout(response.access_token);
    } finally {
      setLoading(false);
    }
  };

  const register = async (credentials: RegisterCredentials) => {
    setLoading(true);
    try {
      const response = await registerApi(credentials);
      localStorage.setItem(TOKEN_KEY, response.access_token);
      localStorage.setItem(USER_KEY, JSON.stringify(response.user));
      setToken(response.access_token);
      setUser(response.user);
      scheduleAutoLogout(response.access_token);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        loading,
        login,
        register,
        logout,
        tokenExpiresAt,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
