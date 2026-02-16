import axios from 'axios';

const api = axios.create({
  // If we are in production, use the full Render URL. Otherwise, use the local proxy.
  baseURL: import.meta.env.PROD 
    ? import.meta.env.VITE_API_BASE_URL 
    : '/api',
});

// Request Interceptor: Attach JWT to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('accessToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => Promise.reject(error));

export default api;
