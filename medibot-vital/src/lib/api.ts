import axios from 'axios';

const api = axios.create({
  // FIX: Explicitly append /api so it matches your Spring Boot @RequestMapping paths
  baseURL: import.meta.env.PROD 
    ? "https://mediconnectbackend-cqu6.onrender.com/api" 
    : "/api",
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
