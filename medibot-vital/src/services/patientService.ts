import api from '@/lib/api';

export const patientService = {
  // 1. Identity Module
  getProfile: async () => {
    const response = await api.get('/users/me');
    return response.data;
  },

  // 2. Booking Module
  getBookings: async (patientId: string) => {
    const response = await api.get(`/bookings/patient/${patientId}`);
    return response.data;
  },

  // 3. Records Module
  getHistory: async (patientId: string) => {
    const response = await api.get(`/records/patient/${patientId}`);
    return response.data;
  },

  // 4. Triage Module
  analyzeSymptoms: async (symptoms: string[]) => {
    const response = await api.post('/triage/analyze', { symptoms });
    return response.data;
  }
};