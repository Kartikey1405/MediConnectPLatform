import api from "@/lib/api";

export const doctorService = {
  // Fetches the specific schedule for this doctor
  getSchedule: async (doctorId: string) => {
    const res = await api.get(`/bookings/doctor/${doctorId}`);
    return res.data;
  },

  // Fetches detailed info about a specific consultation
  getConsultationDetails: async (bookingId: string) => {
    const res = await api.get(`/bookings/${bookingId}`);
    return res.data;
  }
};