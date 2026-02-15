import api from "@/lib/api";

export const adminService = {
  // --- Hospital Management ---
  getAllHospitals: async () => {
    const res = await api.get("/admin/hospitals");
    return res.data;
  },

  addHospital: async (data: any) => {
    const res = await api.post("/admin/hospitals", data);
    return res.data;
  },

  // --- Doctor Management ---
  getAllDoctors: async () => {
    // Matches @GetMapping in AdminDoctorController
    const res = await api.get("/admin/doctors");
    return res.data;
  },

  verifyDoctor: async (doctorId: string) => {
    // Matches @PatchMapping("/{id}/verify") in AdminDoctorController
    const res = await api.patch(`/admin/doctors/${doctorId}/verify`);
    return res.data;
  },

  deleteDoctor: async (doctorId: string) => {
    const res = await api.delete(`/admin/doctors/${doctorId}`);
    return res.data;
  }
};