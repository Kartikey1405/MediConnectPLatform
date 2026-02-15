// // import api from '@/lib/api';

// // /**
// //  * Standardizes user authentication, session storage, and role management.
// //  * Maps backend responses (accessToken, userId, role) to LocalStorage.
// //  */

// // export const login = async (credentials: { email: string; password: any }) => {
// //   const response = await api.post('/auth/login', credentials);
// //   const data = response.data;

// //   // DEBUG: Inspect the backend payload in your browser console (F12)
// //   console.log("AUTH_SERVICE_DEBUG: Full Response Payload:", data);

// //   if (data.accessToken) {
// //     // 1. Store the JWT Token for future authorized requests
// //     localStorage.setItem('accessToken', data.accessToken);
    
// //     // 2. Store the role (ADMIN, PATIENT, or DOCTOR) for RBAC
// //     localStorage.setItem('userRole', data.role); 

// //     // 3. Robust ID Extraction: Tries common field names to avoid 'undefined'
// //     const extractedId = data.userId || data.id || data.uuid || (data.user && data.user.id);
    
// //     if (extractedId && String(extractedId) !== "undefined") {
// //       localStorage.setItem('userId', String(extractedId));
// //       // Store the full object as a string for easy access in Profile pages
// //       localStorage.setItem('user', JSON.stringify(data)); 
// //       console.log("AUTH_SYNC_SUCCESS: Session established for ID:", extractedId);
// //     } else {
// //       console.error("AUTH_SYNC_ERROR: Backend response missing user ID field. Check DTO structure.");
// //     }
// //   }
// //   return data;
// // };

// // /**
// //  * Routes to the Spring Boot UserController for registration.
// //  */
// // export const signup = async (userData: any) => {
// //   const response = await api.post('/users/register', userData);
// //   return response.data;
// // };

// // /**
// //  * Clears all local session data and terminates the user session.
// //  */
// // export const logout = () => {
// //   localStorage.removeItem('accessToken');
// //   localStorage.removeItem('userRole');
// //   localStorage.removeItem('userId');
// //   localStorage.removeItem('user');
// //   // Optional: Clear all to be safe
// //   localStorage.clear();
// //   window.location.href = '/'; // Redirect to landing page
// // };

// // // EXPORT: Bundle functions into a single object to support 'authService.login' syntax
// // export const authService = {
// //   login,
// //   signup,
// //   logout
// // };

// // export default authService;








// import api from '@/lib/api';

// export const login = async (credentials: { email: string; password: any }) => {
//   const response = await api.post('/auth/login', credentials);
//   const data = response.data;

//   console.log("AUTH_SERVICE_DEBUG: Full Response Payload:", data);

//   if (data.accessToken) {
//     localStorage.setItem('accessToken', data.accessToken);
//     localStorage.setItem('userRole', data.role); 

//     // Extract User ID
//     const extractedUserId = data.userId || data.id || data.uuid;
    
//     // Extract Doctor ID (Essential for the Doctor module schedule)
//     const extractedDoctorId = data.doctorId || (data.doctor && data.doctor.id);

//     if (extractedUserId) {
//       localStorage.setItem('userId', String(extractedUserId));
//       localStorage.setItem('user', JSON.stringify(data)); 
      
//       // Specifically store the Doctor ID if the user is a doctor
//       if (extractedDoctorId) {
//         localStorage.setItem('doctorId', String(extractedDoctorId));
//       }

//       console.log("AUTH_SYNC_SUCCESS: Session established for User:", extractedUserId);
//     } else {
//       console.error("AUTH_SYNC_ERROR: Missing User ID. Check LoginResponse DTO.");
//     }
//   }
//   return data;
// };

// export const signup = async (userData: any) => {
//   const response = await api.post('/users/register', userData);
//   return response.data;
// };

// export const logout = () => {
//   localStorage.clear();
//   window.location.href = '/'; 
// };

// export const authService = { login, signup, logout };
// export default authService;






import api from '@/lib/api';

/**
 * Standardizes user authentication and session management.
 * Synchronizes backend identity fields (User ID vs Specialist ID) with LocalStorage.
 */

export const login = async (credentials: { email: string; password: any }) => {
  const response = await api.post('/auth/login', credentials);
  const data = response.data;

  // DEBUG: Monitor identity mapping in the browser console
  console.log("AUTH_SERVICE_DEBUG: Full Response Payload:", data);

  if (data.accessToken) {
    // 1. Core Session Persistence
    localStorage.setItem('accessToken', data.accessToken);
    localStorage.setItem('userRole', data.role); // Standardizes RBAC (ADMIN, DOCTOR, PATIENT)

    // 2. Identity Mapping
    // Standard User ID (linked to the login account)
    const extractedUserId = data.userId || data.id || data.uuid;
    
    // Clinical Specialist ID (linked to the Doctor entity)
    // Essential for the Doctor Dashboard to fetch clinical queues.
    const extractedDoctorId = data.doctorId || (data.doctor && data.doctor.id);

    if (extractedUserId) {
      localStorage.setItem('userId', String(extractedUserId));
      
      // Persist full user object for name greetings and profile views
      localStorage.setItem('user', JSON.stringify(data)); 
      
      // Specifically store the Doctor ID if the clinical role is active
      if (extractedDoctorId) {
        localStorage.setItem('doctorId', String(extractedDoctorId));
        console.log("AUTH_SYNC_SUCCESS: Clinical identity mapped for Specialist ID:", extractedDoctorId);
      }

      console.log("AUTH_SYNC_SUCCESS: User session established for ID:", extractedUserId);
    } else {
      console.error("AUTH_SYNC_ERROR: Missing User ID. Verify backend LoginResponse DTO structure.");
    }
  }
  return data;
};

/**
 * Routes registration data to the Spring Boot UserController.
 */
export const signup = async (userData: any) => {
  const response = await api.post('/users/register', userData);
  return response.data;
};

/**
 * Terminates the active session and clears all medical/identity data from local storage.
 */
export const logout = () => {
  localStorage.clear();
  window.location.href = '/'; // Redirects to home/landing page
};

// EXPORT: Bundle functions to support 'authService.login' syntax across the application
export const authService = {
  login,
  signup,
  logout
};

export default authService;