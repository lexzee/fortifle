const host = "http://127.0.0.1:5000";
const token = localStorage.getItem("jwt");
function encode(data: {}) {
  let string = JSON.stringify(data);
  return string;
}

const headers = {
  "Content-type": "application/json",
  Authorization: `Bearer ${token}`,
};

// API Wrapper
async function apiRequest(url: string, options?: RequestInit) {
  try {
    const res = await fetch(url, options);
    if (!res.ok) {
      const errorData = await res.json();
      return {
        error:
          errorData.error ||
          errorData.message ||
          errorData.msg ||
          "An unexpected error occured",
      };
    }
    return await res.json();
  } catch (error: any) {
    console.error("API Error: ", error);
    return { error: error.message || "Network Error" };
  }
}

// Test server
export async function test() {
  console.log("Testin gserver");

  return apiRequest(`${host}/`, { method: "GET", headers });
}

// Login with email
export async function loginEmail(email: string, password: string) {
  return apiRequest(`${host}/auth/login`, {
    method: "POST",
    headers,
    body: encode({ email: email, password: password }),
  });
}

// Login with google
export function loginGoogle() {
  window.location.href = `${host}/auth/login/google`;
  // alert("Open windows");
}

// Register with email
export async function registerEmail(
  email: string,
  name: string,
  password: string
) {
  return apiRequest(`${host}/register`, {
    method: "POST",
    headers,
    body: encode({ email, name, password }),
  });
}

// Get uploaded files
export async function getFiles() {
  return apiRequest(`${host}/files`, { method: "GET", headers });
}

// Secure upload
export async function secure_upload(user_id: string, file: File | null) {
  if (!file || !user_id) return;

  const formData = new FormData();
  formData.append("file", file);
  formData.append("user_id", user_id);

  return apiRequest(`${host}/secure-upload`, {
    method: "POST",
    body: formData,
    headers: { contentType: "form", Authorization: `Bearer ${token}` },
  });
}

// Secure Download
export async function secure_download(
  base: string,
  ext: string,
  user_id: string
) {
  try {
    const res: any = await fetch(`${host}/secure-download`, {
      method: "POST",
      body: encode({ base, ext, user_id }),
      headers,
    });

    if (!res.ok) {
      throw new Error(res.statusText);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${base}.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    return { success: true };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}
