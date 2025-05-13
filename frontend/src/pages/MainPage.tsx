import { useEffect } from "react";
import SecureFileManager from "../components/Combine";
import { useUser } from "../context/FileManagerContext";
// import { jwtDecode } from "jwt-decode";
import { useNavigate } from "react-router-dom";

export default function MainPage() {
  const { userId, jwt, setJWT } = useUser();
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("jwt");
    if (!token) {
      navigate("/login");
    }
    if (token) setJWT(token);
    // const user = token ? jwtDecode(token) : null;
  }, [userId, jwt]);

  return (
    <>
      <div className="landing">
        {/* <div className="min-h-screen bg-gray-50 flex items-center justify-center"> */}
        {/* <UploadForm userId={userId} aesKey={aesKey} />
          <DownloadFile aesKey={aesKey} /> */}
        {/* <h1>VaraQ</h1> */}
        <h1>FortiFile</h1>
        <SecureFileManager
          // aesKey={aesKey}
          userId={userId}
          // availableFiles={availableFiles}
        />
      </div>
      <small className="footer">Abdulqudduds (Lexzee) ©2025</small>
    </>
  );
}
