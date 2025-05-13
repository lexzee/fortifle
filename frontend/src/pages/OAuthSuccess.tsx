// import { jwtDecode } from "jwt-decode";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useUser } from "../context/FileManagerContext";

export default function OAuthSuccess() {
  const navigate = useNavigate();
  const { setUserId } = useUser();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const name = params.get("name");
    const id = params.get("id");

    try {
      if (token) {
        localStorage.setItem("jwt", token);
        console.log("Google Login Successful");
        navigate("/");
      }
      if (name) {
        localStorage.setItem("name", name);
      }

      if (id) {
        localStorage.setItem("userId", id);
        setUserId(id);
      }
    } catch (err) {
      console.log(err);
    }

    // if (!token) {
    //   navigate("/");
    //   console.log("OAuth login failed.");
    // }
    // } else {
    //   navigate("/");
    //   console.log("OAuth login failed.");
    // }
  }, []);

  return <p>Redirecting...</p>;
}
