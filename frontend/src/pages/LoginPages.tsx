import { useState } from "react";
import "./Login.css";
import GoogleButton from "../components/ui/GoogleButton";
import { loginEmail } from "../utils";
import { useNavigate } from "react-router-dom";
import { useUser } from "../context/FileManagerContext";

const LoginPage: React.FC = () => {
  const { setUserId } = useUser();
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [loginMsg, setLoginMsg] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleEmailLogin = async () => {
    setLoginMsg(null);

    if (!email || !password) {
      setLoginMsg("Some Fields are empty");
      return;
    }

    try {
      const res = await loginEmail(email, password);
      if (res.success) {
        setLoginMsg("Logged in!");
        setUserId(res.user_id);
        localStorage.setItem("jwt", res.token);
        localStorage.setItem("name", res.name);
        navigate("/");
      } else {
        setLoginMsg(res.error);
      }
    } catch (err: any) {
      setLoginMsg("Login failed: " + err.message);
    }
  };

  const navToRegister = () => {
    navigate("/register");
  };

  return (
    <div className="login">
      <h2>Login</h2>
      <div className="card">
        {/* <label htmlFor="email">Email</label> */}
        <input
          type="text"
          value={email}
          id="email"
          placeholder="example@gmail.com"
          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
            setEmail(e.target.value)
          }
        />
        {/* <label htmlFor="password">Password</label> */}
        <input
          type="text"
          value={password}
          id="password"
          placeholder="password"
          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
            setPassword(e.target.value)
          }
        />
        {loginMsg && <div className="msg">{loginMsg}</div>}
        <button onClick={handleEmailLogin}>Login</button>
        <p style={{ padding: 0, margin: 0, fontSize: ".8em" }}>
          Not registered? {"  "}
          <span
            style={{ color: "blue", cursor: "pointer" }}
            onClick={navToRegister}
          >
            Sign up
          </span>
        </p>
        <GoogleButton>Continue with Google</GoogleButton>
      </div>
    </div>
  );
};

export default LoginPage;
