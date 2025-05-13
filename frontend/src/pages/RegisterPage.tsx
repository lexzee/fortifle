import { useState } from "react";
import "./Login.css";
import GoogleButton from "../components/ui/GoogleButton";
import { registerEmail } from "../utils";
import { useNavigate } from "react-router-dom";

const RegisterPage: React.FC = () => {
  const [email, setEmail] = useState<string>("");
  const [name, setName] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [registerMsg, setRegisterMsg] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleEmailRegister = async () => {
    setRegisterMsg(null);

    if (!email || !password || !name) {
      setRegisterMsg("Some Fields are empty");
      return;
    }

    try {
      const res = await registerEmail(email, name, password);
      if (res.success) {
        setRegisterMsg(res.message);
        navigate("/");
      } else {
        setRegisterMsg(res.error);
      }
    } catch (err: any) {
      setRegisterMsg("Register failed: " + err.message);
    }
  };

  const navToLogin = () => {
    navigate("/login");
  };

  return (
    <div className="login">
      <h2>Register</h2>
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
        <input
          type="text"
          value={name}
          id="name"
          placeholder="username"
          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
            setName(e.target.value)
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
        {registerMsg && <div className="msg">{registerMsg}</div>}
        <button onClick={handleEmailRegister}>Register</button>
        <p style={{ padding: 0, margin: 0, fontSize: ".8em" }}>
          Already registered? {"  "}
          <span
            style={{ color: "blue", cursor: "pointer" }}
            onClick={navToLogin}
          >
            Sign in
          </span>
        </p>
        <GoogleButton>Sign up with Google</GoogleButton>
      </div>
    </div>
  );
};

export default RegisterPage;
