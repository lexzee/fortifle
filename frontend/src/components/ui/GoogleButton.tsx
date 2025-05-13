import GoogleIcon from "../../assets/google.svg";
import { loginGoogle } from "../../utils";
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {}

const GoogleButton: React.FC<ButtonProps> = ({ children }) => {
  const handleGoogleLogin = () => {
    loginGoogle();
  };
  return (
    <button className="google" onClick={handleGoogleLogin}>
      <img src={GoogleIcon} alt="Google logo" width={40} />
      {children}
    </button>
  );
};

export default GoogleButton;
