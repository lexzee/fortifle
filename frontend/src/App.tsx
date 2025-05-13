import "./App.css";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import LoginPage from "./pages/LoginPages";
import RegisterPage from "./pages/RegisterPage";
import OAuthSuccess from "./pages/OAuthSuccess";
import MainPage from "./pages/MainPage";

function App() {
  // const { userId, aesKey, availableFiles } = useUser();

  return (
    <Router>
      <Routes>
        <Route path="/" element={<MainPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/oauth-success" element={<OAuthSuccess />} />
      </Routes>
    </Router>
  );
}
export default App;
