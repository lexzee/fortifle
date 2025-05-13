import {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useState,
} from "react";
import { v4 as uuidv4 } from "uuid";

export interface SecureFileManagerProps {
  availableFiles: string[];
  userId: string;
  jwt: string | null;
}

type UserContextType = {
  availableFiles: string[];
  userId: string;
  jwt: string | null;
  setAvailableFiles: (availableFiles: any) => void;
  setUserId: (userId: string) => void;
  setJWT: (jwt: string) => void;
};

const UserContext = createContext<UserContextType | undefined>(undefined);

export const UserProvider = ({ children }: { children: ReactNode }) => {
  const [availableFiles, setAvailableFiles] = useState([]);
  const [userId, setUserId] = useState("");
  const [jwt, setJWT] = useState("");

  // Load from local storage
  useEffect(() => {
    const userId = localStorage.getItem("userId");
    const availableFiles = localStorage.getItem("availableFiles");
    const jwt = localStorage.getItem("jwt");

    if (!userId) genUserId();
    if (userId) setUserId(userId);
    if (jwt) setJWT(jwt);
    if (availableFiles) setAvailableFiles(JSON.parse(availableFiles));
  }, []);

  // Save to local Storage
  useEffect(() => {
    if (userId) localStorage.setItem("userId", userId);
    if (jwt) localStorage.setItem("jwt", jwt);
    if (availableFiles.length > 0)
      localStorage.setItem("availableFiles", JSON.stringify(availableFiles));
  }, [userId, availableFiles, jwt]);

  const genUserId = () => {
    const user = uuidv4();
    setUserId(user);
  };

  // useEffect(() => {
  //   const testingAPI = async () => {
  //     const res = await test();
  //     console.log(res.message);
  //   };

  //   testingAPI();
  // }, []);

  return (
    <UserContext.Provider
      value={{
        availableFiles,
        userId,
        jwt,
        setAvailableFiles,
        setUserId,
        setJWT,
      }}
    >
      {children}
    </UserContext.Provider>
  );
};

export const useUser = () => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error("useGame must be used within a UserProvider");
  }

  return context;
};
