import { useEffect, useState } from "react";
import React from "react";
import "./Combine.css";
import { getFiles, secure_download, secure_upload } from "../utils";
import { useUser } from "../context/FileManagerContext";
import { useNavigate } from "react-router-dom";

interface SecureFileManagerProps {
  userId: string;
}

const SecureFileManager: React.FC<SecureFileManagerProps> = ({ userId }) => {
  const { availableFiles, setAvailableFiles } = useUser();
  const [file, setFile] = useState<File | null>(null);
  const [uploadMsg, setUploadMsg] = useState<string | null>(null);
  const [downloadMsg, setDownloadMsg] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string>("");
  const name = localStorage.getItem("name") || "John-Doe";
  const navigate = useNavigate();

  const handleUpload = async () => {
    setUploadMsg(null);
    if (!file || !userId) {
      console.log("Some fields are empty!");
      return;
    }

    try {
      const res = await secure_upload(userId, file);
      if (res.error) {
        throw new Error(res.error);
      }
      setAvailableFiles((prev: string[]) => {
        const index = prev.findIndex((f: string) => f == file.name);
        if (index !== -1) {
          const newFiles = [...prev];
          return newFiles;
        } else {
          return [...prev, file.name];
        }
      });
      setUploadMsg("File uploaded and encrypted sucessfully");
    } catch (err: any) {
      setUploadMsg("Upload Failed: " + err.message);
    }
  };

  const handleDownload = async () => {
    setDownloadMsg(null);
    if (!selectedFile) {
      alert("You have not selected a file for download!");
      return;
    }

    const files = selectedFile.trim().split(".");
    const base = files.slice(0, -1).join(".");
    const ext = files[files.length - 1] || "enc";

    try {
      const res = await secure_download(base, ext, userId);
      console.log(res);

      if (res.success) {
        setDownloadMsg("File decrypted and downloaded sucessfully!");
      } else {
        throw new Error(res.error);
      }
    } catch (err: any) {
      setDownloadMsg("Download failed: " + err.message);
    }
  };

  const logout = () => {
    localStorage.clear();
    navigate("/login");
  };

  // Get Files
  useEffect(() => {
    const getUserFiles = async () => {
      const res = await getFiles();
      if (res.success) {
        setAvailableFiles([]);
        const userFiles: any = [];
        for (let i of res.files) {
          userFiles.push(i["file_name"]);
        }

        setAvailableFiles(userFiles);
      }
    };

    setTimeout(() => {
      getUserFiles();
    }, 2000);
  }, []);

  return (
    <div className="manager-container">
      <div
        className="card"
        style={{
          margin: 0,
          flexDirection: "row",
          paddingTop: 0,
          paddingBottom: 0,
          justifyContent: "space-between",
        }}
      >
        <h3 style={{}}>{name}</h3>{" "}
        <p style={{ cursor: "pointer", color: "blue" }} onClick={logout}>
          logout
        </p>
      </div>
      {/* Upload */}
      <div className="card">
        <h2>Secure File Upload</h2>
        <input
          type="file"
          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
            setFile(e.target.files?.[0] || null)
          }
        />
        <button onClick={handleUpload}>Upload</button>
        {uploadMsg && <div className="msg">{uploadMsg}</div>}
      </div>

      {/* Download */}
      <div className="card">
        <h2>Secure File Download</h2>
        <input
          type="text"
          placeholder="Enter filename or select from dropdown"
          value={selectedFile}
          onChange={(e) => setSelectedFile(e.target.value)}
        />
        <select
          value={selectedFile}
          onChange={(e) => setSelectedFile(e.target.value)}
        >
          <option value="">-- Select File --</option>
          {availableFiles.map((fname) => (
            <option key={fname} value={fname}>
              {fname}
            </option>
          ))}
        </select>
        <button onClick={handleDownload}>Download</button>
        {downloadMsg && <div className="msg">{downloadMsg}</div>}
      </div>
    </div>
  );
};

export default SecureFileManager;
