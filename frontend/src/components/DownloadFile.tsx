import { useState } from "react";
import { secure_download } from "../utils";
import "./DownloadFile.css";

interface DownloadFileProps {
  aesKey: string;
}

const DownloadFile: React.FC<DownloadFileProps> = ({ aesKey }) => {
  const [filename, setFilename] = useState<string>("");
  const handleDownload = async (e: any) => {
    e.preventDefault();
    const trimmed = filename.trim();
    if (!trimmed) {
      alert("Please enter a filename");
      return;
    }

    const [base, ext = "enc"] = trimmed.split(".");

    await secure_download(base, ext, aesKey);
  };
  return (
    <div className="download-container">
      <h1>Secure Download</h1>
      <label htmlFor="filename">File Name</label>
      <input
        id="filename"
        type="text"
        placeholder="e.g. app.enc"
        value={filename}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
          setFilename(e.target.value)
        }
      />
      <button onClick={handleDownload}>Download</button>
    </div>
  );
};

export default DownloadFile;
