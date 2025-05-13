import { useState } from "react";
import { secure_upload } from "../utils";
import "./UploadForm.css";

interface UploadFormProps {
  userId: string;
  aesKey: string;
}

const UploadForm: React.FC<UploadFormProps> = ({ userId, aesKey }) => {
  const [file, setFile] = useState<File | null>(null);
  const [response, setResponse] = useState<any>();

  const handleUpload = async (e: any) => {
    e.preventDefault();
    if (!file || !userId || !aesKey) {
      console.log("Some fields are empty!");
      return;
    }

    const res = await secure_upload(userId, file, aesKey);
    setResponse(res.data);
  };

  return (
    <div className="upload-container">
      <h1>Secure Upload</h1>

      <input
        type="file"
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
          e.target.files && setFile(e.target.files[0]);
        }}
      />

      <input
        type="text"
        placeholder="AES Key (Base64)"
        value={aesKey}
        readOnly
        hidden
      />

      <button onClick={handleUpload}>Upload</button>

      {response && (
        <div>
          <h2>Server Response:</h2>
          {response && (
            <div>
              <p>encrypted_file_path : {response.encrypted_file_path}</p>
              <p>meta_data_file_path : {response.meta_data_file_path}</p>
              <p>signature_file_path : {response.signature_file_path}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default UploadForm;
