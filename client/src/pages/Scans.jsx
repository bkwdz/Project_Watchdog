import axios from "axios";
import { useState } from "react";

const Scans = () => {
  const [ip, setIp] = useState("");
  const [result, setResult] = useState(null);

  const startScan = () => {
    axios.post("http://localhost:8080/api/scans/start", { ip })
      .then(res => setResult(res.data))
      .catch(err => console.log(err));
  };

  return (
    <>
      <h1>Scans</h1>

      <div className="card">
        <h2>Start New Scan</h2>
        <input
          type="text"
          placeholder="Enter IP address..."
          value={ip}
          onChange={e => setIp(e.target.value)}
          style={{ width: "200px", marginRight: "10px" }}
        />
        <button onClick={startScan}>Start Scan</button>
      </div>

      {result && (
        <div className="card">
          <h2>Scan Started</h2>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </>
  );
};

export default Scans;
