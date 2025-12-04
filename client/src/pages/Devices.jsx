import axios from "axios";
import { useEffect, useState } from "react";

const Devices = () => {
  const [devices, setDevices] = useState([]);

  useEffect(() => {
    axios.get("http://localhost:8080/api/devices")
      .then(res => setDevices(res.data))
      .catch(err => console.log(err));
  }, []);

  return (
    <>
      <h1>Devices</h1>

      <div className="card">
        {devices.length === 0 ? (
          <p>No devices found.</p>
        ) : (
          devices.map(d => (
            <div key={d.id} className="card" style={{ marginBottom: "10px" }}>
              <h3>{d.name || "Unnamed Device"}</h3>
              <p>IP: {d.ip}</p>
            </div>
          ))
        )}
      </div>
    </>
  );
};

export default Devices;
