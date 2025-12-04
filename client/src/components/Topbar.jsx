import { useContext, useState } from "react";
import { AuthContext } from "../contexts/AuthContext";

export default function Topbar() {
  const { user, logout } = useContext(AuthContext);
  const [open, setOpen] = useState(false);

  const firstLetter = user?.username?.charAt(0)?.toUpperCase() || "?";

  return (
    <div style={styles.bar}>
      <h2 style={styles.title}>Watchdog</h2>

      <div style={styles.userArea}>
        <div style={styles.userIcon} onClick={() => setOpen(!open)}>
          {firstLetter}
        </div>

        {open && (
          <div style={styles.popup}>
            <div style={styles.header}>
              <strong>User Info</strong>
              <button style={styles.closeBtn} onClick={() => setOpen(false)}>✕</button>
            </div>

            <div style={styles.detail}>Username: {user.username}</div>
            <div style={styles.detail}>Role: {user.role}</div>

            <button style={styles.logoutBtn} onClick={logout}>
              Logout
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

const styles = {
  bar: {
    height: "60px",
    backgroundColor: "#141414",
    borderBottom: "1px solid #222",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "0 20px",
  },
  title: {
    color: "white",
    margin: 0,
  },
  userArea: {
    position: "relative",
  },
  userIcon: {
    width: "42px",
    height: "42px",
    borderRadius: "50%",
    backgroundColor: "#333",
    color: "white",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    cursor: "pointer",
    fontSize: "18px"
  },
  popup: {
    position: "absolute",
    top: "55px",
    right: 0,
    backgroundColor: "#1c1c1c",
    width: "200px",
    padding: "15px",
    borderRadius: "6px",
    border: "1px solid #333",
    zIndex: 100,
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: "10px",
    color: "#ccc",
  },
  detail: {
    fontSize: "14px",
    color: "#bbb",
    marginBottom: "8px",
  },
  closeBtn: {
    background: "none",
    border: "none",
    color: "#aaa",
    cursor: "pointer",
    fontSize: "15px",
  },
  logoutBtn: {
    width: "100%",
    padding: "8px",
    borderRadius: "5px",
    backgroundColor: "#d9534f",
    border: "none",
    color: "white",
    cursor: "pointer",
    marginTop: "10px",
  },
};
