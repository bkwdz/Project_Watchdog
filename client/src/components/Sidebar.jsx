import { Link, useLocation } from "react-router-dom";

const Sidebar = () => {
  const { pathname } = useLocation();

  return (
    <div style={styles.sidebar}>
      <h2 style={styles.title}>Watchdog</h2>

      <Link to="/" style={{ ...styles.link, ...(pathname === "/" && styles.active) }}>
        Dashboard
      </Link>

      <Link to="/devices" style={{ ...styles.link, ...(pathname === "/devices" && styles.active) }}>
        Devices
      </Link>

      <Link to="/scans" style={{ ...styles.link, ...(pathname === "/scans" && styles.active) }}>
        Scans
      </Link>

      <div style={{ flexGrow: 1 }} />
    </div>
  );
};

const styles = {
  sidebar: {
    width: "220px",
    backgroundColor: "#141414",
    padding: "20px",
    display: "flex",
    flexDirection: "column",
    borderRight: "1px solid #222",
    height: "100dvh",
    boxSizing: "border-box",
  },
  title: {
    color: "#fff",
    marginBottom: "25px",
    fontSize: "22px",
  },
  link: {
    padding: "10px 0",
    color: "#aaa",
    textDecoration: "none",
    fontSize: "16px",
    transition: "0.2s",
  },
  active: {
    color: "#00b3ff",
    fontWeight: "bold",
  }
};

export default Sidebar;
