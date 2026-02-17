import axios from "axios";

const baseURL = import.meta.env.VITE_API_URL || "/api";

export default axios.create({
  baseURL,
  withCredentials: true,
});
