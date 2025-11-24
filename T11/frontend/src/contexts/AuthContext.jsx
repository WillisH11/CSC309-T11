import React, { createContext, useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const AuthContext = createContext(null);

const BACKEND_URL =
  import.meta.env.VITE_BACKEND_URL || "http://localhost:3000";

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);

  useEffect(() => {
    const checkUser = async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/api/user/me`, {
          credentials: "include",
        });

        if (!res.ok) {
          setUser(null);
          return;
        }

        const data = await res.json();
        setUser(data.user);
      } catch {
        setUser(null);
      }
    };

    checkUser();
  }, []);

  const login = async (username, password) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/login`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        return data.message;
      }

      setUser(data.user);
      navigate("/profile");
    } catch {
      return "Network error";
    }
  };

  const logout = async () => {
    await fetch(`${BACKEND_URL}/api/logout`, {
      method: "POST",
      credentials: "include",
    });

    setUser(null);
    navigate("/");
  };

  const register = async (form) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/register`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(form),
      });

      const data = await res.json();

      if (!res.ok) {
        return data.message;
      }

      navigate("/success");
    } catch {
      return "Network error";
    }
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
