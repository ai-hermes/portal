import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./pages/AppShell";
import { LoginPage } from "./pages/LoginPage";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/app/*" element={<AppShell />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
