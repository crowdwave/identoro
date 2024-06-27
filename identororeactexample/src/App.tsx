// AppRouter.tsx
import "react-toastify/dist/ReactToastify.css";
import React from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import {IdentoroRoutes} from "./IdentoroApp";

const NotFound: React.FC = () => <div>404 Not Found</div>;
const HomePage: React.FC = () => <div>Home Page</div>;

const AppRouter: React.FC = () => {
  return (
    <BrowserRouter basename={process.env.PUBLIC_URL}>
      <Routes>
        <Route path="404" element={<NotFound />} />
        <Route path="/auth/*" element={<IdentoroRoutes />} />
        <Route path="/" element={<HomePage />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
};

export default AppRouter;
