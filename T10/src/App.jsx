import "./App.css";
import { CitiesProvider } from "./contexts/CitiesContext";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Detail from "./pages/Detail";
import NotFound from "./pages/NotFound";

const App = () => {
    return (
        <CitiesProvider>
            <BrowserRouter>
                <Routes>
                    <Route path="/" element={<Layout />}>
                        {/* Home page */}
                        <Route index element={<Home />} />

                        {/* City page */}
                        <Route path=":cityId" element={<Detail />} />

                        <Route path="*" element={<NotFound />} />
                    </Route>
                </Routes>
            </BrowserRouter>
        </CitiesProvider>
    );
};

export default App;