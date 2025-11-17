import { createContext, useContext, useState } from "react";

const CitiesContext = createContext();

export const CitiesProvider = ({ children }) => {
    const [cities, setCities] = useState([
        { id: 1, name: "Toronto", latitude: 43.70011, longitude: -79.4163 }
    ]);

    const removeCity = (cityId) => {
        setCities((prev) => prev.filter((city) => city.id !== cityId));
    };

    const addCity = ({ name, latitude, longitude }) => {
        setCities((prev) => [
            ...prev,
            {
                id: crypto.randomUUID(),
                name,
                latitude,
                longitude
            }
        ]);
    };

    return (
        <CitiesContext.Provider value={{ cities, addCity, removeCity }}>
            {children}
        </CitiesContext.Provider>
    );
};

export const useCities = () => useContext(CitiesContext);