import "./City.css";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useCities } from "../contexts/CitiesContext";

const City = ({ city }) => {
    const [temperature, setTemperature] = useState(null);

    const navigate = useNavigate();
    const { removeCity } = useCities();

    useEffect(() => {
        const fetchTemp = async () => {
            try {
                const res = await fetch(
                    `https://api.open-meteo.com/v1/forecast?latitude=${city.latitude}&longitude=${city.longitude}&current_weather=true`
                );
                const data = await res.json();

                if (data.current_weather) {
                    setTemperature(data.current_weather.temperature);
                }
            } catch (err) {
                console.error("Error fetching temperature:", err);
            }
        };

        fetchTemp();
    }, [city.latitude, city.longitude]);

    const handleClick = () => {
        navigate(`/${city.id}`);
    };

    return (
        <div className="city-card">
            <button
                className="remove-btn"
                onClick={() => removeCity(city.id)}
            >
                ×
            </button>

            <div className="city-content" onClick={handleClick}>
                <h2>{city.name}</h2>

                {temperature !== null ? (
                    <p className="temperature">{temperature}°C</p>
                ) : (
                    <div className="spinner"></div>
                )}
            </div>
        </div>
    );
};

export default City;