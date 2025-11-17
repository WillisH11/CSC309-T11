import "./Detail.css";
import { useCities } from "../contexts/CitiesContext";
import NotFound from "./NotFound";
import { useParams, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";

function Weather({ city }) {
    const [weather, setWeather] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchWeather = async () => {
            try {
                const res = await fetch(
                    `https://api.open-meteo.com/v1/forecast?latitude=${city.latitude}&longitude=${city.longitude}&current=temperature_2m,wind_speed_10m,relative_humidity_2m,precipitation_probability`
                );

                const data = await res.json();

                if (data.current) {
                    setWeather(data.current);
                }
            } catch (err) {
                console.error("Error fetching detailed weather:", err);
            }
        };

        fetchWeather();
    }, [city.latitude, city.longitude]);

    return (
        <>
            <h1>{city.name}</h1>

            {weather ? (
                <div className="weather-info">
                    <div>
                        <h3>Temperature</h3>
                        <p>{weather.temperature_2m}°C</p>
                    </div>

                    <div>
                        <h3>Humidity</h3>
                        <p>{weather.relative_humidity_2m}%</p>
                    </div>

                    <div>
                        <h3>Wind</h3>
                        <p className="small">{weather.wind_speed_10m} km/h</p>
                    </div>

                    <div>
                        <h3>Precipitation</h3>
                        <p>{weather.precipitation_probability}%</p>
                    </div>
                </div>
            ) : (
                <div className="spinner"></div>
            )}

            <button className="btn" onClick={() => navigate("/")}>
                Back
            </button>
        </>
    );
}

function Detail() {
    const { cityId } = useParams();
    const { cities } = useCities();

    const city = cities.find((c) => String(c.id) === cityId);

    if (!city) {
        return <NotFound />;
    }

    return <Weather city={city} />;
}

export default Detail;
