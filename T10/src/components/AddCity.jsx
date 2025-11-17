import "./AddCity.css";
import { forwardRef, useState } from "react";
import { useCities } from "../contexts/CitiesContext";

const AddCity = forwardRef(({ setError }, ref) => {
    const [cityName, setCityName] = useState("");
    const { addCity } = useCities();

    const handle_submit = async (e) => {
        e.preventDefault();

        const trimmed = cityName.trim();

        if (trimmed === "") {
            setError("City name cannot be blank.");
            return;
        }

        try {
            const response = await fetch(
                `https://nominatim.openstreetmap.org/search?format=json&q=${trimmed}&limit=1`,
                {
                    headers: {
                        "User-Agent": "ACoolWeatherApp/0.1 (your_email)"
                    }
                }
            );

            const data = await response.json();

            if (!data || data.length === 0) {
                setError(`City '${trimmed}' is not found.`);
                return;
            }

            const result = data[0];
            const latitude = parseFloat(result.lat);
            const longitude = parseFloat(result.lon);
            
            addCity({
                name: trimmed,
                latitude,
                longitude
            });

            setCityName("");
            setError("");
            ref.current?.close();

        } catch (err) {
            console.error("Nominatim error:", err);
            setError("Failed to fetch city data. Try again later.");
        }
    };

    return (
        <dialog ref={ref}>
            <div className="dialog-header">
                <span>Add A City</span>
                <a onClick={() => ref.current?.close()}>✖</a>
            </div>

            <form onSubmit={handle_submit}>
                <input
                    type="text"
                    placeholder="Enter City Name"
                    value={cityName}
                    onChange={(e) => setCityName(e.target.value)}
                    required
                />

                <div className="button-group">
                    <button type="submit">Add</button>
                    <button type="button" onClick={() => ref.current?.close()}>
                        Close
                    </button>
                </div>
            </form>
        </dialog>
    );
});

export default AddCity;