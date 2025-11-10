import "./style.css";
import React, { useState } from "react";

function NewTodo({ addTodo }) {
    const [text, setText] = useState("");

    function handleSubmit() {
        if (!text.trim()) return;
        if (addTodo) {
            addTodo(text.trim());
        }
        setText("");
    }

    return (
        <div className="new-todo row">
            <input
                type="text"
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Enter a new task"
            />
            <button onClick={handleSubmit}>+</button>
        </div>
    );
}

export default NewTodo;
