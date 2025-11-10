import "./style.css";
import React, { useState } from "react";

function NewTodo({ addTodo = () => {} }) {
    const [text, setText] = useState("");

    function handleSubmit() {
        const val = text.trim();
        if (!val) return;

        setTimeout(() => {
            addTodo(val);
            setText("");
        }, 0);
    }

    return (
        <div className="new-todo row">
            <input
                type="text"
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Enter a new task"
            />
            <button type="button" onClick={handleSubmit}>+</button>
        </div>
    );
}

export default NewTodo;
