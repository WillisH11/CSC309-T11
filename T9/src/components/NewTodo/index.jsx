import "./style.css";
import React, { useState } from "react";

function NewTodo({ addTodo = () => {} }) {
  const [text, setText] = useState("");

  function handleSubmit() {
    const val = text.trim();
    if (!val) return;
    addTodo(val);
    setText("");
  }

  return (
    <div className="new-todo row">
      <input
        type="text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter") handleSubmit(); }}
        placeholder="Enter a new task"
      />
      <button type="button" onClick={handleSubmit}>+</button>
    </div>
  );
}

export default NewTodo;
