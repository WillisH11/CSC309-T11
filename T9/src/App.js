import "./App.css";
import React, { useState } from "react";
import NewTodo from "./components/NewTodo";
import TodoItem from "./components/TodoItem";

// You can use this to seed your TODO list
const seed = [
    { id: 0, text: "Submit assignment 2", completed: false },
    { id: 1, text: "Reschedule the dentist appointment", completed: false },
    { id: 2, text: "Prepare for CSC309 exam", completed: false },
    { id: 3, text: "Find term project partner", completed: true },
    { id: 4, text: "Learn React Hooks", completed: false },
];

function App() {
  const [todos, setTodos] = useState(seed);

  function addTodo(text) {
    const newTodo = {
      id: Date.now(),
      text,
      completed: false,
    };
    setTodos([...todos, newTodo]);
  }

  function deleteTodo(id) {
    setTodos(todos.filter(t => t.id !== id));
  }

  function toggleTodo(id) {
    setTodos(
      todos.map(t =>
        t.id === id ? { ...t, completed: !t.completed } : t
      )
    );
  }

  return (
    <div className="app">
      <h1>My ToDos</h1>

      <NewTodo addTodo={addTodo} />

      {todos.map(todo => (
        <TodoItem
          key={todo.id}
          todo={todo}
          onDelete={deleteTodo}
          onToggle={toggleTodo}
        />
      ))}
    </div>
  );
}

export default App;
