import "./style.css";
import trash from "./trash.webp";

function TodoItem({ todo, onDelete, onToggle }) {

    function handleDelete(e) {
        e.preventDefault();
        onDelete(todo.id);
    }

    return (
        <div className="todo-item row">
            <input
                type="checkbox"
                checked={todo.completed}
                onChange={() => onToggle(todo.id)}
            />

            <span className={todo.completed ? "completed" : ""}>
                {todo.text}
            </span>

            {/* eslint-disable jsx-a11y/anchor-is-valid */}
            <a href="#" onClick={handleDelete}>
                <img src={trash} alt="delete" />
            </a>
            {/* eslint-enable jsx-a11y/anchor-is-valid */}
        </div>
    );
}

export default TodoItem;
