/*
 * controller.js
 *
 * CSC309 Tutorial 8
 * 
 * Complete me
 */

let nextParagraph = 1;
let hasMore = true;
const container = document.getElementById("data");

function renderParagraph(paragraph) {
  const div = document.createElement("div");
  div.id = `paragraph_${paragraph.id}`;

  const p = document.createElement("p");
  p.textContent = paragraph.content + " ";

  const b = document.createElement("b");
  b.textContent = `(Paragraph: ${paragraph.id})`;
  p.appendChild(b);

  const btn = document.createElement("button");
  btn.classList.add("btn", "like");
  btn.textContent = `Likes: ${paragraph.likes}`;
  btn.addEventListener("click", async () => {
    try {
      const res = await fetch("/text/like", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ paragraph: paragraph.id }),
      });
      if (!res.ok) return;

      const data = await res.json();
      btn.textContent = `Likes: ${data.data.likes}`;
    } catch (err) {
      console.error("Error updating likes:", err);
    }
  });

  div.appendChild(p);
  div.appendChild(btn);
  container.appendChild(div);
}

async function fetchParagraphs() {
  if (!hasMore) return;

  try {
    const res = await fetch(`/text?paragraph=${nextParagraph}`);
    if (!res.ok) return;

    const data = await res.json();

    data.data.forEach((para) => renderParagraph(para));

    nextParagraph += data.data.length;
    hasMore = data.next;

    if (!hasMore) {
      const endMsg = document.createElement("b");
      endMsg.textContent = "You have reached the end";
      container.appendChild(endMsg);
    }
  } catch (err) {
    console.error("Error fetching paragraphs:", err);
  }
}

window.addEventListener("scroll", () => {
  if (
    window.innerHeight + window.scrollY >=
    document.body.offsetHeight - 10
  ) {
    fetchParagraphs();
  }
});

window.addEventListener("DOMContentLoaded", () => {
  fetchParagraphs();
});
