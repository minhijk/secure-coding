"use strict";

const chatEl = document.getElementById("chat");
const partnerId = chatEl.dataset.partnerId;
const socket = io();

socket.on("private_message", (data) => {
  if (!data || typeof data.username !== "string" || typeof data.message !== "string") {
    return;
  }
  const messages = document.getElementById("messages");
  const item = document.createElement("li");
  // textContent 로만 삽입하여 DOM 기반 XSS 를 차단한다.
  item.textContent = `${data.username}: ${data.message}`;
  messages.appendChild(item);
  messages.scrollTop = messages.scrollHeight;
});

function sendPrivateMessage() {
  const input = document.getElementById("chat_input");
  const message = input.value.trim();
  if (message) {
    socket.emit("private_message", { to: partnerId, message });
    input.value = "";
  }
}

document.querySelector("#chat button").addEventListener("click", sendPrivateMessage);
document.getElementById("chat_input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    sendPrivateMessage();
  }
});
