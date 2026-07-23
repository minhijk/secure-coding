"use strict";

const socket = io();

socket.on("message", (data) => {
  if (!data || typeof data.username !== "string" || typeof data.message !== "string") {
    return;
  }
  const messages = document.getElementById("messages");
  const item = document.createElement("li");
  item.textContent = `${data.username}: ${data.message}`;
  messages.appendChild(item);
  messages.scrollTop = messages.scrollHeight;
});

function sendMessage() {
  const input = document.getElementById("chat_input");
  const message = input.value.trim();
  if (message) {
    socket.emit("send_message", { message });
    input.value = "";
  }
}

document.querySelector("#chat button").addEventListener("click", sendMessage);
