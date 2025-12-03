document.querySelectorAll(".card").forEach((card, idx) => {
  card.style.transition = "transform 0.3s ease, box-shadow 0.3s ease";
  card.style.transform = "rotateY(0deg)";
  setTimeout(() => card.classList.add("card-ready"), idx * 80);
  card.addEventListener("mousemove", e => {
    const rect = card.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    card.style.transform = `rotateY(${x * 8}deg) rotateX(${ -y * 8}deg) scale(1.02)`;
  });
  card.addEventListener("mouseleave", () => {
    card.style.transform = "rotateY(0deg) rotateX(0deg) scale(1)";
  });
});