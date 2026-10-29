const viewNames = { dashboard: "Übersicht", sessions: "OIDC-Sitzungen" };

function showView(id) {
  if (!viewNames[id]) return;
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === id));
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === id));
  document.querySelector("#crumb").textContent = viewNames[id];
  document.querySelector(".sidebar").classList.remove("open");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll("[data-view]").forEach((item) => item.addEventListener("click", () => showView(item.dataset.view)));
document.querySelector(".mobile-menu").addEventListener("click", () => document.querySelector(".sidebar").classList.toggle("open"));
document.querySelector(".notice button").addEventListener("click", (event) => event.currentTarget.closest(".notice").remove());
