document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".banner").forEach((banner) => banner.setAttribute("role", "status"));
  document.querySelectorAll("button").forEach((button) => button.addEventListener("click", () => {
    if (button.form && button.type === "submit") { button.classList.add("is-loading"); button.setAttribute("aria-busy", "true"); }
  }));
});
