/**
 * Fade-in on scroll for [data-reveal] elements.
 *
 * Elements are only hidden once this script marks them pending, so the page
 * reads normally without it. Anything already on screen is shown straight
 * away, and a timeout makes sure nothing is ever left hidden.
 */
(function () {
  var elements = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));

  if (!elements.length || !("IntersectionObserver" in window) ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    return;
  }

  function reveal(element) {
    var delay = Number(element.getAttribute("data-reveal-delay") || 0);

    if (delay) {
      element.style.setProperty("--reveal-delay", delay + "ms");
    }

    element.setAttribute("data-reveal-state", "visible");
  }

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        reveal(entry.target);
        observer.unobserve(entry.target);
      }
    });
  }, { rootMargin: "0px 0px -6% 0px" });

  elements.forEach(function (element) {
    var box = element.getBoundingClientRect();

    if (box.top < window.innerHeight && box.bottom > 0) {
      return;
    }

    element.setAttribute("data-reveal-state", "pending");
    observer.observe(element);
  });

  // Failsafe: never leave content hidden because an observer callback was missed.
  window.setTimeout(function () {
    elements.forEach(function (element) {
      if (element.getAttribute("data-reveal-state") === "pending") {
        reveal(element);
      }
    });
  }, 4000);
})();
