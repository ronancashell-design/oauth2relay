/**
 * Scroll journey for [data-journey] sections.
 *
 * The section is several screens tall and its panel is position: sticky, so it
 * stays pinned while the page scrolls through it. Scroll progress across the
 * section (0..1) picks the active step: its icon, its text and the rail dots.
 * With reduced motion the script does nothing and the steps stay stacked.
 */
(function () {
  var sections = document.querySelectorAll("[data-journey]");

  if (!sections.length || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    return;
  }

  document.documentElement.classList.add("js-journey");

  sections.forEach(function (section) {
    var chapters = section.querySelectorAll("[data-journey-chapter]");
    var icons = section.querySelectorAll("[data-journey-icon]");
    var rails = section.querySelectorAll(".journey-rail i");
    var shown = -1;
    var queued = false;

    function update() {
      queued = false;

      var bounds = section.getBoundingClientRect();
      var travel = Math.max(1, bounds.height - window.innerHeight);
      var progress = Math.min(1, Math.max(0, -bounds.top / travel));
      var step = Math.min(chapters.length - 1, Math.floor(progress * chapters.length));

      if (step === shown) {
        return;
      }

      shown = step;

      chapters.forEach(function (chapter, i) {
        chapter.classList.toggle("is-active", i === step);

        if (i === step) {
          chapter.removeAttribute("aria-hidden");
        } else {
          chapter.setAttribute("aria-hidden", "true");
        }
      });

      icons.forEach(function (icon, i) {
        icon.classList.toggle("is-active", i === step);
      });

      rails.forEach(function (rail, i) {
        rail.classList.toggle("is-active", i <= step);
      });
    }

    function schedule() {
      if (!queued) {
        queued = true;
        window.requestAnimationFrame(update);
      }
    }

    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule, { passive: true });
    update();
  });
})();
