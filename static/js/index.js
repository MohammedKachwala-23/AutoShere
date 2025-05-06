
  const links = document.querySelectorAll('.sidebar nav a');
  const current = window.location.pathname;

  links.forEach(link => {
    if (link.href.includes(current)) {
      link.classList.add('active');
    }
  });
