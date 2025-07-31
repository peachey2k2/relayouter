window.addEventListener('load', () => {
  const entries = performance.getEntriesByType("resource");
  const navigation = performance.getEntriesByType("navigation")[0];

  // Grab index.js and style.css timings
  const resourceMetrics = entries.filter(entry =>
    ["index.js", "style.css"].some(name => entry.name.includes(name))
  ).map(entry => ({
    name: entry.name.split('/').pop(),
    duration: parseFloat(entry.duration.toFixed(2))
  }));

  // Add index.html timing from navigation entry
  if (navigation) {
    resourceMetrics.unshift({
      name: "index.html",
      duration: parseFloat(navigation.duration.toFixed(2))
    });
  }

  // Build chart
  const ctx = document.getElementById('performanceChart').getContext('2d');
  const labels = resourceMetrics.map(m => m.name);
  const durations = resourceMetrics.map(m => m.duration);

  Chart.defaults = {
  };

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: durations,
        backgroundColor: '#ffffff',
        borderColor: '#ffffff',
        categoryPercentage: 0.2,
      }],
      defaults: {
      },
    },
    options: {
      scales: {
        x: {
          barPercentage: 0.1,
          grid: {
              color: '#ffffff',
          },
          ticks: {
            color: '#ffffff',
            font: {
              family: "'Miracode'",
              size: 16,
            },
          }
        },
        y: {
          beginAtZero: true,
          grid: {
              color: '#ffffff',
          },
          ticks: {
            color: '#ffffff',
            font: {
              family: "'Miracode'",
              size: 16,
            },
          }
        }
      },
      animation: false,
      layout: {
        padding: 20,
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: context => `${context.parsed.y} ms`
          }
        }
      }
    }
  });
});
