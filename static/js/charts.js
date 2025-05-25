document.addEventListener('DOMContentLoaded', function() {
  // Insider Trading Activity Chart
  const ctx1 = document.getElementById('insiderChart').getContext('2d');
  new Chart(ctx1, {
    type: 'bar',
    data: {
      labels: ['Executives', 'Directors', '10% Owners', 'Other'],
      datasets: [{
        label: 'Buy Transactions',
        data: [12, 19, 8, 5],
        backgroundColor: 'rgba(75, 192, 192, 0.7)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1
      }, {
        label: 'Sell Transactions',
        data: [8, 15, 12, 7],
        backgroundColor: 'rgba(255, 99, 132, 0.7)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: '#e0e0e0'
          }
        },
        tooltip: {
          mode: 'index',
          intersect: false
        }
      },
      scales: {
        x: {
          grid: {
            color: 'rgba(255, 255, 255, 0.1)'
          },
          ticks: {
            color: '#e0e0e0'
          }
        },
        y: {
          grid: {
            color: 'rgba(255, 255, 255, 0.1)'
          },
          ticks: {
            color: '#e0e0e0'
          }
        }
      }
    }
  });

  // Impact Chart
  const ctx2 = document.getElementById('impactChart').getContext('2d');
  new Chart(ctx2, {
    type: 'scatter',
    data: {
      datasets: [{
        label: 'Trades',
        data: [
          {x: 10000, y: 1.2},
          {x: 50000, y: 2.3},
          {x: 25000, y: 0.8},
          {x: 75000, y: 3.1},
          {x: 150000, y: 4.5}
        ],
        backgroundColor: 'rgba(110, 72, 170, 0.7)',
        borderColor: 'rgba(110, 72, 170, 1)',
        borderWidth: 1,
        pointRadius: 8,
        pointHoverRadius: 10
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              return `Shares: ${context.parsed.x.toLocaleString()}, Impact: ${context.parsed.y}%`;
            }
          }
        }
      },
      scales: {
        x: {
          title: {
            display: true,
            text: 'Shares Traded',
            color: '#e0e0e0'
          },
          grid: {
            color: 'rgba(255, 255, 255, 0.1)'
          },
          ticks: {
            color: '#e0e0e0'
          }
        },
        y: {
          title: {
            display: true,
            text: 'Price Impact (%)',
            color: '#e0e0e0'
          },
          grid: {
            color: 'rgba(255, 255, 255, 0.1)'
          },
          ticks: {
            color: '#e0e0e0'
          }
        }
      }
    }
  });

  // Time period buttons
  document.querySelectorAll('.chart-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      // Add your data filtering logic here
    });
  });
});