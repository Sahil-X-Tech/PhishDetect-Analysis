document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('urlForm');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const resultsSection = document.getElementById('resultsSection');
    const errorAlert = document.getElementById('errorAlert');
    const reportForm = document.getElementById('reportForm');
    let confidenceChart = null;

    // Initialize Chart.js if we need to display a chart
    function updateConfidenceChart(safePercentage, phishingPercentage) {
        const ctx = document.getElementById('confidenceChart').getContext('2d');

        if (confidenceChart) {
            confidenceChart.destroy();
        }

        confidenceChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Phishing'],
                datasets: [{
                    data: [safePercentage, phishingPercentage],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#ffffff'
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.label + ': ' + context.raw.toFixed(1) + '%';
                            }
                        }
                    }
                }
            }
        });
    }

    // Function to update metric cards
    function updateMetrics(containerId, metricsData) {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = '';

        Object.entries(metricsData).forEach(([key, value]) => {
            const row = document.createElement('div');
            row.className = 'metric-row d-flex justify-content-between align-items-center';

            const label = document.createElement('span');
            label.textContent = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());

            const valueEl = document.createElement('span');

            if (typeof value === 'boolean') {
                valueEl.innerHTML = value ? 
                    '<i class="fas fa-times-circle text-danger"></i>' : 
                    '<i class="fas fa-check-circle text-success"></i>';
            } else if (typeof value === 'number') {
                valueEl.textContent = value;
            } else {
                valueEl.textContent = value.toString();
            }

            row.appendChild(label);
            row.appendChild(valueEl);
            container.appendChild(row);
        });
    }

    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const urlInput = document.getElementById('urlInput');
            if (!urlInput || !urlInput.value) {
                if (errorAlert) {
                    errorAlert.textContent = "Please enter a URL";
                    errorAlert.classList.remove('d-none');
                }
                return;
            }

            // Reset UI
            if (loadingSpinner) loadingSpinner.classList.remove('d-none');
            if (resultsSection) resultsSection.classList.add('d-none');
            if (errorAlert) errorAlert.classList.add('d-none');

            // Prepare form data
            const formData = new FormData();
            formData.append('url', urlInput.value);

            // Get CSRF token if it exists
            const csrfToken = document.querySelector('input[name="csrf_token"]');
            if (csrfToken) {
                formData.append('csrf_token', csrfToken.value);
            }

            // Send request
            fetch('/analyze', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Hide loading spinner
                if (loadingSpinner) {
                    loadingSpinner.classList.add('d-none');
                }

                if (resultsSection) {
                    resultsSection.classList.remove('d-none');
                }

                // Update result indicator
                const resultText = document.getElementById('resultText');
                const resultIcon = document.querySelector('#resultIndicator i');

                if (resultText && resultIcon) {
                    if (data.prediction === 'phishing') {
                        resultText.textContent = 'Potential Phishing';
                        resultText.className = 'mt-2 text-danger';
                        resultIcon.className = 'fas fa-exclamation-triangle text-danger fa-4x';
                    } else {
                        resultText.textContent = 'Safe';
                        resultText.className = 'mt-2 text-success';
                        resultIcon.className = 'fas fa-check-circle text-success fa-4x';
                    }
                }

                // Update metrics
                updateMetrics('securityMetrics', data.security_metrics);
                updateMetrics('urlStructure', data.url_structure);
                updateMetrics('suspiciousPatterns', data.suspicious_patterns);

                // Update confidence chart if available
                if (typeof Chart !== 'undefined' && document.getElementById('confidenceChart')) {
                    updateConfidenceChart(data.probability_safe * 100, data.probability_phishing * 100);
                }
            })
            .catch(error => {
                console.error("Error:", error);

                if (loadingSpinner) {
                    loadingSpinner.classList.add('d-none');
                }

                if (errorAlert) {
                    errorAlert.textContent = "Error analyzing URL. Please try again.";
                    errorAlert.classList.remove('d-none');
                }
            });
        });
    }

    // Report form submission
    if (reportForm) {
        reportForm.addEventListener("submit", function(e) {
            e.preventDefault();

            const formData = new FormData(reportForm);

            fetch("/submit_report", {
                method: "POST",
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert("Report submitted successfully!");
                    reportForm.reset();
                } else {
                    alert("Error submitting report: " + data.error);
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("Error submitting report. Please try again.");
            });
        });
    }
});

// Helper function to update metrics tables
function updateMetricsTable(tableId, metrics) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const tbody = table.querySelector("tbody");
    if (!tbody) return;
    
    tbody.innerHTML = "";
    
    for (const [key, value] of Object.entries(metrics)) {
        const row = document.createElement("tr");
        row.className = "metric-row";
        
        const keyCell = document.createElement("td");
        keyCell.textContent = key;
        
        const valueCell = document.createElement("td");
        valueCell.className = "text-end";
        
        if (typeof value === "boolean") {
            const badge = document.createElement("span");
            badge.className = value ? "badge bg-danger" : "badge bg-success";
            badge.textContent = value ? "Yes" : "No";
            valueCell.appendChild(badge);
        } else {
            valueCell.textContent = value;
        }
        
        row.appendChild(keyCell);
        row.appendChild(valueCell);
        tbody.appendChild(row);
    }
}

// Update the confidence chart
function updateConfidenceChartOld(safeProb, phishingProb) {
    const chartContainer = document.getElementById("confidenceChart");
    if (!chartContainer) return;
    
    // Clear previous chart
    chartContainer.innerHTML = "";
    
    // Create the chart using a simple div representation
    const safePct = Math.round(safeProb * 100);
    const phishingPct = Math.round(phishingProb * 100);
    
    chartContainer.innerHTML = `
        <div class="progress" style="height: 20px;">
            <div class="progress-bar bg-success" role="progressbar" style="width: ${safePct}%" 
                aria-valuenow="${safePct}" aria-valuemin="0" aria-valuemax="100">
                ${safePct}% Safe
            </div>
            <div class="progress-bar bg-danger" role="progressbar" style="width: ${phishingPct}%" 
                aria-valuenow="${phishingPct}" aria-valuemin="0" aria-valuemax="100">
                ${phishingPct}% Phishing
            </div>
        </div>
    `;
}