document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('urlForm');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const resultsSection = document.getElementById('resultsSection');
    const errorAlert = document.getElementById('errorAlert');
    let confidenceChart = null;

    function updateMetrics(elementId, metrics) {
        const container = document.getElementById(elementId);
        container.innerHTML = '';

        Object.entries(metrics).forEach(([key, value]) => {
            const row = document.createElement('div');
            row.className = 'metric-row d-flex justify-content-between align-items-center py-2';

            const label = document.createElement('span');
            label.textContent = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

            const indicator = document.createElement('span');
            if (typeof value === 'boolean') {
                // Special handling for security features - Yes is good (green), No is bad (red)
                if (key === 'HTTPS' || key === 'Special Characters') {
                    indicator.className = `badge ${value ? 'bg-success' : 'bg-danger'}`;
                } else {
                    // For suspicious patterns - Yes is bad (red), No is good (green)
                    indicator.className = `badge ${value ? 'bg-danger' : 'bg-success'}`;
                }
                indicator.textContent = value ? 'Yes' : 'No';
            } else {
                indicator.textContent = value;
            }

            row.appendChild(label);
            row.appendChild(indicator);
            container.appendChild(row);
        });
    }

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
                        position: 'bottom'
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

    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const urlInput = document.getElementById('urlInput');
            if (!urlInput || !urlInput.value) {
                errorAlert.textContent = "Please enter a URL";
                errorAlert.classList.remove('d-none');
                return;
            }

            // Reset UI
            loadingSpinner.classList.remove('d-none');
            resultsSection.classList.add('d-none');
            errorAlert.classList.add('d-none');

            // Prepare form data
            const formData = new FormData();
            formData.append('url', urlInput.value);

            // Send request
            fetch('/analyze', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Error analyzing URL');
                }
                return response.json();
            })
            .then(data => {
                loadingSpinner.classList.add('d-none');
                resultsSection.classList.remove('d-none');

                // Update result indicator
                const resultText = document.getElementById('resultText');
                const resultIcon = document.querySelector('#resultIndicator i');

                if (data.safe === false) {
                    resultText.textContent = 'Potential Phishing';
                    resultText.className = 'mt-2 text-danger';
                    resultIcon.className = 'fas fa-exclamation-triangle text-danger fa-4x';
                } else {
                    resultText.textContent = 'Safe';
                    resultText.className = 'mt-2 text-success';
                    resultIcon.className = 'fas fa-check-circle text-success fa-4x';
                }

                // Update metrics
                updateMetrics('securityMetrics', data.security_metrics);
                updateMetrics('urlStructure', data.url_structure);
                updateMetrics('suspiciousPatterns', data.suspicious_patterns);

                // Update confidence chart
                updateConfidenceChart(data.probability_safe * 100, data.probability_phishing * 100);

                // Show similar domain warning if available
                if (data.similar_to) {
                    const warning = document.createElement('div');
                    warning.className = 'alert alert-danger mt-3';
                    warning.innerHTML = `<strong>Warning:</strong> This domain appears to be mimicking: ${data.similar_to.join(', ')}`;
                    resultsSection.querySelector('.card-body').appendChild(warning);
                }
            })
            .catch(error => {
                console.error("Error:", error);
                loadingSpinner.classList.add('d-none');
                errorAlert.textContent = error.message || "Error analyzing URL. Please try again.";
                errorAlert.classList.remove('d-none');
            });
        });
    }
});