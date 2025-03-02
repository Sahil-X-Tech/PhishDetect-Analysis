document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('urlForm');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const resultsSection = document.getElementById('resultsSection');
    const errorAlert = document.getElementById('errorAlert');
    let confidenceChart = null;

    if (urlForm) {
        urlForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            const urlInput = document.getElementById('urlInput').value;
            const csrfToken = document.querySelector('input[name="csrf_token"]').value;

            // Reset UI
            loadingSpinner.classList.remove('d-none');
            resultsSection.classList.add('d-none');
            if (errorAlert) errorAlert.classList.add('d-none');

            try {
                const formData = new FormData();
                formData.append('url', urlInput);
                formData.append('csrf_token', csrfToken);

                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }

                const data = await response.json();

                // Hide loading spinner and show results
                loadingSpinner.classList.add('d-none');
                resultsSection.classList.remove('d-none');

                // Update the result text and icon
                const resultText = document.getElementById('resultText');
                const resultIcon = document.querySelector('#resultIndicator i');

                if (data.prediction === 'phishing') {
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
                updateConfidenceChart(data.probability_safe, data.probability_phishing);
            } catch (error) {
                loadingSpinner.classList.add('d-none');
                const errorAlert = document.getElementById('errorAlert');
                errorAlert.textContent = error.message || 'Error analyzing URL. Please try again.';
                errorAlert.classList.remove('d-none');
            }
        });
    }

    function updateMetrics(elementId, metrics) {
        const container = document.getElementById(elementId);
        if (!container) return;

        container.innerHTML = '';

        Object.entries(metrics).forEach(([key, value]) => {
            const row = document.createElement('div');
            row.className = 'metric-row d-flex justify-content-between align-items-center py-2';

            const label = document.createElement('span');
            label.textContent = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

            const indicator = document.createElement('span');
            if (typeof value === 'boolean') {
                indicator.className = `badge ${value ? 'bg-danger' : 'bg-success'}`;
                indicator.textContent = value ? 'Yes' : 'No';
            } else if (typeof value === 'number') {
                indicator.textContent = value;
            }

            row.appendChild(label);
            row.appendChild(indicator);
            container.appendChild(row);
        });
    }

    function updateConfidenceChart(safeProbability, phishingProbability) {
        const canvas = document.getElementById('confidenceChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');

        // Destroy existing chart if it exists
        if (confidenceChart instanceof Chart) {
            confidenceChart.destroy();
        }

        confidenceChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Suspicious'],
                datasets: [{
                    data: [safeProbability, phishingProbability],
                    backgroundColor: ['#198754', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Confidence Score'
                    }
                }
            }
        });
    }
});