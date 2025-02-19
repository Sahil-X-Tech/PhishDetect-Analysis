document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('urlForm');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const resultsSection = document.getElementById('resultsSection');
    const errorAlert = document.getElementById('errorAlert');
    let confidenceChart = null;

    urlForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const urlInput = document.getElementById('urlInput').value;
        
        // Reset UI
        loadingSpinner.classList.remove('d-none');
        resultsSection.classList.add('d-none');
        errorAlert.classList.add('d-none');

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `url=${encodeURIComponent(urlInput)}`
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Analysis failed');
            }

            updateResults(data);
        } catch (error) {
            showError(error.message);
        } finally {
            loadingSpinner.classList.add('d-none');
        }
    });

    function updateResults(data) {
        resultsSection.classList.remove('d-none');
        
        // Update result indicator
        const resultIndicator = document.getElementById('resultIndicator');
        const resultText = document.getElementById('resultText');
        const icon = resultIndicator.querySelector('i');
        
        if (data.prediction === 'safe') {
            icon.className = 'fas fa-circle-check text-success fa-4x';
            resultText.className = 'mt-2 text-success';
            resultText.textContent = 'Safe';
        } else {
            icon.className = 'fas fa-triangle-exclamation text-danger fa-4x';
            resultText.className = 'mt-2 text-danger';
            resultText.textContent = 'Phishing';
        }

        // Update confidence chart
        updateConfidenceChart(data);

        // Update metrics
        updateMetricsSection('securityMetrics', data.security_metrics);
        updateMetricsSection('urlStructure', data.url_structure);
        updateMetricsSection('suspiciousPatterns', data.suspicious_patterns);
    }

    function updateConfidenceChart(data) {
        if (confidenceChart) {
            confidenceChart.destroy();
        }

        const ctx = document.getElementById('confidenceChart').getContext('2d');
        confidenceChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Phishing'],
                datasets: [{
                    data: [data.probability_safe, data.probability_phishing],
                    backgroundColor: ['#198754', '#dc3545'],
                    borderWidth: 0
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

    function updateMetricsSection(sectionId, metrics) {
        const section = document.getElementById(sectionId);
        section.innerHTML = '';

        Object.entries(metrics).forEach(([key, value]) => {
            const row = document.createElement('div');
            row.className = 'mb-2';
            
            // Format the value based on type
            let displayValue;
            if (typeof value === 'boolean' || value === 0 || value === 1) {
                displayValue = value ? 
                    '<i class="fas fa-circle text-danger"></i>' : 
                    '<i class="fas fa-circle text-success"></i>';
            } else {
                displayValue = value;
            }

            row.innerHTML = `
                <div class="d-flex justify-content-between">
                    <span>${key}</span>
                    <span>${displayValue}</span>
                </div>
            `;
            section.appendChild(row);
        });
    }

    function showError(message) {
        errorAlert.textContent = message;
        errorAlert.classList.remove('d-none');
        resultsSection.classList.add('d-none');
    }
});
