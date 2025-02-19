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

        // Update metrics with enhanced display
        updateMetricsSection('securityMetrics', data.security_metrics, {
            'HTTPS': 'Uses secure HTTPS protocol',
            'Special Characters': 'Number of special characters in URL',
            'Suspicious Keywords': 'Contains known phishing-related words',
            'Suspicious TLD': 'Uses potentially suspicious top-level domain'
        });

        updateMetricsSection('urlStructure', data.url_structure, {
            'URL Length': 'Total length of the URL',
            'Domain Length': 'Length of the domain name',
            'Path Length': 'Length of the URL path',
            'Directory Depth': 'Number of directory levels',
            'Query Parameters': 'Number of query parameters'
        });

        updateMetricsSection('suspiciousPatterns', data.suspicious_patterns, {
            'IP Address': 'URL contains an IP address instead of domain name',
            'Misspelled Domain': 'Domain name appears to be misspelled',
            'Shortened URL': 'Uses a URL shortening service',
            'At Symbol': 'Contains @ symbol in URL',
            'Multiple Subdomains': 'Has unusually many subdomains'
        });
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

    function updateMetricsSection(sectionId, metrics, tooltips) {
        const section = document.getElementById(sectionId);
        section.innerHTML = '';

        Object.entries(metrics).forEach(([key, value]) => {
            const row = document.createElement('div');
            row.className = 'mb-2';

            // Format the value based on type
            let displayValue, displayClass;
            if (typeof value === 'boolean') {
                displayValue = value ? 
                    '<i class="fas fa-check-circle text-success"></i>' : 
                    '<i class="fas fa-times-circle text-danger"></i>';
                displayClass = value ? 'text-success' : 'text-danger';
            } else if (typeof value === 'number') {
                displayValue = value;
                displayClass = value > 5 ? 'text-warning' : 'text-success';
            } else {
                displayValue = value;
                displayClass = 'text-info';
            }

            row.innerHTML = `
                <div class="d-flex justify-content-between align-items-center" 
                     data-bs-toggle="tooltip" 
                     data-bs-placement="top" 
                     title="${tooltips[key]}">
                    <span>${key}</span>
                    <span class="${displayClass}">${displayValue}</span>
                </div>
            `;
            section.appendChild(row);
        });

        // Initialize tooltips
        const tooltipTriggerList = [].slice.call(section.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    function showError(message) {
        errorAlert.textContent = message;
        errorAlert.classList.remove('d-none');
        resultsSection.classList.add('d-none');
    }
});