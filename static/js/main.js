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

        // Update metrics with enhanced display and better thresholds
        updateMetricsSection('securityMetrics', data.security_metrics, {
            'HTTPS': 'Uses secure HTTPS protocol - Recommended for secure websites',
            'Special Characters': 'Number of special characters in URL - High numbers may indicate suspicious activity',
            'Suspicious Keywords': 'Contains words commonly used in phishing attempts',
            'Suspicious TLD': 'Uses an uncommon or potentially risky top-level domain'
        });

        updateMetricsSection('urlStructure', data.url_structure, {
            'URL Length': 'Total length of the URL - Very long URLs may be suspicious',
            'Domain Length': 'Length of the domain name - Extremely long domain names are unusual',
            'Path Length': 'Length of the URL path after the domain',
            'Directory Depth': 'Number of subdirectories in the URL',
            'Query Parameters': 'Number of parameters in the URL'
        });

        updateMetricsSection('suspiciousPatterns', data.suspicious_patterns, {
            'IP Address': 'Using IP address instead of domain name (suspicious)',
            'Misspelled Domain': 'Domain name appears to be misspelling a known brand',
            'Shortened URL': 'URL has been shortened, hiding its true destination',
            'At Symbol': 'Contains @ symbol which can be used to obscure the true destination',
            'Multiple Subdomains': 'Has an unusual number of subdomains'
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
                    data: [data.probability_safe * 100, data.probability_phishing * 100],
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

            // Improved value formatting and thresholds
            let displayValue, displayClass;
            if (typeof value === 'boolean') {
                if (key === 'HTTPS') {
                    // Reverse the logic for HTTPS - true is good
                    displayValue = value ? 
                        '<i class="fas fa-check-circle text-success"></i>' : 
                        '<i class="fas fa-times-circle text-danger"></i>';
                    displayClass = value ? 'text-success' : 'text-danger';
                } else {
                    // For other boolean values, true usually indicates a risk
                    displayValue = value ? 
                        '<i class="fas fa-times-circle text-danger"></i>' : 
                        '<i class="fas fa-check-circle text-success"></i>';
                    displayClass = value ? 'text-danger' : 'text-success';
                }
            } else if (typeof value === 'number') {
                displayValue = value;
                // Adjust thresholds based on the metric
                if (key === 'URL Length') {
                    displayClass = value > 100 ? 'text-warning' : 'text-success';
                } else if (key === 'Special Characters') {
                    displayClass = value > 3 ? 'text-warning' : 'text-success';
                } else if (key === 'Directory Depth') {
                    displayClass = value > 4 ? 'text-warning' : 'text-success';
                } else {
                    displayClass = value > 2 ? 'text-warning' : 'text-success';
                }
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