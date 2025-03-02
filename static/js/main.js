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
                    const contentType = response.headers.get('content-type');
                    if (contentType && contentType.includes('application/json')) {
                        const errorData = await response.json();
                        throw new Error(errorData.error || 'Analysis failed');
                    } else {
                        throw new Error('Server error occurred');
                    }
                }

                const data = await response.json();
                updateResults(data);
            } catch (error) {
                showError(error.message);
            } finally {
                loadingSpinner.classList.add('d-none');
            }
        });
    }

    function showError(message) {
        if (errorAlert) {
            errorAlert.textContent = message;
            errorAlert.classList.remove('d-none');
        } else {
            console.error('Error:', message);
        }
    }

    function updateResults(data) {
        resultsSection.classList.remove('d-none');
        
        // Update result indicator
        const resultText = document.getElementById('resultText');
        const resultIcon = document.querySelector('#resultIndicator i');
        
        if (resultText && resultIcon) {
            if (data.prediction === 'phishing') {
                resultText.textContent = 'Potentially Unsafe';
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

        // Update confidence chart
        updateConfidenceChart(data.probability_safe, data.probability_phishing);
    }
    
    function updateMetrics(elementId, metrics) {
        const container = document.getElementById(elementId);
        if (!container || !metrics) return;
        
        container.innerHTML = '';
        
        Object.entries(metrics).forEach(([key, value]) => {
            const row = document.createElement('div');
            row.className = 'metric-row d-flex justify-content-between align-items-center py-2';
            
            const label = document.createElement('span');
            label.textContent = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            const indicator = document.createElement('span');
            if (typeof value === 'boolean') {
                indicator.innerHTML = value ? 
                    '<i class="fas fa-times-circle text-danger"></i>' : 
                    '<i class="fas fa-check-circle text-success"></i>';
            } else {
                indicator.textContent = value;
            }
            
            row.appendChild(label);
            row.appendChild(indicator);
            container.appendChild(row);
        });
    }
    
    function updateConfidenceChart(safeProbability, phishingProbability) {
        const ctx = document.getElementById('confidenceChart');
        if (!ctx) return;
        
        if (confidenceChart) {
            confidenceChart.destroy();
        }
        
        confidenceChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Potentially Unsafe'],
                datasets: [{
                    data: [safeProbability, phishingProbability],
                    backgroundColor: ['rgba(40, 167, 69, 0.8)', 'rgba(220, 53, 69, 0.8)'],
                    borderColor: ['#28a745', '#dc3545'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
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