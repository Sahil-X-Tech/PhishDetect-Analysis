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
// DOM Elements
document.addEventListener("DOMContentLoaded", function() {
    // URL form submission
    const urlForm = document.getElementById("urlForm");
    const loadingSpinner = document.getElementById("loadingSpinner");
    const resultContainer = document.getElementById("resultContainer");
    const reportForm = document.getElementById("reportForm");
    
    if (urlForm) {
        urlForm.addEventListener("submit", function(e) {
            e.preventDefault();
            
            // Show loading spinner
            if (loadingSpinner) {
                loadingSpinner.classList.remove("d-none");
            }
            
            if (resultContainer) {
                resultContainer.classList.add("d-none");
            }
            
            // Get URL
            const urlInput = document.getElementById("urlInput");
            if (!urlInput || !urlInput.value) {
                alert("Please enter a URL");
                if (loadingSpinner) {
                    loadingSpinner.classList.add("d-none");
                }
                return;
            }
            
            // Prepare form data
            const formData = new FormData();
            formData.append("url", urlInput.value);
            
            // Send request
            fetch("/analyze", {
                method: "POST",
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
                    loadingSpinner.classList.add("d-none");
                }
                
                if (resultContainer) {
                    resultContainer.classList.remove("d-none");
                }
                
                // Update result indicator
                const resultIndicator = document.getElementById("resultIndicator");
                if (resultIndicator) {
                    resultIndicator.className = data.prediction === "phishing" ? 
                        "alert alert-danger text-center" : 
                        "alert alert-success text-center";
                    
                    resultIndicator.innerHTML = `
                        <h3 class="mb-3">
                            <i class="${data.prediction === "phishing" ? "fas fa-exclamation-triangle" : "fas fa-shield-alt"}"></i>
                            ${data.prediction === "phishing" ? "Potential Phishing Detected" : "Legitimate Website"}
                        </h3>
                        <p class="mb-0 lead">Confidence: ${data.confidence}%</p>
                    `;
                }
                
                // Update confidence chart
                updateConfidenceChart(data.probability_safe, data.probability_phishing);
                
                // Update security metrics
                updateMetricsTable("securityMetrics", data.security_metrics);
                updateMetricsTable("urlStructure", data.url_structure);
                updateMetricsTable("suspiciousPatterns", data.suspicious_patterns);
                
                // Update report form if it exists
                if (reportForm) {
                    const urlField = document.getElementById("reportUrl");
                    const actualResultField = document.getElementById("actualResult");
                    
                    if (urlField) urlField.value = urlInput.value;
                    if (actualResultField) actualResultField.value = data.prediction;
                }
            })
            .catch(error => {
                console.error("Error:", error);
                if (loadingSpinner) {
                    loadingSpinner.classList.add("d-none");
                }
                alert("Error analyzing URL. Please try again.");
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
function updateConfidenceChart(safeProb, phishingProb) {
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
