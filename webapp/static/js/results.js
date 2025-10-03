document.addEventListener('DOMContentLoaded', async function() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    const chain = params.get('chain');

    const loadingScreen = document.getElementById('loading');
    const resultsContent = document.getElementById('results');
    const resultsContainer = document.getElementById('results-sections');
    const sidebar = document.querySelector('.sidebar');
    const progress = document.getElementById('progress');
    const progressCurrent = document.getElementById('progress-current');
    const progressTotal = document.getElementById('progress-total');

    progressTotal.textContent = "32";

    const eventSource = new EventSource('/api/progress');
    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const percentage = (data.value / 32) * 100;
        progress.style.width = `${percentage}%`;
        progressCurrent.textContent = data.value;
    };

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, chain })
        });

        const data = await response.json();
        eventSource.close();

        if (!response.ok) throw new Error(data.detail || 'Analysis failed');

        const rawResults = data.data.raw_results;
        const score = data.data.score;
        const analyses = rawResults.analyses;

        // Store everything globally if needed
        window.analysisResults = rawResults;

        // Hide loading screen
        loadingScreen.style.display = 'none';

        // Show results and sidebar
        resultsContent.style.display = 'block';
        sidebar.style.visibility = 'visible';
        requestAnimationFrame(() => sidebar.classList.add('visible'));

        // Update model prediction display
        if (score) {
            // Update verdict text
            const verdictText = document.getElementById('model-verdict-text');
            const verdictClass = score.prediction === 'non-spam' ? 'safe-verdict' : 'risk-verdict';
            verdictText.innerHTML = `
                <strong>Verdict:</strong>
                <span class="${verdictClass}">${score.prediction === 'non-spam' ? 'Safe Token' : 'High Risk Token'}</span>
            `;

            // Update confidence level
            const confidenceElement = document.getElementById('model-confidence');
            confidenceElement.textContent = score.confidence.charAt(0).toUpperCase() + score.confidence.slice(1);

            // Update probabilities
            const safeProb = (score.non_spam_probability * 100).toFixed(1);
            const riskProb = (score.spam_probability * 100).toFixed(1);

            document.getElementById('safe-probability').textContent = `${safeProb}%`;
            document.getElementById('risk-probability').textContent = `${riskProb}%`;

            document.getElementById('safe-prob-bar').style.width = `${safeProb}%`;
            document.getElementById('risk-prob-bar').style.width = `${riskProb}%`;

            // Update decision score
            const scoreElement = document.getElementById('model-score');
            const normalizedScore = Math.round(50 + (score.decision_score * 25));
            const clampedScore = Math.max(0, Math.min(100, normalizedScore));
            
            scoreElement.textContent = clampedScore;
            scoreElement.className = 'score-value ' + 
                (clampedScore >= 70 ? 'score-high' : 
                 clampedScore >= 40 ? 'score-medium' : 
                 'score-low');
        }

        // Display glance indicators
        const glanceIndicators = document.getElementById('glance-indicators');
        if (glanceIndicators) {
            const createStatusIndicator = (icon, label, status, details = '') => {
                const statusClass = status === true ? 'success' :
                                    status === false ? 'danger' :
                                    status === 'warning' ? 'warning' : 'neutral';
                return `
                    <div class="glance-indicator ${statusClass}">
                        <i class="fas ${icon}"></i>
                        <div class="indicator-content">
                            <span class="indicator-label">${label}</span>
                            ${details ? `<span class="indicator-details">${details}</span>` : ''}
                        </div>
                    </div>
                `;
            };

            let indicatorsHTML = '';
            if (analyses.contract) {
                indicatorsHTML += createStatusIndicator(
                    'fa-file-contract',
                    'Contract Verified',
                    analyses.contract.contract_name ? true : false,
                    analyses.contract.contract_name || 'Unverified'
                );
            }
            if (analyses.holder) {
                indicatorsHTML += createStatusIndicator(
                    'fa-users',
                    'Token Distribution',
                    analyses.holder.top_10_less_than_70_percent_of_circulating ? 'success' : 'warning',
                    analyses.holder.top_10_less_than_70_percent_of_circulating ?
                    'Well distributed' : 'Highly concentrated'
                );
            }
            if (analyses.security) {
                indicatorsHTML += createStatusIndicator(
                    'fa-shield-alt',
                    'Security Warnings',
                    analyses.security.howmany_warnings === 0 ? true : false,
                    `${analyses.security.howmany_warnings} warnings found`
                );
            }
            if (analyses.liquidity) {
                const hasLiquidity = !analyses.liquidity.error;
                indicatorsHTML += createStatusIndicator(
                    'fa-coins',
                    'Liquidity Pool',
                    hasLiquidity ? true : false,
                    hasLiquidity ? 'Available' : 'Not found'
                );
            }

            glanceIndicators.innerHTML = indicatorsHTML;
        }

        // Display all analysis sections
        for (const [type, results] of Object.entries(analyses)) {
            if (!results || Object.keys(results).length === 0) continue;
            const section = document.createElement('section');
            section.className = 'analysis-section';
            section.id = type;
            section.innerHTML = `
                <h2>${type.charAt(0).toUpperCase() + type.slice(1)} Analysis</h2>
                <pre><code>${JSON.stringify(results, null, 2)}</code></pre>
            `;
            resultsContainer.appendChild(section);
        }

        // Download results button
        const downloadBtn = document.getElementById('download-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', function () {
                const jsonString = JSON.stringify(window.analysisResults, null, 2);
                const blob = new Blob([jsonString], { type: "text/plain" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "analysis_results.json";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }

    } catch (error) {
        eventSource.close();
        alert('Error analyzing token: ' + error.message);
        window.location.href = '/';
    }
});
