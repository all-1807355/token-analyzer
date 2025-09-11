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

    // Set initial progress state
    let currentProgress = 0;
    progressTotal.textContent = "32";

    const eventSource = new EventSource('/api/progress');
    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        currentProgress = data.value;
        const percentage = (currentProgress / 32) * 100;
        progress.style.width = `${percentage}%`;
        progressCurrent.textContent = currentProgress;
    };

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token, chain })
        });

        const data = await response.json();
        console.log(data)
        eventSource.close();

        if (!response.ok) {
            throw new Error(data.detail || 'Analysis failed');
        }
        const tokenInfo = data.data;
        console.log(tokenInfo)
        const analyses = tokenInfo.analyses;
        window.analysisResults = tokenInfo;

        // Hide loading screen
        loadingScreen.style.display = 'none';

        // Show results and sidebar
        resultsContent.style.display = 'block';
        sidebar.style.visibility = 'visible';
        requestAnimationFrame(() => {
            sidebar.classList.add('visible');
        });
        
        // Display Safety Score
        if (tokenInfo && tokenInfo.safety_score) {
            const safetyScore = tokenInfo.safety_score;

            // Update circular score
            const scoreNumber = document.getElementById('score-number');
            const scoreRating = document.getElementById('score-rating');
            const scoreSlippage = document.getElementById('score-slippage');

            scoreNumber.textContent = safetyScore.percentage || 0;
            scoreRating.textContent = safetyScore.rating || 'N/A';
            scoreSlippage.textContent = safetyScore.effective_slippage_rate_percent !== undefined
                ? safetyScore.effective_slippage_rate_percent.toFixed(2)
                : 'N/A';

            // Optional: dynamically update the chart stroke length based on score
            const scorePath = document.getElementById('score-path');
            const percentage = Math.min((safetyScore.percentage || 0), 100);
            const circumference = 100; // Simplified, normally you calculate from SVG dimensions
            const offset = circumference * (1 - (percentage / 100));
            scorePath.style.strokeDasharray = `${circumference}`;
            scorePath.style.strokeDashoffset = `${offset}`;
        }

        // Create "At a Glance" section

        
        const glanceIndicators = document.getElementById('glance-indicators');
        if (glanceIndicators) {
            // Helper function to create status indicators
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

            // Prepare indicators HTML
            let indicatorsHTML = '';

            // Contract Analysis
            if (analyses.contract) {
                indicatorsHTML += createStatusIndicator(
                    'fa-file-contract',
                    'Contract Verified',
                    analyses.contract.contract_name ? true : false,
                    analyses.contract.contract_name || 'Unverified'
                );
            }

            // Holder Analysis
            if (analyses.holder) {
                indicatorsHTML += createStatusIndicator(
                    'fa-users',
                    'Token Distribution',
                    analyses.holder.top_10_less_than_70_percent_of_circulating ? 'success' : 'warning',
                    analyses.holder.top_10_less_than_70_percent_of_circulating ? 
                    'Well distributed' : 'Highly concentrated'
                );
            }

            // Security Analysis
            if (analyses.security) {
                indicatorsHTML += createStatusIndicator(
                    'fa-shield-alt',
                    'Security Warnings',
                    analyses.security.howmany_warnings === 0 ? true : false,
                    `${analyses.security.howmany_warnings} warnings found`
                );
            }

            // Liquidity Analysis
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

        // ➕ Display results for each analysis type
        for (const [type, results] of Object.entries(analyses)) {
            if (Object.keys(results).length === 0) continue;

            const section = document.createElement('section');
            section.className = 'analysis-section';
            section.id = type;
            section.innerHTML = `
                <h2>${type.charAt(0).toUpperCase() + type.slice(1)} Analysis</h2>
                <pre><code>${JSON.stringify(results, null, 2)}</code></pre>
            `;
            resultsContainer.appendChild(section);
        }

        // ✅ Download button functionality
        const downloadBtn = document.getElementById('download-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', function () {
                const resultData = window.analysisResults || {};
                const jsonString = JSON.stringify(resultData, null, 2);
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

// Sidebar active link switching
const sections = document.querySelectorAll('.overview-section, .analysis-section');
const navLinks = document.querySelectorAll('.nav-item');

const observerOptions = {
    root: null,
    rootMargin: '-40% 0px -40% 0px',
    threshold: 0
};

const sectionObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const id = entry.target.id;
            navLinks.forEach(link => {
                link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
            });
        }
    });
}, observerOptions);

sections.forEach(section => sectionObserver.observe(section));
