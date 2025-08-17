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
    progressTotal.textContent = "32"; // Total steps from all wrappers

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
        eventSource.close();

        if (!response.ok) {
            throw new Error(data.detail || 'Analysis failed');
        }

        // Hide loading screen
        loadingScreen.style.display = 'none';
        
        // Show results and sidebar
        resultsContent.style.display = 'block';
        sidebar.style.visibility = 'visible';
        requestAnimationFrame(() => {
            sidebar.classList.add('visible');
        });

        // Display results for each analysis type
        const analyses = data.data.analyses;
        for (const [type, results] of Object.entries(analyses)) {
            if (Object.keys(results).length === 0) continue;

            const section = document.createElement('section'); // Changed to section
            section.className = 'analysis-section';
            section.id = type;
            section.innerHTML = `
                <h2>${type.charAt(0).toUpperCase() + type.slice(1)} Analysis</h2>
                <pre><code>${JSON.stringify(results, null, 2)}</code></pre>
            `;
            resultsContainer.appendChild(section);
        }

    } catch (error) {
        eventSource.close();
        alert('Error analyzing token: ' + error.message);
        window.location.href = '/';
    }
});

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

